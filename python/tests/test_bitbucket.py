"""Tests for the Bitbucket capability ladder.

A Bitbucket app password is half a credential — the REST API uses HTTP Basic
``username:app_password`` and the paired username is NOT in the raw ``ATBB``
finding — so EVERY rung is MANUAL and the ladder makes NO live HTTP call. The
tests run inside ``respx.mock`` (which rejects any unmocked request) to PROVE no
network traffic ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: whoami,
  list-workspace-repo-permissions; one GATED: create-repository), so the verdict
  is DENIED;
* each safe_curl keeps the secret as ``$KEY`` and uses a ``USERNAME`` placeholder
  (never the raw app password);
* the GATED create-repository rung is recorded ``blocked`` without consent and
  stays a manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw secret is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import bitbucket
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "ATBB" + "EXAMPLEFAKEKEYNOTREAL00000000000"


def _finding(detector: str = "BitbucketAppPassword", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await bitbucket.bitbucket_ladder(_finding(), Consent.denied())


@respx.mock
async def test_bitbucket_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await bitbucket.bitbucket_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "bitbucket"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "whoami",
        "list-workspace-repo-permissions",
        "create-repository",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["whoami", "list-workspace-repo-permissions"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        curl = rung.evidence["safe_curl"]
        assert "$KEY" in curl
        assert "USERNAME" in curl
        assert FAKE_KEY not in curl


@respx.mock
async def test_bitbucket_gated_create_repo_blocked_without_consent() -> None:
    result = await bitbucket.bitbucket_ladder(_finding(), SAFE_CONSENT)

    create = next(r for r in result.rungs if r.name == "create-repository")
    assert create.tier is ProbeTier.GATED
    assert create.blocked is True
    assert create.success is False
    assert "$KEY" in create.evidence["safe_curl"]


@respx.mock
async def test_bitbucket_gated_create_repo_with_consent_stays_manual() -> None:
    result = await bitbucket.bitbucket_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    create = next(r for r in result.rungs if r.name == "create-repository")
    assert create.blocked is False
    assert create.success is False
    assert create.evidence["manual"] is True


async def test_bitbucket_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await bitbucket.bitbucket_gated_create_repository(SAFE_CONSENT)
    assert bitbucket.bitbucket_gated_create_repository.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_bitbucket_result_is_redacted() -> None:
    result = await bitbucket.bitbucket_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("BitbucketAppPassword") is bitbucket.bitbucket_ladder
    assert get_ladder("bitbucketapppassword") is bitbucket.bitbucket_ladder
