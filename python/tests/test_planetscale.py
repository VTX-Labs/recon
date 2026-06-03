"""Tests for the PlanetScale capability ladder.

PlanetScale authenticates with ``Authorization: <token_id>:<token>``; the token
*id* is a second value not present in the raw ``pscale_tkn_`` secret, so EVERY
rung is MANUAL and the ladder makes NO live HTTP call. The tests run inside
``respx.mock`` (which rejects any unmocked request) to PROVE no network traffic
ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: list-organizations,
  list-databases; one GATED: create-branch), so the verdict is DENIED;
* each safe_curl keeps the secret as ``$KEY`` and the id as ``$TOKEN_ID`` (never
  the raw token);
* the GATED create-branch rung is recorded ``blocked`` without consent and stays
  a manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import planetscale
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "pscale_tkn_" + "EXAMPLEFAKEKEYNOTREAL00000000000"


def _finding(detector: str = "PlanetScale", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await planetscale.planetscale_ladder(_finding(), Consent.denied())


@respx.mock
async def test_planetscale_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await planetscale.planetscale_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "planetscale"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "list-organizations",
        "list-databases",
        "create-branch",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["list-organizations", "list-databases"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        curl = rung.evidence["safe_curl"]
        assert "$KEY" in curl
        assert "$TOKEN_ID" in curl
        assert FAKE_KEY not in curl


@respx.mock
async def test_planetscale_gated_create_branch_blocked_without_consent() -> None:
    result = await planetscale.planetscale_ladder(_finding(), SAFE_CONSENT)

    branch = next(r for r in result.rungs if r.name == "create-branch")
    assert branch.tier is ProbeTier.GATED
    assert branch.blocked is True
    assert branch.success is False
    assert branch.evidence["billable"] is True
    assert "$KEY" in branch.evidence["safe_curl"]


@respx.mock
async def test_planetscale_gated_create_branch_with_consent_stays_manual() -> None:
    result = await planetscale.planetscale_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    branch = next(r for r in result.rungs if r.name == "create-branch")
    assert branch.blocked is False
    assert branch.success is False
    assert branch.evidence["manual"] is True


async def test_planetscale_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await planetscale._planetscale_create_branch(SAFE_CONSENT)
    assert planetscale._planetscale_create_branch.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_planetscale_result_is_redacted() -> None:
    result = await planetscale.planetscale_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("PlanetScale") is planetscale.planetscale_ladder
    assert get_ladder("planetscale") is planetscale.planetscale_ladder
