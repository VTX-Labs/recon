"""Tests for the Docker Hub capability ladder.

A Docker Hub PAT is not a bearer credential — the management API is driven by a
short-lived JWT minted by exchanging ``username`` + PAT, and the username is not
in the token — so EVERY rung is MANUAL and the ladder makes NO live HTTP call.
The tests run inside ``respx.mock`` (which rejects any unmocked request) to PROVE
no network traffic ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: auth-token-exchange,
  list-namespace-repos; one GATED: delete-repository), so the verdict is DENIED;
* the exchange rung keeps the PAT as ``$KEY``; the JWT-driven rungs keep the
  minted token as ``$JWT`` — the raw PAT never appears in any curl;
* the GATED delete-repository rung is recorded ``blocked`` without consent and
  stays a manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* both Dockerhub / Docker detectors route here;
* the raw PAT is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import dockerhub
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "dckr_pat_" + "EXAMPLEFAKEKEYNOTREAL000000"


def _finding(detector: str = "Dockerhub", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await dockerhub.dockerhub_ladder(_finding(), Consent.denied())


@respx.mock
async def test_dockerhub_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await dockerhub.dockerhub_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "dockerhub"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "auth-token-exchange",
        "list-namespace-repos",
        "delete-repository",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["auth-token-exchange", "list-namespace-repos"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert FAKE_KEY not in rung.evidence["safe_curl"]

    # Rung 1 exchanges the PAT ($KEY); the later rungs carry the minted JWT ($JWT).
    assert "$KEY" in result.rungs[0].evidence["safe_curl"]
    assert "$JWT" in result.rungs[1].evidence["safe_curl"]
    assert "$JWT" in result.rungs[2].evidence["safe_curl"]


@respx.mock
async def test_dockerhub_gated_delete_blocked_without_consent() -> None:
    result = await dockerhub.dockerhub_ladder(_finding(), SAFE_CONSENT)

    delete = next(r for r in result.rungs if r.name == "delete-repository")
    assert delete.tier is ProbeTier.GATED
    assert delete.blocked is True
    assert delete.success is False
    assert "$JWT" in delete.evidence["safe_curl"]


@respx.mock
async def test_dockerhub_gated_delete_with_consent_stays_manual() -> None:
    result = await dockerhub.dockerhub_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    delete = next(r for r in result.rungs if r.name == "delete-repository")
    assert delete.blocked is False
    assert delete.success is False
    assert delete.evidence["manual"] is True


async def test_dockerhub_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await dockerhub.dockerhub_delete_repository(SAFE_CONSENT)
    assert dockerhub.dockerhub_delete_repository.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_dockerhub_result_is_redacted() -> None:
    result = await dockerhub.dockerhub_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Dockerhub") is dockerhub.dockerhub_ladder
    assert get_ladder("Docker") is dockerhub.dockerhub_ladder
    assert get_ladder("dockerhub") is dockerhub.dockerhub_ladder
