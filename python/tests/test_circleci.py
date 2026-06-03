"""Tests for the CircleCI capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (whoami -> collaborations) to VALID, using
  the ``Circle-Token`` header;
* a dead token (401) yields DENIED and stops after the identity rung;
* the GATED trigger-pipeline rung is MANUAL: always recorded blocked with a
  ``$KEY`` safe curl and never fires a live POST (no consent needed to observe);
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import circleci
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# Modern CircleCI PAT shape: CCIPAT_<...>; random padding, not a real token.
FAKE_KEY = "CCIPAT_" + "EXAMPLEFAKEKEYNOTREAL0" + "_" + "deadbeef" * 5


def _finding(detector: str = "CircleCI", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await circleci.circleci_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_two_safe_rungs() -> None:
    me = respx.get("https://circleci.com/api/v2/me").mock(
        return_value=httpx.Response(200, json={"id": "u-1", "login": "leaky-bot", "name": "Bot"})
    )
    collabs = respx.get("https://circleci.com/api/v2/me/collaborations").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"slug": "gh/acme", "name": "acme"},
                {"slug": "gh/beta", "name": "beta"},
            ],
        )
    )

    result = await circleci.circleci_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "circleci"
    assert result.verdict is Verdict.VALID
    assert me.called
    assert collabs.called

    req = me.calls.last.request
    assert req.url.host == "circleci.com"
    assert req.url.path == "/api/v2/me"
    assert req.headers["Circle-Token"] == FAKE_KEY

    identity = result.rungs[0]
    assert identity.name == "circleci.whoami"
    assert identity.evidence["login"] == "leaky-bot"

    collab = result.rungs[1]
    assert collab.name == "circleci.list-collaborations"
    assert collab.evidence["collaboration_count"] == 2
    assert collab.evidence["slugs"] == ["gh/acme", "gh/beta"]


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    me = respx.get("https://circleci.com/api/v2/me").mock(
        return_value=httpx.Response(401, json={"message": "Unauthorized"})
    )
    collabs = respx.get("https://circleci.com/api/v2/me/collaborations").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await circleci.circleci_ladder(_finding(raw="CCIPAT_dead_deadbeef"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["circleci.whoami"]
    assert me.called
    assert not collabs.called


@respx.mock
async def test_gated_trigger_pipeline_is_manual_blocked_note() -> None:
    respx.get("https://circleci.com/api/v2/me").mock(
        return_value=httpx.Response(200, json={"id": "u-1", "login": "bot"})
    )
    respx.get("https://circleci.com/api/v2/me/collaborations").mock(
        return_value=httpx.Response(200, json=[])
    )
    # A POST to trigger a pipeline must never be issued by the ladder.
    pipeline_route = respx.post(url__regex=r"https://circleci\.com/api/v2/project/.*").mock(
        return_value=httpx.Response(201, json={"id": "leaked"})
    )

    # Even with FULL consent the manual rung is recorded blocked and never fires.
    result = await circleci.circleci_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "circleci.trigger-pipeline")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert gated.evidence["billable"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not pipeline_route.called


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://circleci.com/api/v2/me").mock(
        return_value=httpx.Response(200, json={"id": "u-1", "login": "bot"})
    )
    respx.get("https://circleci.com/api/v2/me/collaborations").mock(
        return_value=httpx.Response(200, json=[])
    )
    result = await circleci.circleci_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Circle") is circleci.circleci_ladder
    assert get_ladder("CircleCI") is circleci.circleci_ladder
    assert get_ladder("circleci") is circleci.circleci_ladder
