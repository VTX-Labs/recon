"""Tests for the Figma personal-access-token capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid PAT climbs the SAFE ``me`` rung to VALID, sent with the Figma-specific
  ``X-Figma-Token`` header (NOT ``Authorization``), and the deeper
  ``list-team-projects`` rung is a MANUAL safe-curl note (it needs a team_id the
  engine cannot fill, so it never fires);
* a dead token (403) yields DENIED and stops after ``me``;
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import figma
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")

FAKE_KEY = "figd_" + "EXAMPLE-FAKE-KEY-NOT-REAL000000000000000"


def _finding(detector: str = "FigmaPersonalAccessToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await figma.figma_ladder(_finding(), Consent.denied())


@respx.mock
async def test_figma_valid_token_climbs_me_and_emits_manual_rung() -> None:
    me = respx.get("https://api.figma.com/v1/me").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "12345",
                "handle": "victim",
                "email": "victim@example.com",
                "img_url": "https://example.com/a.png",
            },
        )
    )

    result = await figma.figma_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "figma"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == ["me", "list-team-projects"]
    # Figma uses the X-Figma-Token header, never Authorization.
    assert me.calls.last.request.headers["X-Figma-Token"] == FAKE_KEY
    assert "Authorization" not in me.calls.last.request.headers
    identity = next(r for r in result.rungs if r.name == "me")
    assert identity.success is True
    assert identity.evidence["handle"] == "victim"
    # The deeper rung is MANUAL (needs a team_id) and never fired.
    projects = next(r for r in result.rungs if r.name == "list-team-projects")
    assert projects.success is False
    assert projects.tier is ProbeTier.SAFE
    assert projects.evidence["manual"] is True
    assert "$KEY" in projects.evidence["safe_curl"]
    assert FAKE_KEY not in projects.evidence["safe_curl"]


@respx.mock
async def test_figma_dead_token_is_denied_and_stops_early() -> None:
    me = respx.get("https://api.figma.com/v1/me").mock(
        return_value=httpx.Response(403, json={"status": 403, "err": "Invalid token"})
    )

    result = await figma.figma_ladder(
        _finding(raw="figd_deadtokendeadtokendeadtokendeadtoken00"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["me"]
    assert me.called


@respx.mock
async def test_figma_result_is_redacted() -> None:
    respx.get("https://api.figma.com/v1/me").mock(
        return_value=httpx.Response(200, json={"id": "1", "handle": "v"})
    )

    result = await figma.figma_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("FigmaPersonalAccessToken") is figma.figma_ladder
    assert get_ladder("figmapersonalaccesstoken") is figma.figma_ladder
