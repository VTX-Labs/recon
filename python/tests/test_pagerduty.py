"""Tests for the PagerDuty capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs two SAFE rungs (abilities -> list-users) to VALID, using the
  ``Authorization: Token token={key}`` header and the versioned Accept header;
* a dead key (401) yields DENIED and stops after the abilities rung;
* the GATED create-incident rung is MANUAL: blocked (no network) without consent,
  and WITH consent it stays a ``$KEY`` safe curl that never fires a live POST;
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import pagerduty
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# PagerDuty REST API keys are 20-char tokens; random padding, not a real key.
FAKE_KEY = "y_AbCd01234_EfGh5678"


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="PagerDutyApiKey", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await pagerduty.pagerduty_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_key_climbs_two_safe_rungs() -> None:
    abilities = respx.get("https://api.pagerduty.com/abilities").mock(
        return_value=httpx.Response(200, json={"abilities": ["sso", "teams", "advanced_reports"]})
    )
    users = respx.get(url__regex=r"https://api\.pagerduty\.com/users.*").mock(
        return_value=httpx.Response(
            200,
            json={"users": [{"id": "P1", "role": "admin"}], "more": False},
        )
    )

    result = await pagerduty.pagerduty_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "pagerduty"
    assert result.verdict is Verdict.VALID
    assert abilities.called
    assert users.called

    req = abilities.calls.last.request
    assert req.url.host == "api.pagerduty.com"
    assert req.url.path == "/abilities"
    assert req.headers["Authorization"] == f"Token token={FAKE_KEY}"
    assert "vnd.pagerduty+json" in req.headers["Accept"]

    abil = result.rungs[0]
    assert abil.name == "abilities"
    assert abil.evidence["ability_count"] == 3

    user_rung = result.rungs[1]
    assert user_rung.name == "list-users"
    assert user_rung.evidence["first_user_id"] == "P1"
    assert user_rung.evidence["first_user_role"] == "admin"


@respx.mock
async def test_dead_key_is_denied_and_stops_early() -> None:
    abilities = respx.get("https://api.pagerduty.com/abilities").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )
    users = respx.get(url__regex=r"https://api\.pagerduty\.com/users.*").mock(
        return_value=httpx.Response(200, json={"users": []})
    )

    result = await pagerduty.pagerduty_ladder(_finding(raw="y_deaddeaddeaddead00"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["abilities"]
    assert abilities.called
    assert not users.called


@respx.mock
async def test_gated_incident_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.pagerduty.com/abilities").mock(
        return_value=httpx.Response(200, json={"abilities": []})
    )
    respx.get(url__regex=r"https://api\.pagerduty\.com/users.*").mock(
        return_value=httpx.Response(200, json={"users": []})
    )
    incident_route = respx.post("https://api.pagerduty.com/incidents").mock(
        return_value=httpx.Response(201, json={"incident": {"id": "leaked"}})
    )

    result = await pagerduty.pagerduty_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "create-incident")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not incident_route.called


@respx.mock
async def test_gated_incident_with_consent_is_manual_no_post() -> None:
    respx.get("https://api.pagerduty.com/abilities").mock(
        return_value=httpx.Response(200, json={"abilities": []})
    )
    respx.get(url__regex=r"https://api\.pagerduty\.com/users.*").mock(
        return_value=httpx.Response(200, json={"users": []})
    )
    incident_route = respx.post("https://api.pagerduty.com/incidents").mock(
        return_value=httpx.Response(201, json={"incident": {"id": "leaked"}})
    )

    result = await pagerduty.pagerduty_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "create-incident")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert not incident_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert pagerduty._pagerduty_create_incident.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.pagerduty.com/abilities").mock(
        return_value=httpx.Response(200, json={"abilities": []})
    )
    respx.get(url__regex=r"https://api\.pagerduty\.com/users.*").mock(
        return_value=httpx.Response(200, json={"users": []})
    )
    result = await pagerduty.pagerduty_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("PagerDutyApiKey") is pagerduty.pagerduty_ladder
    assert get_ladder("pagerdutyapikey") is pagerduty.pagerduty_ladder
