"""Tests for the Asana capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (users-me -> list-workspaces) to VALID;
* a dead token (401) yields DENIED and stops after the identity rung;
* the GATED list-workspace-users rung is MANUAL: blocked (no network) without
  consent, and WITH consent it still only renders a ``$KEY`` safe curl;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import asana
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# Asana PATs are long opaque strings; random padding, not a real token.
FAKE_KEY = "0/0000000000000000:" + "00000000000000000000000000000000"


def _finding(detector: str = "AsanaPersonalAccessToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await asana.asana_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_two_safe_rungs() -> None:
    me = respx.get("https://app.asana.com/api/1.0/users/me").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "gid": "1199",
                    "name": "Leaky Bot",
                    "email": "leak@victim.example",
                    "workspaces": [{"gid": "W1", "name": "Acme"}],
                }
            },
        )
    )
    workspaces = respx.get("https://app.asana.com/api/1.0/workspaces").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"gid": "W1", "name": "Acme"}, {"gid": "W2", "name": "Beta"}]},
        )
    )

    result = await asana.asana_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "asana"
    assert result.verdict is Verdict.VALID
    assert me.called
    assert workspaces.called

    req = me.calls.last.request
    assert req.url.host == "app.asana.com"
    assert req.url.path == "/api/1.0/users/me"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"

    identity = result.rungs[0]
    assert identity.name == "users-me"
    assert identity.tier is ProbeTier.SAFE
    assert identity.evidence["gid"] == "1199"
    assert identity.evidence["workspace_count"] == 1

    ws = result.rungs[1]
    assert ws.name == "list-workspaces"
    assert ws.evidence["workspace_count"] == 2


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    me = respx.get("https://app.asana.com/api/1.0/users/me").mock(
        return_value=httpx.Response(401, json={"errors": [{"message": "Not Authorized"}]})
    )
    workspaces = respx.get("https://app.asana.com/api/1.0/workspaces").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    result = await asana.asana_ladder(_finding(raw="1/dead:deadbeef"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["users-me"]
    assert me.called
    assert not workspaces.called


@respx.mock
async def test_gated_users_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://app.asana.com/api/1.0/users/me").mock(
        return_value=httpx.Response(200, json={"data": {"gid": "1", "workspaces": []}})
    )
    respx.get("https://app.asana.com/api/1.0/workspaces").mock(
        return_value=httpx.Response(200, json={"data": [{"gid": "W1", "name": "Acme"}]})
    )
    # If the boundary ever leaked, the directory read would be hit. It must not be.
    users_route = respx.get("https://app.asana.com/api/1.0/users").mock(
        return_value=httpx.Response(200, json={"data": [{"email": "leak@x"}]})
    )

    result = await asana.asana_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "list-workspace-users")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not users_route.called


@respx.mock
async def test_gated_users_with_consent_is_manual_safe_curl() -> None:
    respx.get("https://app.asana.com/api/1.0/users/me").mock(
        return_value=httpx.Response(200, json={"data": {"gid": "1", "workspaces": []}})
    )
    respx.get("https://app.asana.com/api/1.0/workspaces").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    users_route = respx.get("https://app.asana.com/api/1.0/users").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    result = await asana.asana_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "list-workspace-users")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    # Manual: never fires the live directory read even under consent.
    assert not users_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert asana.asana_gated_list_workspace_users.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://app.asana.com/api/1.0/users/me").mock(
        return_value=httpx.Response(200, json={"data": {"gid": "1", "workspaces": []}})
    )
    respx.get("https://app.asana.com/api/1.0/workspaces").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await asana.asana_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("AsanaPersonalAccessToken") is asana.asana_ladder
    assert get_ladder("AsanaOauth") is asana.asana_ladder
    assert get_ladder("asanaoauth") is asana.asana_ladder
