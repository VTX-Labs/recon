"""Tests for the Render capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs two SAFE rungs (list-owners -> list-services) to VALID,
  using Bearer auth;
* a dead key (401) yields DENIED and stops after the identity rung;
* the GATED read-env-vars rung is MANUAL: blocked (no network) without consent,
  and WITH consent it stays a ``$KEY`` safe curl that never fires a live call;
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import render
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# rnd_<random>; random padding, not a real key.
FAKE_KEY = "rnd_" + "EXAMPLEFAKEKEYNOTREAL0"


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Render", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await render.render_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_key_climbs_two_safe_rungs() -> None:
    owners = respx.get("https://api.render.com/v1/owners").mock(
        return_value=httpx.Response(
            200,
            json=[{"owner": {"id": "own-1", "name": "Acme", "email": "leak@victim.example"}}],
        )
    )
    services = respx.get("https://api.render.com/v1/services").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"service": {"id": "srv-1", "name": "api", "type": "web_service"}},
                {"service": {"id": "srv-2", "name": "worker", "type": "background_worker"}},
            ],
        )
    )

    result = await render.render_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "render"
    assert result.verdict is Verdict.VALID
    assert owners.called
    assert services.called

    req = owners.calls.last.request
    assert req.url.host == "api.render.com"
    assert req.url.path == "/v1/owners"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"

    own = result.rungs[0]
    assert own.name == "list-owners"
    assert own.evidence["owner_count"] == 1
    assert own.evidence["owner_names"] == ["Acme"]

    svc = result.rungs[1]
    assert svc.name == "list-services"
    assert svc.success is True
    assert svc.evidence["service_count"] == 2
    assert svc.evidence["service_types"] == ["background_worker", "web_service"]


@respx.mock
async def test_dead_key_is_denied_and_stops_early() -> None:
    owners = respx.get("https://api.render.com/v1/owners").mock(
        return_value=httpx.Response(401, json={"message": "Unauthorized"})
    )
    services = respx.get("https://api.render.com/v1/services").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await render.render_ladder(_finding(raw="rnd_deadbeef"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["list-owners"]
    assert owners.called
    assert not services.called


@respx.mock
async def test_gated_env_vars_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.render.com/v1/owners").mock(
        return_value=httpx.Response(200, json=[{"owner": {"id": "o1", "name": "Acme"}}])
    )
    respx.get("https://api.render.com/v1/services").mock(
        return_value=httpx.Response(
            200, json=[{"service": {"id": "srv-1", "name": "api", "type": "web_service"}}]
        )
    )
    env_route = respx.get(url__regex=r"https://api\.render\.com/v1/services/.*/env-vars").mock(
        return_value=httpx.Response(
            200, json=[{"envVar": {"key": "DATABASE_URL", "value": "leaked"}}]
        )
    )

    result = await render.render_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "read-env-vars")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not env_route.called


@respx.mock
async def test_gated_env_vars_with_consent_is_manual_no_call() -> None:
    respx.get("https://api.render.com/v1/owners").mock(
        return_value=httpx.Response(200, json=[{"owner": {"id": "o1", "name": "Acme"}}])
    )
    respx.get("https://api.render.com/v1/services").mock(
        return_value=httpx.Response(
            200, json=[{"service": {"id": "srv-1", "name": "api", "type": "web_service"}}]
        )
    )
    env_route = respx.get(url__regex=r"https://api\.render\.com/v1/services/.*/env-vars").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await render.render_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "read-env-vars")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert not env_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert render._render_read_env_vars.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.render.com/v1/owners").mock(return_value=httpx.Response(200, json=[]))
    respx.get("https://api.render.com/v1/services").mock(return_value=httpx.Response(200, json=[]))
    result = await render.render_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Render") is render.render_ladder
    assert get_ladder("render") is render.render_ladder
