"""Tests for the Fastly capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (token-self -> list-services) to VALID,
  using the ``Fastly-Key`` header (NOT Bearer);
* a dead token (401) yields DENIED and stops after the identity rung;
* the GATED purge-all rung is MANUAL: blocked (no network) without consent, and
  WITH consent it stays a ``$KEY`` safe curl that never fires a live POST;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import fastly
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# 32-char [A-Za-z0-9_-] Fastly token; random padding, not a real token.
FAKE_KEY = "AbCdEf01234567_GhIjKl-89mnopQRST"


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="FastlyPersonalToken", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await fastly.fastly_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_two_safe_rungs() -> None:
    token_self = respx.get("https://api.fastly.com/tokens/self").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "tok-1",
                "user_id": "user-1",
                "scope": "global:read",
                "created_at": "2024-01-01T00:00:00Z",
                "services": ["svc-1", "svc-2"],
            },
        )
    )
    services = respx.get("https://api.fastly.com/service").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": "svc-1", "name": "cdn-prod"}, {"id": "svc-2", "name": "cdn-stg"}],
        )
    )

    result = await fastly.fastly_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "fastly"
    assert result.verdict is Verdict.VALID
    assert token_self.called
    assert services.called

    req = token_self.calls.last.request
    assert req.url.host == "api.fastly.com"
    assert req.url.path == "/tokens/self"
    assert req.headers["Fastly-Key"] == FAKE_KEY
    assert "Authorization" not in req.headers

    identity = result.rungs[0]
    assert identity.name == "token-self"
    assert identity.evidence["scope"] == "global:read"
    assert identity.evidence["scoped_service_count"] == 2

    svc = result.rungs[1]
    assert svc.name == "list-services"
    assert svc.success is True
    assert svc.evidence["service_count"] == 2
    assert svc.evidence["service_names"] == ["cdn-prod", "cdn-stg"]


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    token_self = respx.get("https://api.fastly.com/tokens/self").mock(
        return_value=httpx.Response(
            401, json={"msg": "Provided credentials are missing or invalid"}
        )
    )
    services = respx.get("https://api.fastly.com/service").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await fastly.fastly_ladder(
        _finding(raw="DEADdeadDEADdeadDEADdeadDEADdead"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["token-self"]
    assert token_self.called
    assert not services.called


@respx.mock
async def test_gated_purge_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.fastly.com/tokens/self").mock(
        return_value=httpx.Response(200, json={"id": "tok-1", "scope": "global"})
    )
    respx.get("https://api.fastly.com/service").mock(
        return_value=httpx.Response(200, json=[{"id": "svc-1", "name": "cdn"}])
    )
    purge_route = respx.post(url__regex=r"https://api\.fastly\.com/service/.*/purge_all").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    result = await fastly.fastly_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "purge-all")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not purge_route.called


@respx.mock
async def test_gated_purge_with_consent_is_manual_no_post() -> None:
    respx.get("https://api.fastly.com/tokens/self").mock(
        return_value=httpx.Response(200, json={"id": "tok-1", "scope": "global"})
    )
    respx.get("https://api.fastly.com/service").mock(
        return_value=httpx.Response(200, json=[{"id": "svc-1", "name": "cdn"}])
    )
    purge_route = respx.post(url__regex=r"https://api\.fastly\.com/service/.*/purge_all").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    result = await fastly.fastly_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "purge-all")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert not purge_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert fastly._fastly_purge_all.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.fastly.com/tokens/self").mock(
        return_value=httpx.Response(200, json={"id": "tok-1", "scope": "global"})
    )
    respx.get("https://api.fastly.com/service").mock(return_value=httpx.Response(200, json=[]))
    result = await fastly.fastly_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("FastlyPersonalToken") is fastly.fastly_ladder
    assert get_ladder("fastlypersonaltoken") is fastly.fastly_ladder
