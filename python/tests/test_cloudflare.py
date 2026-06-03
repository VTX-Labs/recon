"""Tests for the Cloudflare capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs three SAFE rungs (verify-token -> permissions -> zones)
  to VALID, with the bearer header and real JSON evidence;
* a dead token (403) yields DENIED and stops after verify-token;
* the GATED edit-dns rung is structurally blocked without consent (recorded
  ``blocked``, NO network call) and stays a MANUAL safe-curl note even WITH
  full consent (its URL needs a ZONE_ID the engine cannot fill);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import cloudflare
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "v1.0-" + "EXAMPLEFAKEKEYNOTREAL0000000000000000000"


def _finding(detector: str = "CloudflareApiToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


def _ok(result: dict) -> dict:
    return {"success": True, "errors": [], "messages": [], "result": result}


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await cloudflare.cloudflare_ladder(_finding(), Consent.denied())


@respx.mock
async def test_cloudflare_valid_token_climbs_safe_rungs() -> None:
    verify = respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(
            200, json=_ok({"id": "tok_123", "status": "active", "expires_on": None})
        )
    )
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/permission_groups").mock(
        return_value=httpx.Response(200, json=_ok([{"name": "DNS Write"}, {"name": "Zone Read"}]))
    )
    respx.get("https://api.cloudflare.com/client/v4/zones").mock(
        return_value=httpx.Response(200, json=_ok([{"name": "victim.example"}]))
    )

    result = await cloudflare.cloudflare_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "cloudflare"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == "acme h1 program #4242"
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["verify-token", "token-permissions", "list-zones"]
    assert all(r.success for r in safe)
    # The bearer header carried the live token.
    assert verify.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    verify_rung = next(r for r in result.rungs if r.name == "verify-token")
    assert verify_rung.evidence["token_id"] == "tok_123"
    perms = next(r for r in result.rungs if r.name == "token-permissions")
    assert perms.evidence["permission_group_count"] == 2
    zones = next(r for r in result.rungs if r.name == "list-zones")
    assert zones.evidence["zone_count"] == 1


@respx.mock
async def test_cloudflare_dead_token_is_denied_and_stops_early() -> None:
    verify = respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(403, json={"success": False, "errors": [{"message": "bad"}]})
    )
    perms = respx.get("https://api.cloudflare.com/client/v4/user/tokens/permission_groups").mock(
        return_value=httpx.Response(200, json=_ok([]))
    )

    result = await cloudflare.cloudflare_ladder(
        _finding(raw="v1.0-deadtokendeadtokendeadtoken"), FULL_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["verify-token"]
    assert verify.called
    assert not perms.called


@respx.mock
async def test_cloudflare_gated_edit_dns_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(200, json=_ok({"id": "tok_1", "status": "active"}))
    )
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/permission_groups").mock(
        return_value=httpx.Response(200, json=_ok([]))
    )
    respx.get("https://api.cloudflare.com/client/v4/zones").mock(
        return_value=httpx.Response(200, json=_ok([{"name": "victim.example"}]))
    )
    # If the boundary ever leaked, this mutating route would be hit. It must not be.
    dns_route = respx.post("https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records").mock(
        return_value=httpx.Response(200, json=_ok({"id": "rec_LEAK"}))
    )

    result = await cloudflare.cloudflare_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    dns = next(r for r in result.rungs if r.name == "edit-dns-record")
    assert dns.tier is ProbeTier.GATED
    assert dns.blocked is True
    assert dns.success is False
    assert dns.evidence["manual"] is True
    assert "$KEY" in dns.evidence["safe_curl"]
    assert FAKE_KEY not in dns.evidence["safe_curl"]
    assert not dns_route.called


@respx.mock
async def test_cloudflare_gated_edit_dns_with_consent_stays_manual_no_call() -> None:
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(200, json=_ok({"id": "tok_1", "status": "active"}))
    )
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/permission_groups").mock(
        return_value=httpx.Response(200, json=_ok([]))
    )
    respx.get("https://api.cloudflare.com/client/v4/zones").mock(
        return_value=httpx.Response(200, json=_ok([{"name": "victim.example"}]))
    )
    dns_route = respx.post("https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records").mock(
        return_value=httpx.Response(200, json=_ok({"id": "rec_LEAK"}))
    )

    result = await cloudflare.cloudflare_ladder(_finding(), FULL_CONSENT)

    # Even with full consent the manual gated rung never fires (needs ZONE_ID),
    # so it is not a successful GATED rung and the verdict stays VALID.
    assert result.verdict is Verdict.VALID
    dns = next(r for r in result.rungs if r.name == "edit-dns-record")
    assert dns.blocked is False
    assert dns.success is False
    assert dns.evidence["manual"] is True
    assert not dns_route.called


async def test_cloudflare_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await cloudflare.cloudflare_gated_edit_dns(SAFE_CONSENT)
    assert cloudflare.cloudflare_gated_edit_dns.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_cloudflare_result_is_redacted() -> None:
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").mock(
        return_value=httpx.Response(200, json=_ok({"id": "tok_1", "status": "active"}))
    )
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/permission_groups").mock(
        return_value=httpx.Response(200, json=_ok([]))
    )
    respx.get("https://api.cloudflare.com/client/v4/zones").mock(
        return_value=httpx.Response(200, json=_ok([]))
    )

    result = await cloudflare.cloudflare_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("CloudflareApiToken") is cloudflare.cloudflare_ladder
    assert get_ladder("CloudflareGlobalApiKey") is cloudflare.cloudflare_ladder
    assert get_ladder("cloudflareapitoken") is cloudflare.cloudflare_ladder
