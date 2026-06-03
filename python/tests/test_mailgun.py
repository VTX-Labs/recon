"""Tests for the Mailgun capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs two SAFE rungs (list-domains -> list-domain-keys) to VALID,
  using ``Authorization: Basic {key}`` (Mailgun has no whoami);
* a dead key (401) yields DENIED and stops after the identity/domains rung;
* the GATED send-message rung is MANUAL: blocked (no network) without consent,
  and WITH consent it stays a ``$KEY`` safe curl that never fires a live POST;
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import mailgun
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# Legacy key-<32 hex/alnum> shape; random padding, not a real key.
FAKE_KEY = "key" + "-" + "deadbeef" * 4


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Mailgun", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await mailgun.mailgun_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_key_climbs_two_safe_rungs() -> None:
    domains = respx.get("https://api.mailgun.net/v4/domains").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 2,
                "items": [{"name": "mg.victim.example"}, {"name": "mail.victim.example"}],
            },
        )
    )
    dkim = respx.get("https://api.mailgun.net/v1/dkim/keys").mock(
        return_value=httpx.Response(
            200,
            json={"items": [{"signing_domain": "mg.victim.example"}]},
        )
    )

    result = await mailgun.mailgun_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "mailgun"
    assert result.verdict is Verdict.VALID
    assert domains.called
    assert dkim.called

    req = domains.calls.last.request
    assert req.url.host == "api.mailgun.net"
    assert req.url.path == "/v4/domains"
    assert req.headers["Authorization"] == f"Basic {FAKE_KEY}"

    identity = result.rungs[0]
    assert identity.name == "list-domains"
    assert identity.evidence["domain_count"] == 2
    assert identity.evidence["total_count"] == 2

    keys = result.rungs[1]
    assert keys.name == "list-domain-keys"
    assert keys.evidence["dkim_key_count"] == 1


@respx.mock
async def test_dead_key_is_denied_and_stops_early() -> None:
    domains = respx.get("https://api.mailgun.net/v4/domains").mock(
        return_value=httpx.Response(401, json={"message": "Invalid private key"})
    )
    dkim = respx.get("https://api.mailgun.net/v1/dkim/keys").mock(
        return_value=httpx.Response(200, json={"items": []})
    )

    result = await mailgun.mailgun_ladder(_finding(raw="key-deadbeefdeadbeef"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["list-domains"]
    assert domains.called
    assert not dkim.called


@respx.mock
async def test_gated_send_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.mailgun.net/v4/domains").mock(
        return_value=httpx.Response(200, json={"items": [{"name": "mg.x"}], "total_count": 1})
    )
    respx.get("https://api.mailgun.net/v1/dkim/keys").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    send_route = respx.post(url__regex=r"https://api\.mailgun\.net/v3/.*/messages").mock(
        return_value=httpx.Response(200, json={"id": "leaked"})
    )

    result = await mailgun.mailgun_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "send-message")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not send_route.called


@respx.mock
async def test_gated_send_with_consent_is_manual_no_post() -> None:
    respx.get("https://api.mailgun.net/v4/domains").mock(
        return_value=httpx.Response(200, json={"items": [], "total_count": 0})
    )
    respx.get("https://api.mailgun.net/v1/dkim/keys").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    send_route = respx.post(url__regex=r"https://api\.mailgun\.net/v3/.*/messages").mock(
        return_value=httpx.Response(200, json={"id": "leaked"})
    )

    result = await mailgun.mailgun_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "send-message")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert not send_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert mailgun.mailgun_gated_send_message.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.mailgun.net/v4/domains").mock(
        return_value=httpx.Response(200, json={"items": [], "total_count": 0})
    )
    respx.get("https://api.mailgun.net/v1/dkim/keys").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    result = await mailgun.mailgun_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Mailgun") is mailgun.mailgun_ladder
    assert get_ladder("mailgun") is mailgun.mailgun_ladder
