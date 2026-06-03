"""Tests for the Postmark capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (get-server -> delivery-stats) to VALID,
  using the ``X-Postmark-Server-Token`` header;
* a dead token (401) yields DENIED and stops after the identity rung;
* the GATED send-email rung is MANUAL: blocked (no network) without consent, and
  WITH consent it stays a ``$KEY`` safe curl that never fires a live POST;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import postmark
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# Postmark server token is a UUID; random padding, not a real token.
FAKE_KEY = "a1b2c3d4-0011-2233-4455-66778899aabb"


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Postmark", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await postmark.postmark_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_two_safe_rungs() -> None:
    server = respx.get("https://api.postmarkapp.com/server").mock(
        return_value=httpx.Response(
            200,
            json={
                "ID": 12345,
                "Name": "Victim Prod",
                "Color": "blue",
                "SmtpApiActivated": True,
                "DeliveryType": "Live",
            },
        )
    )
    stats = respx.get("https://api.postmarkapp.com/deliverystats").mock(
        return_value=httpx.Response(
            200,
            json={"InactiveMails": 3, "Bounces": [{"Type": "HardBounce"}, {"Type": "Spam"}]},
        )
    )

    result = await postmark.postmark_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "postmark"
    assert result.verdict is Verdict.VALID
    assert server.called
    assert stats.called

    req = server.calls.last.request
    assert req.url.host == "api.postmarkapp.com"
    assert req.url.path == "/server"
    assert req.headers["X-Postmark-Server-Token"] == FAKE_KEY

    identity = result.rungs[0]
    assert identity.name == "get-server"
    assert identity.evidence["id"] == 12345
    assert identity.evidence["name"] == "Victim Prod"

    stat = result.rungs[1]
    assert stat.name == "delivery-stats"
    assert stat.evidence["inactive_mails"] == 3
    assert stat.evidence["bounce_type_count"] == 2


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    server = respx.get("https://api.postmarkapp.com/server").mock(
        return_value=httpx.Response(401, json={"ErrorCode": 10, "Message": "Bad token"})
    )
    stats = respx.get("https://api.postmarkapp.com/deliverystats").mock(
        return_value=httpx.Response(200, json={"InactiveMails": 0, "Bounces": []})
    )

    result = await postmark.postmark_ladder(
        _finding(raw="00000000-dead-dead-dead-000000000000"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["get-server"]
    assert server.called
    assert not stats.called


@respx.mock
async def test_gated_send_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.postmarkapp.com/server").mock(
        return_value=httpx.Response(200, json={"ID": 1, "Name": "S"})
    )
    respx.get("https://api.postmarkapp.com/deliverystats").mock(
        return_value=httpx.Response(200, json={"InactiveMails": 0, "Bounces": []})
    )
    send_route = respx.post("https://api.postmarkapp.com/email").mock(
        return_value=httpx.Response(200, json={"MessageID": "leaked"})
    )

    result = await postmark.postmark_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "send-email")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not send_route.called


@respx.mock
async def test_gated_send_with_consent_is_manual_no_post() -> None:
    respx.get("https://api.postmarkapp.com/server").mock(
        return_value=httpx.Response(200, json={"ID": 1, "Name": "S"})
    )
    respx.get("https://api.postmarkapp.com/deliverystats").mock(
        return_value=httpx.Response(200, json={"InactiveMails": 0, "Bounces": []})
    )
    send_route = respx.post("https://api.postmarkapp.com/email").mock(
        return_value=httpx.Response(200, json={"MessageID": "leaked"})
    )

    result = await postmark.postmark_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "send-email")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert not send_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert postmark._postmark_send_email.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.postmarkapp.com/server").mock(
        return_value=httpx.Response(200, json={"ID": 1, "Name": "S"})
    )
    respx.get("https://api.postmarkapp.com/deliverystats").mock(
        return_value=httpx.Response(200, json={"InactiveMails": 0, "Bounces": []})
    )
    result = await postmark.postmark_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Postmark") is postmark.postmark_ladder
    assert get_ladder("postmark") is postmark.postmark_ladder
