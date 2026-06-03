"""Tests for the SendGrid capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs the SAFE ``scopes`` rung to VALID with the bearer header,
  surfacing the granted scopes (and a redacted key prefix, never the raw key);
* a dead key (401) yields DENIED and skips the gated rung;
* the GATED mail-send is structurally blocked without consent (recorded
  ``blocked``, NO network call), and WITH full consent it actually FIRES (a live
  gated rung) — SendGrid's 202 -> PROVEN with a state-changed flag;
* a no-scope consent raises ScopeRequired;
* the raw key is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import sendgrid
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "SG." + "EXAMPLEFAKEKEYNOTREAL0" + "." + "EXAMPLEFAKEKEYNOTREAL000000000000000000000"


def _finding(detector: str = "SendGrid", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await sendgrid.sendgrid_ladder(_finding(), Consent.denied())


@respx.mock
async def test_sendgrid_valid_key_climbs_safe_rung() -> None:
    scopes = respx.get("https://api.sendgrid.com/v3/scopes").mock(
        return_value=httpx.Response(
            200, json={"scopes": ["mail.send", "user.profile.read", "stats.read"]}
        )
    )

    result = await sendgrid.sendgrid_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "sendgrid"
    assert result.verdict is Verdict.VALID
    scopes_rung = next(r for r in result.rungs if r.name == "sendgrid.scopes")
    assert scopes_rung.tier is ProbeTier.SAFE
    assert scopes_rung.success is True
    assert scopes.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert scopes_rung.evidence["scope_count"] == 3
    assert scopes_rung.evidence["can_send_mail"] is True
    # The key prefix is redacted in evidence, never the raw key.
    assert FAKE_KEY not in scopes_rung.evidence["key_prefix"]
    # Without consent the gated send rung is blocked.
    send = next(r for r in result.rungs if r.name == "sendgrid.send_mail")
    assert send.blocked is True


@respx.mock
async def test_sendgrid_dead_key_is_denied_and_skips_gated() -> None:
    scopes = respx.get("https://api.sendgrid.com/v3/scopes").mock(
        return_value=httpx.Response(401, json={"errors": [{"message": "invalid"}]})
    )
    send_route = respx.post("https://api.sendgrid.com/v3/mail/send").mock(
        return_value=httpx.Response(202)
    )

    result = await sendgrid.sendgrid_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["sendgrid.scopes"]
    assert scopes.called
    assert not send_route.called


@respx.mock
async def test_sendgrid_gated_send_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.sendgrid.com/v3/scopes").mock(
        return_value=httpx.Response(200, json={"scopes": ["mail.send"]})
    )
    send_route = respx.post("https://api.sendgrid.com/v3/mail/send").mock(
        return_value=httpx.Response(202)
    )

    result = await sendgrid.sendgrid_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    send = next(r for r in result.rungs if r.name == "sendgrid.send_mail")
    assert send.tier is ProbeTier.GATED
    assert send.blocked is True
    assert send.success is False
    # The hard guarantee: no email was ever sent.
    assert not send_route.called


@respx.mock
async def test_sendgrid_gated_send_fires_with_full_consent_is_proven() -> None:
    respx.get("https://api.sendgrid.com/v3/scopes").mock(
        return_value=httpx.Response(200, json={"scopes": ["mail.send"]})
    )
    send_route = respx.post("https://api.sendgrid.com/v3/mail/send").mock(
        return_value=httpx.Response(202)
    )

    result = await sendgrid.sendgrid_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.PROVEN
    send = next(r for r in result.rungs if r.name == "sendgrid.send_mail")
    assert send.tier is ProbeTier.GATED
    assert send.blocked is False
    assert send.success is True
    assert send.evidence["state_changed"] is True
    assert send_route.called
    assert send_route.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_KEY}"


async def test_sendgrid_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await sendgrid._sendgrid_send_mail(SAFE_CONSENT, FAKE_KEY)
    assert sendgrid._sendgrid_send_mail.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_sendgrid_result_is_redacted() -> None:
    respx.get("https://api.sendgrid.com/v3/scopes").mock(
        return_value=httpx.Response(200, json={"scopes": ["mail.send"]})
    )

    result = await sendgrid.sendgrid_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("SendGrid") is sendgrid.sendgrid_ladder
    assert get_ladder("Sendgrid") is sendgrid.sendgrid_ladder
    assert get_ladder("sendgrid") is sendgrid.sendgrid_ladder
