"""Tests for the PayPal capability ladder.

A PayPal credential is a ``client_id:client_secret`` pair and every live call
needs a bearer token minted from it, which the engine cannot do from one opaque
secret — so EVERY rung is MANUAL and the ladder makes NO live HTTP call. The
tests run inside ``respx.mock`` (which rejects any unmocked request) to PROVE no
network traffic ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: oauth2-token, userinfo; one
  GATED: create-payout), so the verdict is DENIED;
* each safe_curl keeps the secret as ``$KEY`` (never the raw secret);
* the GATED create-payout rung is recorded ``blocked`` without consent and stays
  a manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw secret is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import paypal
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "EXAMPLEFAKEKEYNOTREALclientid" + ":" + "EXAMPLEFAKEKEYNOTREAL" + "clientsecret"


def _finding(detector: str = "PaypalOauth", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await paypal.paypal_ladder(_finding(), Consent.denied())


@respx.mock
async def test_paypal_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await paypal.paypal_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "paypal"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["oauth2-token", "userinfo", "create-payout"]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["oauth2-token", "userinfo"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
        assert FAKE_KEY not in rung.evidence["safe_curl"]


@respx.mock
async def test_paypal_gated_payout_blocked_without_consent() -> None:
    result = await paypal.paypal_ladder(_finding(), SAFE_CONSENT)

    payout = next(r for r in result.rungs if r.name == "create-payout")
    assert payout.tier is ProbeTier.GATED
    assert payout.blocked is True
    assert payout.success is False
    assert "$KEY" in payout.evidence["safe_curl"]


@respx.mock
async def test_paypal_gated_payout_with_consent_stays_manual() -> None:
    result = await paypal.paypal_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    payout = next(r for r in result.rungs if r.name == "create-payout")
    assert payout.blocked is False
    assert payout.success is False
    assert payout.evidence["manual"] is True


async def test_paypal_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await paypal.paypal_gated_create_payout(SAFE_CONSENT)
    assert paypal.paypal_gated_create_payout.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_paypal_result_is_redacted() -> None:
    result = await paypal.paypal_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("PaypalOauth") is paypal.paypal_ladder
    assert get_ladder("paypaloauth") is paypal.paypal_ladder
