"""Tests for the Stripe capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs its SAFE rungs (auth -> products -> balance txns) to VALID,
  and a restricted-key 403 on a scope probe still counts as reachable;
* a dead key yields DENIED and skips every gated rung;
* the GATED account/charges reads are *structurally* blocked without consent —
  recorded ``blocked`` and firing NO network request;
* with full consent the gated reads run -> PROVEN, PII summarised not dumped.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import stripe
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")


def _finding(detector: str, raw: str) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await stripe.stripe_ladder(_finding("Stripe", "sk_live_x"), Consent.denied())


@respx.mock
async def test_stripe_valid_key_climbs_safe_rungs_403_still_reachable() -> None:
    respx.get("https://api.stripe.com/v1/balance").mock(
        return_value=httpx.Response(200, json={"object": "balance"})
    )
    # Restricted key: forbidden on products, but still a live key.
    respx.get("https://api.stripe.com/v1/products").mock(
        return_value=httpx.Response(403, json={"error": {"message": "no permission"}})
    )
    respx.get("https://api.stripe.com/v1/balance_transactions").mock(
        return_value=httpx.Response(200, json={"object": "list", "data": [{"id": "txn_1"}]})
    )

    result = await stripe.stripe_ladder(_finding("Stripe", "sk_live_x"), SAFE_CONSENT)

    assert result.provider == "stripe"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == [
        "stripe.auth_check",
        "stripe.products.list",
        "stripe.balance_transactions",
    ]
    assert all(r.success for r in safe)
    products = next(r for r in result.rungs if r.name == "stripe.products.list")
    assert products.evidence["readable"] is False  # 403 -> reachable, not readable
    txns = next(r for r in result.rungs if r.name == "stripe.balance_transactions")
    assert txns.evidence["readable"] is True
    assert txns.evidence["sample_count"] == 1


@respx.mock
async def test_stripe_gated_rungs_blocked_without_consent_make_no_call() -> None:
    respx.get("https://api.stripe.com/v1/balance").mock(
        return_value=httpx.Response(200, json={"object": "balance"})
    )
    respx.get("https://api.stripe.com/v1/products").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get("https://api.stripe.com/v1/balance_transactions").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    # If the boundary ever leaked, these would be hit. They must not be.
    account_route = respx.get("https://api.stripe.com/v1/account").mock(
        return_value=httpx.Response(200, json={"id": "acct_LEAK"})
    )
    charges_route = respx.get("https://api.stripe.com/v1/charges").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "ch_LEAK"}]})
    )

    result = await stripe.stripe_ladder(_finding("Stripe", "sk_live_x"), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    account = next(r for r in result.rungs if r.name == "stripe.account.read")
    charges = next(r for r in result.rungs if r.name == "stripe.charges.list")
    for rung in (account, charges):
        assert rung.tier is ProbeTier.GATED
        assert rung.blocked is True
        assert rung.success is False
    # The hard guarantee: no PII request was ever issued.
    assert not account_route.called
    assert not charges_route.called


@respx.mock
async def test_stripe_gated_probes_raise_when_called_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probes themselves refuse."""
    account_route = respx.get("https://api.stripe.com/v1/account").mock(
        return_value=httpx.Response(200, json={"id": "acct_LEAK"})
    )
    charges_route = respx.get("https://api.stripe.com/v1/charges").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    with pytest.raises(GatedProbeBlocked):
        await stripe._stripe_account_read(SAFE_CONSENT, "sk_live_x")
    with pytest.raises(GatedProbeBlocked):
        await stripe._stripe_charges_list(SAFE_CONSENT, "sk_live_x")
    assert not account_route.called
    assert not charges_route.called


@respx.mock
async def test_stripe_full_consent_reaches_gated_rungs_and_is_proven() -> None:
    respx.get("https://api.stripe.com/v1/balance").mock(
        return_value=httpx.Response(200, json={"object": "balance"})
    )
    respx.get("https://api.stripe.com/v1/products").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get("https://api.stripe.com/v1/balance_transactions").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get("https://api.stripe.com/v1/account").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "acct_123",
                "country": "US",
                "business_type": "company",
                "charges_enabled": True,
                "email": "owner@victim.example",
            },
        )
    )
    respx.get("https://api.stripe.com/v1/charges").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "ch_1",
                        "receipt_email": "buyer@victim.example",
                        "billing_details": {"name": "Jane Buyer"},
                    }
                ]
            },
        )
    )

    result = await stripe.stripe_ladder(_finding("Stripe", "sk_live_x"), FULL_CONSENT)

    assert result.verdict is Verdict.PROVEN
    account = next(r for r in result.rungs if r.name == "stripe.account.read")
    assert account.success is True
    assert account.blocked is False
    assert account.evidence["account_id"] == "acct_123"
    # PII is summarised, not dumped: the raw email is not stored on evidence.
    assert "email" not in account.evidence
    assert "email" in account.evidence["pii_fields_present"]
    charges = next(r for r in result.rungs if r.name == "stripe.charges.list")
    assert charges.success is True
    assert charges.evidence["charge_count"] == 1
    assert "receipt_email" in charges.evidence["pii_fields_present"]
    assert "receipt_email" not in charges.evidence


@respx.mock
async def test_stripe_dead_key_is_denied_and_skips_gated() -> None:
    respx.get("https://api.stripe.com/v1/balance").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Invalid API Key"}})
    )
    account_route = respx.get("https://api.stripe.com/v1/account").mock(
        return_value=httpx.Response(200, json={"id": "acct_LEAK"})
    )

    result = await stripe.stripe_ladder(_finding("Stripe", "sk_live_dead"), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    [rung] = result.rungs
    assert rung.success is False
    # Dead key never authenticated, so the gated PII reads were not attempted.
    assert not account_route.called


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Stripe") is stripe.stripe_ladder
    assert get_ladder("StripeAccessToken") is stripe.stripe_ladder
    # Detector matching is case-insensitive.
    assert get_ladder("stripe") is stripe.stripe_ladder


def test_stripe_gated_reads_tagged_gated() -> None:
    assert stripe._stripe_account_read.__vtx_tier__ is ProbeTier.GATED
    assert stripe._stripe_charges_list.__vtx_tier__ is ProbeTier.GATED
