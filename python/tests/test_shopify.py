"""Tests for the Shopify capability ladder.

Shopify is a FULLY MANUAL provider: every endpoint lives on the ``{shop}`` host
that is NOT in the raw token, so NO rung ever issues a live call. respx proves no
network request leaves the process. The tests assert:

* the ladder makes zero network calls and lands on DENIED;
* the two SAFE rungs render ``$KEY`` safe curls (raw token never present);
* the GATED list-customers rung is blocked without consent, and stays a MANUAL
  ``$KEY`` safe curl WITH consent — no live call either way;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import shopify
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# shpat_<32 hex>; random padding, not a real token.
FAKE_KEY = "shpat_" + "deadbeef" * 4


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="ShopifyToken", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await shopify.shopify_ladder(_finding(), Consent.denied())


@respx.mock(assert_all_called=False)
async def test_safe_rungs_manual_no_network_gated_blocked() -> None:
    # No routes registered: any live request would raise, proving no network call.
    result = await shopify.shopify_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "shopify"
    assert result.verdict is Verdict.DENIED  # all manual -> nothing succeeds
    assert len(respx.calls) == 0

    assert [r.name for r in result.rungs] == ["access-scopes", "shop-info", "list-customers"]

    for name in ("access-scopes", "shop-info"):
        rung = next(r for r in result.rungs if r.name == name)
        assert rung.tier is ProbeTier.SAFE
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
        assert FAKE_KEY not in rung.evidence["safe_curl"]

    # GATED rung is blocked without consent.
    gated = next(r for r in result.rungs if r.name == "list-customers")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert "$KEY" in gated.evidence["safe_curl"]


@respx.mock(assert_all_called=False)
async def test_gated_customers_with_consent_is_manual_no_network() -> None:
    result = await shopify.shopify_ladder(_finding(), FULL_CONSENT)

    assert len(respx.calls) == 0
    assert result.verdict is Verdict.DENIED
    gated = next(r for r in result.rungs if r.name == "list-customers")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]


def test_gated_probe_tagged_gated() -> None:
    assert shopify._shopify_list_customers.__vtx_tier__ is ProbeTier.GATED


async def test_no_raw_secret_in_public_result() -> None:
    result = await shopify.shopify_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("ShopifyToken") is shopify.shopify_ladder
    assert get_ladder("Shopify") is shopify.shopify_ladder
    assert get_ladder("shopify") is shopify.shopify_ladder
