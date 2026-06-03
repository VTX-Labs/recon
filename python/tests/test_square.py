"""Tests for the Square capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs three SAFE rungs (locations -> merchant -> team) to VALID,
  with the ``Authorization: Bearer`` + pinned ``Square-Version`` headers and
  parsed evidence;
* a dead token (401) yields DENIED and stops after the locations rung;
* the GATED+MANUAL ``create-payment`` rung is blocked (no network) without
  consent, and stays a ``$KEY`` safe curl that never fires a live charge even
  WITH consent;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import square
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "EAAA" + "EXAMPLEFAKEKEYNOTREAL00000000000000"

_LOCATIONS = "https://connect.squareup.com/v2/locations"
_MERCHANT = "https://connect.squareup.com/v2/merchants/me"
_TEAM = "https://connect.squareup.com/v2/team-members/search"
_PAYMENTS = "https://connect.squareup.com/v2/payments"


def _finding(detector: str = "Square", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await square.square_ladder(_finding(), Consent.denied())


@respx.mock
async def test_square_valid_token_climbs_three_safe_rungs() -> None:
    locations = respx.get(_LOCATIONS).mock(
        return_value=httpx.Response(
            200,
            json={"locations": [{"id": "L1", "name": "Main St"}, {"id": "L2", "name": "2nd Ave"}]},
        )
    )
    respx.get(_MERCHANT).mock(
        return_value=httpx.Response(
            200,
            json={
                "merchant": {
                    "id": "M123",
                    "business_name": "Acme Coffee",
                    "country": "US",
                    "currency": "USD",
                }
            },
        )
    )
    respx.post(_TEAM).mock(
        return_value=httpx.Response(
            200,
            json={
                "team_members": [{"status": "ACTIVE"}, {"status": "ACTIVE"}, {"status": "INACTIVE"}]
            },
        )
    )
    payments_route = respx.post(_PAYMENTS).mock(
        return_value=httpx.Response(200, json={"payment": {"id": "LEAK"}})
    )

    result = await square.square_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "square"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == [
        "list-locations",
        "retrieve-merchant-me",
        "list-team-members",
        "create-payment",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert all(r.success for r in safe)

    req = locations.calls.last.request
    assert req.url.host == "connect.squareup.com"
    assert req.url.path == "/v2/locations"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert req.headers["Square-Version"] == "2024-01-18"

    locs = result.rungs[0]
    assert locs.evidence["location_count"] == 2
    assert locs.evidence["location_names"] == ["Main St", "2nd Ave"]
    merchant = result.rungs[1]
    assert merchant.evidence["merchant_id"] == "M123"
    assert merchant.evidence["currency"] == "USD"
    team = result.rungs[2]
    assert team.evidence["team_member_count"] == 3
    assert team.evidence["active_count"] == 2

    # GATED+MANUAL payment: blocked without consent, no charge fired.
    payment = result.rungs[3]
    assert payment.tier is ProbeTier.GATED
    assert payment.blocked is True
    assert payment.success is False
    assert "$KEY" in payment.evidence["safe_curl"]
    assert FAKE_KEY not in payment.evidence["safe_curl"]
    assert not payments_route.called


@respx.mock
async def test_square_dead_token_is_denied_and_stops_early() -> None:
    locations = respx.get(_LOCATIONS).mock(
        return_value=httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED"}]})
    )
    merchant = respx.get(_MERCHANT).mock(
        return_value=httpx.Response(200, json={"merchant": {"id": "LEAK"}})
    )

    result = await square.square_ladder(_finding(raw="EAAAdeadtoken"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["list-locations"]
    assert locations.called
    assert not merchant.called


@respx.mock
async def test_square_gated_payment_with_consent_stays_manual_no_charge() -> None:
    respx.get(_LOCATIONS).mock(return_value=httpx.Response(200, json={"locations": []}))
    respx.get(_MERCHANT).mock(return_value=httpx.Response(200, json={"merchant": {}}))
    respx.post(_TEAM).mock(return_value=httpx.Response(200, json={"team_members": []}))
    payments_route = respx.post(_PAYMENTS).mock(
        return_value=httpx.Response(200, json={"payment": {"id": "LEAK"}})
    )

    result = await square.square_ladder(_finding(), FULL_CONSENT)

    # Even with full consent the payment rung is MANUAL: never fires, stays VALID.
    assert result.verdict is Verdict.VALID
    payment = next(r for r in result.rungs if r.name == "create-payment")
    assert payment.blocked is False
    assert payment.success is False
    assert payment.evidence["manual"] is True
    assert payment.evidence["billable"] is True
    assert not payments_route.called


async def test_square_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await square._square_create_payment(SAFE_CONSENT)
    assert square._square_create_payment.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_square_no_raw_secret_in_public_result() -> None:
    respx.get(_LOCATIONS).mock(return_value=httpx.Response(200, json={"locations": []}))
    respx.get(_MERCHANT).mock(return_value=httpx.Response(200, json={"merchant": {}}))
    respx.post(_TEAM).mock(return_value=httpx.Response(200, json={"team_members": []}))
    result = await square.square_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Square") is square.square_ladder
    assert get_ladder("square") is square.square_ladder
