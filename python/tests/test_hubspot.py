"""Tests for the HubSpot capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE whoami rungs (token-info -> account-info) to
  VALID, with the embedded-token introspection URL and Bearer account-info call,
  and the gated CRM read blocked without consent making NO call;
* a private-app token that 400s on token-info but authenticates on account-info
  still reaches VALID;
* a dead token yields DENIED and never attempts the gated PII read;
* with full consent the GATED ``list-contacts`` PII read runs live -> PROVEN,
  PII summarised (fields present) not dumped;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import hubspot
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "pat-na1-" + "00000000-0000-0000-0000-000000000000"

_ACCOUNT = "https://api.hubapi.com/account-info/v3/details"
_CONTACTS = "https://api.hubapi.com/crm/v3/objects/contacts"


def _token_info_route(status: int, json: dict | None = None):
    return respx.get(url__regex=r"https://api\.hubapi\.com/oauth/v1/access-tokens/.*").mock(
        return_value=httpx.Response(status, json=json or {})
    )


def _finding(detector: str = "HubSpot", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await hubspot.hubspot_ladder(_finding(), Consent.denied())


@respx.mock
async def test_hubspot_valid_token_climbs_safe_rungs_gated_blocked() -> None:
    _token_info_route(
        200,
        {
            "hub_id": 9876,
            "hub_domain": "victim.com",
            "user": "owner@victim.com",
            "scopes": ["crm.objects.contacts.read", "oauth"],
        },
    )
    account = respx.get(_ACCOUNT).mock(
        return_value=httpx.Response(
            200,
            json={"portalId": 9876, "accountType": "STANDARD", "dataHostingLocation": "na1"},
        )
    )
    contacts_route = respx.get(url__regex=rf"{_CONTACTS}.*").mock(
        return_value=httpx.Response(200, json={"results": [{"properties": {"email": "LEAK"}}]})
    )

    result = await hubspot.hubspot_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "hubspot"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == [
        "hubspot.token-info",
        "hubspot.account-info",
        "hubspot.list-contacts",
    ]

    token_info = result.rungs[0]
    assert token_info.tier is ProbeTier.SAFE
    assert token_info.success is True
    assert token_info.evidence["hub_id"] == 9876
    assert token_info.evidence["scopes"] == ["crm.objects.contacts.read", "oauth"]

    req = account.calls.last.request
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert result.rungs[1].evidence["portal_id"] == 9876

    gated = result.rungs[2]
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert not contacts_route.called


@respx.mock
async def test_hubspot_private_app_token_info_400_account_info_ok_is_valid() -> None:
    _token_info_route(400, {"message": "private-app token"})
    respx.get(_ACCOUNT).mock(
        return_value=httpx.Response(200, json={"portalId": 555, "accountType": "DEVELOPER_TEST"})
    )

    result = await hubspot.hubspot_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    token_info = result.rungs[0]
    assert token_info.success is False
    account_info = result.rungs[1]
    assert account_info.success is True
    # account-info authenticated, so the gated rung is still reached (blocked).
    assert any(r.name == "hubspot.list-contacts" for r in result.rungs)


@respx.mock
async def test_hubspot_dead_token_is_denied_and_skips_gated() -> None:
    _token_info_route(401, {"message": "unauthorized"})
    respx.get(_ACCOUNT).mock(return_value=httpx.Response(401, json={"message": "unauthorized"}))
    contacts_route = respx.get(url__regex=rf"{_CONTACTS}.*").mock(
        return_value=httpx.Response(200, json={"results": [{"properties": {"email": "LEAK"}}]})
    )

    result = await hubspot.hubspot_ladder(_finding(raw="pat-na1-deadtoken"), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["hubspot.token-info", "hubspot.account-info"]
    assert not contacts_route.called


@respx.mock
async def test_hubspot_full_consent_reads_contacts_proven_pii_summarised() -> None:
    _token_info_route(200, {"hub_id": 1, "user": "o@v.com", "scopes": []})
    respx.get(_ACCOUNT).mock(return_value=httpx.Response(200, json={"portalId": 1}))
    respx.get(url__regex=rf"{_CONTACTS}.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "properties": {
                            "firstname": "Jane",
                            "lastname": "Buyer",
                            "email": "jane@victim.example",
                            "phone": "+1-555-0100",
                        }
                    }
                ]
            },
        )
    )

    result = await hubspot.hubspot_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.PROVEN
    contacts = next(r for r in result.rungs if r.name == "hubspot.list-contacts")
    assert contacts.success is True
    assert contacts.blocked is False
    assert contacts.evidence["sample_count"] == 1
    # PII is summarised, not dumped: field names present, no raw values stored.
    assert contacts.evidence["pii_fields_present"] == ["email", "firstname", "lastname", "phone"]
    assert "jane@victim.example" not in repr(contacts.evidence)


@respx.mock
async def test_hubspot_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    contacts_route = respx.get(url__regex=rf"{_CONTACTS}.*").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    with pytest.raises(GatedProbeBlocked):
        await hubspot._hubspot_list_contacts(SAFE_CONSENT, FAKE_KEY)
    assert not contacts_route.called
    assert hubspot._hubspot_list_contacts.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_hubspot_no_raw_secret_in_public_result() -> None:
    _token_info_route(200, {"hub_id": 1, "user": "o", "scopes": []})
    respx.get(_ACCOUNT).mock(return_value=httpx.Response(200, json={"portalId": 1}))
    result = await hubspot.hubspot_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("HubSpot") is hubspot.hubspot_ladder
    assert get_ladder("hubspot") is hubspot.hubspot_ladder
