"""Tests for the Intercom capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (me -> list-admins) to VALID, using Bearer
  auth pinned to ``Intercom-Version: 2.11``;
* a dead token (401) yields DENIED and stops after the identity rung;
* the GATED contacts read is blocked (no network) without consent, and WITH full
  consent it FIRES a live read -> PROVEN with PII summarised, not dumped;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import intercom
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# Intercom tokens are opaque base64-ish strings; random padding, not real.
FAKE_KEY = "dG9r" + "OkVYQU1QTEVfRkFLRV9LRVlfTk9UX1JFQUwwMA=="


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Intercom", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await intercom.intercom_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_two_safe_rungs() -> None:
    me = respx.get("https://api.intercom.io/me").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "admin-1",
                "email": "leak@victim.example",
                "name": "Leaky Bot",
                "app": {"id_code": "abc123", "name": "Acme Workspace"},
            },
        )
    )
    admins = respx.get("https://api.intercom.io/admins").mock(
        return_value=httpx.Response(
            200,
            json={"admins": [{"email": "a@x"}, {"email": "b@x"}]},
        )
    )

    result = await intercom.intercom_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "intercom"
    assert result.verdict is Verdict.VALID
    assert me.called
    assert admins.called

    req = me.calls.last.request
    assert req.url.host == "api.intercom.io"
    assert req.url.path == "/me"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert req.headers["Intercom-Version"] == "2.11"

    identity = result.rungs[0]
    assert identity.name == "intercom.me"
    assert identity.evidence["admin_id"] == "admin-1"
    assert identity.evidence["app_name"] == "Acme Workspace"

    admin_rung = result.rungs[1]
    assert admin_rung.name == "intercom.list-admins"
    assert admin_rung.evidence["admin_count"] == 2


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    me = respx.get("https://api.intercom.io/me").mock(
        return_value=httpx.Response(401, json={"type": "error.list"})
    )
    admins = respx.get("https://api.intercom.io/admins").mock(
        return_value=httpx.Response(200, json={"admins": []})
    )

    result = await intercom.intercom_ladder(_finding(raw="dead-token"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["intercom.me"]
    assert me.called
    assert not admins.called


@respx.mock
async def test_gated_contacts_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.intercom.io/me").mock(
        return_value=httpx.Response(200, json={"id": "admin-1", "app": {}})
    )
    respx.get("https://api.intercom.io/admins").mock(
        return_value=httpx.Response(200, json={"admins": []})
    )
    contacts_route = respx.get(url__regex=r"https://api\.intercom\.io/contacts.*").mock(
        return_value=httpx.Response(200, json={"data": [{"email": "leak@x"}], "total_count": 1})
    )

    result = await intercom.intercom_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    gated = next(r for r in result.rungs if r.name == "intercom.list-contacts")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert not contacts_route.called


@respx.mock
async def test_full_consent_fires_gated_read_to_proven_pii_summarised() -> None:
    respx.get("https://api.intercom.io/me").mock(
        return_value=httpx.Response(200, json={"id": "admin-1", "app": {}})
    )
    respx.get("https://api.intercom.io/admins").mock(
        return_value=httpx.Response(200, json={"admins": []})
    )
    contacts_route = respx.get(url__regex=r"https://api\.intercom\.io/contacts.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 4200,
                "data": [
                    {
                        "name": "Jane Buyer",
                        "email": "jane@victim.example",
                        "phone": "+15551234567",
                        "location": {"city": "NYC"},
                    }
                ],
            },
        )
    )

    result = await intercom.intercom_ladder(_finding(), FULL_CONSENT)

    assert contacts_route.called
    assert result.verdict is Verdict.PROVEN
    gated = next(r for r in result.rungs if r.name == "intercom.list-contacts")
    assert gated.blocked is False
    assert gated.success is True
    assert gated.evidence["total_count"] == 4200
    assert gated.evidence["sample_count"] == 1
    # PII is summarised (which fields present), values are never stored.
    assert gated.evidence["pii_fields_present"] == ["email", "location", "name", "phone"]
    assert "jane@victim.example" not in repr(gated.evidence)


@respx.mock
async def test_gated_probe_raises_without_consent() -> None:
    with pytest.raises(GatedProbeBlocked):
        await intercom._intercom_list_contacts(SAFE_CONSENT, FAKE_KEY)


def test_gated_probe_tagged_gated() -> None:
    assert intercom._intercom_list_contacts.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.intercom.io/me").mock(
        return_value=httpx.Response(200, json={"id": "admin-1", "app": {}})
    )
    respx.get("https://api.intercom.io/admins").mock(
        return_value=httpx.Response(200, json={"admins": []})
    )
    result = await intercom.intercom_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Intercom") is intercom.intercom_ladder
    assert get_ladder("intercom") is intercom.intercom_ladder
