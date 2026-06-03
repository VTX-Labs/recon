"""Tests for the Airtable capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid PAT climbs two SAFE rungs (whoami -> list-bases) to VALID, with parsed
  identity/scopes/base evidence;
* a dead PAT (401) yields DENIED and stops after the identity rung;
* the GATED record read is MANUAL: blocked (no network) without consent, and
  WITH consent it still only renders a ``$KEY`` safe curl (never a live call);
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import airtable
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# Realistic shape: pat<14>.<64 hex>; random padding, not a real key.
FAKE_KEY = "pat" + "EXAMPLEFAKEKEY" + "." + "deadbeef" * 8


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="AirtablePersonalAccessToken", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await airtable.airtable_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_key_climbs_two_safe_rungs() -> None:
    whoami = respx.get("https://api.airtable.com/v0/meta/whoami").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "usrXXXXXXXXXXXXXX",
                "email": "leak@victim.example",
                "scopes": ["data.records:read", "schema.bases:read"],
            },
        )
    )
    bases = respx.get("https://api.airtable.com/v0/meta/bases").mock(
        return_value=httpx.Response(
            200,
            json={
                "bases": [
                    {"id": "appONE", "name": "Sales", "permissionLevel": "read"},
                    {"id": "appTWO", "name": "Ops", "permissionLevel": "create"},
                ]
            },
        )
    )

    result = await airtable.airtable_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "airtable"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == SCOPE
    assert whoami.called
    assert bases.called

    # Endpoint + auth header assertions on the identity request.
    req = whoami.calls.last.request
    assert req.url.host == "api.airtable.com"
    assert req.url.path == "/v0/meta/whoami"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"

    identity = result.rungs[0]
    assert identity.name == "airtable.whoami"
    assert identity.tier is ProbeTier.SAFE
    assert identity.success is True
    assert identity.evidence["user_id"] == "usrXXXXXXXXXXXXXX"
    assert identity.evidence["scopes"] == ["data.records:read", "schema.bases:read"]

    base_rung = result.rungs[1]
    assert base_rung.name == "airtable.list-bases"
    assert base_rung.evidence["base_count"] == 2
    assert base_rung.evidence["base_ids"] == ["appONE", "appTWO"]


@respx.mock
async def test_dead_key_is_denied_and_stops_early() -> None:
    whoami = respx.get("https://api.airtable.com/v0/meta/whoami").mock(
        return_value=httpx.Response(401, json={"error": "INVALID_AUTHORIZATION"})
    )
    bases = respx.get("https://api.airtable.com/v0/meta/bases").mock(
        return_value=httpx.Response(200, json={"bases": []})
    )

    result = await airtable.airtable_ladder(_finding("patDEADDEADDEAD.deadbeef"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["airtable.whoami"]
    assert whoami.called
    assert not bases.called


@respx.mock
async def test_gated_record_read_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.airtable.com/v0/meta/whoami").mock(
        return_value=httpx.Response(200, json={"id": "usr1", "scopes": []})
    )
    respx.get("https://api.airtable.com/v0/meta/bases").mock(
        return_value=httpx.Response(200, json={"bases": [{"id": "appONE", "name": "B"}]})
    )

    result = await airtable.airtable_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    gated = next(r for r in result.rungs if r.name == "airtable.list-base-records")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]


@respx.mock
async def test_gated_record_read_with_consent_is_manual_safe_curl() -> None:
    respx.get("https://api.airtable.com/v0/meta/whoami").mock(
        return_value=httpx.Response(200, json={"id": "usr1", "scopes": []})
    )
    respx.get("https://api.airtable.com/v0/meta/bases").mock(
        return_value=httpx.Response(200, json={"bases": []})
    )

    result = await airtable.airtable_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "airtable.list-base-records")
    # Even WITH consent the manual rung never fires a live call (no network mock
    # for the record-read URL exists, so any call would error).
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$KEY" in gated.evidence["safe_curl"]
    # Manual rung never succeeds -> verdict stays VALID, not PROVEN.
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert airtable._airtable_list_base_records.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.airtable.com/v0/meta/whoami").mock(
        return_value=httpx.Response(200, json={"id": "usr1", "scopes": []})
    )
    respx.get("https://api.airtable.com/v0/meta/bases").mock(
        return_value=httpx.Response(200, json={"bases": []})
    )
    result = await airtable.airtable_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("AirtablePersonalAccessToken") is airtable.airtable_ladder
    assert get_ladder("airtablepersonalaccesstoken") is airtable.airtable_ladder
