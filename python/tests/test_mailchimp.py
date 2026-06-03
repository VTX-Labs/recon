"""Tests for the Mailchimp capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key (with a ``-us21`` datacenter suffix) climbs two SAFE rungs
  (api-root -> list-audiences) live against the derived ``{dc}`` host, using HTTP
  Basic auth, to VALID;
* a key with no datacenter suffix cannot address the API -> DENIED, no network;
* a dead key (401) yields DENIED and stops after api-root;
* the GATED+MANUAL ``add-list-member`` rung is blocked (no network) without
  consent and stays a ``$KEY`` safe curl WITH consent;
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import mailchimp
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

DC = "us21"
FAKE_KEY = "deadbeefdeadbeefdeadbeefdeadbeef-" + DC

_ROOT = f"https://{DC}.api.mailchimp.com/3.0/"
_LISTS = f"https://{DC}.api.mailchimp.com/3.0/lists"
_MEMBERS_RE = rf"https://{DC}\.api\.mailchimp\.com/3\.0/lists/.*/members"


def _finding(detector: str = "Mailchimp", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await mailchimp.mailchimp_ladder(_finding(), Consent.denied())


@respx.mock
async def test_mailchimp_valid_key_climbs_two_safe_rungs() -> None:
    root = respx.get(_ROOT).mock(
        return_value=httpx.Response(
            200,
            json={
                "account_id": "acc_1",
                "account_name": "Acme",
                "login_id": "log_1",
                "email": "owner@victim.example",
                "total_subscribers": 4200,
            },
        )
    )
    respx.get(_LISTS).mock(
        return_value=httpx.Response(
            200,
            json={"lists": [{"name": "Newsletter"}, {"name": "Promos"}], "total_items": 2},
        )
    )
    members_route = respx.post(url__regex=_MEMBERS_RE).mock(
        return_value=httpx.Response(200, json={"id": "LEAK"})
    )

    result = await mailchimp.mailchimp_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "mailchimp"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == ["api-root", "list-audiences", "add-list-member"]

    req = root.calls.last.request
    assert req.url.host == f"{DC}.api.mailchimp.com"
    assert req.headers["Authorization"] == f"Basic {FAKE_KEY}"

    identity = result.rungs[0]
    assert identity.tier is ProbeTier.SAFE
    assert identity.success is True
    assert identity.evidence["datacenter"] == DC
    assert identity.evidence["account_id"] == "acc_1"
    audiences = result.rungs[1]
    assert audiences.evidence["total_items"] == 2
    assert audiences.evidence["audiences_sample"] == ["Newsletter", "Promos"]

    member = result.rungs[2]
    assert member.tier is ProbeTier.GATED
    assert member.blocked is True
    assert member.success is False
    assert "$KEY" in member.evidence["safe_curl"]
    assert FAKE_KEY not in member.evidence["safe_curl"]
    assert not members_route.called


@respx.mock
async def test_mailchimp_key_without_datacenter_suffix_is_denied() -> None:
    # No "-us<NN>" suffix: the ladder cannot address any Marketing endpoint.
    result = await mailchimp.mailchimp_ladder(
        _finding(raw="0123456789abcdef0123456789abcdef"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["api-root"]
    assert result.rungs[0].evidence["datacenter"] is None


@respx.mock
async def test_mailchimp_dead_key_is_denied_and_stops_early() -> None:
    root = respx.get(_ROOT).mock(
        return_value=httpx.Response(401, json={"title": "API Key Invalid"})
    )
    lists = respx.get(_LISTS).mock(return_value=httpx.Response(200, json={"lists": []}))

    result = await mailchimp.mailchimp_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["api-root"]
    assert root.called
    assert not lists.called


@respx.mock
async def test_mailchimp_gated_member_with_consent_stays_manual() -> None:
    respx.get(_ROOT).mock(return_value=httpx.Response(200, json={"account_id": "a"}))
    respx.get(_LISTS).mock(return_value=httpx.Response(200, json={"lists": []}))
    members_route = respx.post(url__regex=_MEMBERS_RE).mock(
        return_value=httpx.Response(200, json={"id": "LEAK"})
    )

    result = await mailchimp.mailchimp_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.VALID
    member = next(r for r in result.rungs if r.name == "add-list-member")
    assert member.blocked is False
    assert member.success is False
    assert member.evidence["manual"] is True
    assert not members_route.called


async def test_mailchimp_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await mailchimp.mailchimp_gated_add_member(SAFE_CONSENT, DC)
    assert mailchimp.mailchimp_gated_add_member.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_mailchimp_no_raw_secret_in_public_result() -> None:
    respx.get(_ROOT).mock(return_value=httpx.Response(200, json={"account_id": "a"}))
    respx.get(_LISTS).mock(return_value=httpx.Response(200, json={"lists": []}))
    result = await mailchimp.mailchimp_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Mailchimp") is mailchimp.mailchimp_ladder
    assert get_ladder("mailchimp") is mailchimp.mailchimp_ladder
