"""Tests for the DigitalOcean capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs the SAFE account rung (whoami) to VALID, and lists droplets;
* a dead token (401) yields DENIED and stops after the account rung;
* the GATED create-droplet rung is blocked (no network) without consent, and WITH
  consent it stays a MANUAL safe-curl that never fires a billable POST;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.

Note: the create-droplet safe curl keeps the secret as ``$DO_TOKEN`` (a shell
variable), not the literal ``$KEY``.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import digitalocean
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# dop_v1_<64 hex>; random padding, not a real token.
FAKE_KEY = "dop_v1_" + "deadbeef" * 8


def _finding(detector: str = "DigitalOceanV2", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await digitalocean.digitalocean_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_safe_rungs() -> None:
    account = respx.get("https://api.digitalocean.com/v2/account").mock(
        return_value=httpx.Response(
            200,
            json={
                "account": {
                    "email": "leak@victim.example",
                    "uuid": "acc-uuid-1",
                    "status": "active",
                    "droplet_limit": 25,
                    "email_verified": True,
                }
            },
        )
    )
    droplets = respx.get("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(
            200,
            json={
                "droplets": [
                    {"name": "web-1", "region": {"slug": "nyc3"}},
                    {"name": "web-2", "region": {"slug": "sfo3"}},
                ]
            },
        )
    )

    result = await digitalocean.digitalocean_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "digitalocean"
    assert result.verdict is Verdict.VALID
    assert account.called
    assert droplets.called

    req = account.calls.last.request
    assert req.url.host == "api.digitalocean.com"
    assert req.url.path == "/v2/account"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"

    acct = result.rungs[0]
    assert acct.name == "account"
    assert acct.evidence["email"] == "leak@victim.example"
    assert acct.evidence["account_status"] == "active"

    drops = result.rungs[1]
    assert drops.name == "list-droplets"
    assert drops.evidence["droplet_count"] == 2
    assert drops.evidence["regions"] == ["nyc3", "sfo3"]


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    account = respx.get("https://api.digitalocean.com/v2/account").mock(
        return_value=httpx.Response(401, json={"id": "unauthorized"})
    )
    droplets = respx.get("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(200, json={"droplets": []})
    )

    result = await digitalocean.digitalocean_ladder(_finding(raw="dop_v1_dead"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["account"]
    assert account.called
    assert not droplets.called


@respx.mock
async def test_gated_create_droplet_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.digitalocean.com/v2/account").mock(
        return_value=httpx.Response(200, json={"account": {"email": "x@y", "status": "active"}})
    )
    respx.get("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(
            200, json={"droplets": [{"name": "a", "region": {"slug": "nyc3"}}]}
        )
    )
    # A POST to provision a droplet must never be issued without consent.
    create_route = respx.post("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(202, json={"droplet": {"id": "leaked"}})
    )

    result = await digitalocean.digitalocean_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID
    gated = next(r for r in result.rungs if r.name == "create-droplet")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$DO_TOKEN" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert not create_route.called


@respx.mock
async def test_gated_create_droplet_with_consent_is_manual_no_post() -> None:
    respx.get("https://api.digitalocean.com/v2/account").mock(
        return_value=httpx.Response(200, json={"account": {"email": "x@y", "status": "active"}})
    )
    respx.get("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(200, json={"droplets": []})
    )
    create_route = respx.post("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(202, json={"droplet": {"id": "leaked"}})
    )

    result = await digitalocean.digitalocean_ladder(_finding(), FULL_CONSENT)

    gated = next(r for r in result.rungs if r.name == "create-droplet")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert gated.evidence["success_status"] == 202
    # Manual: never fires the billable POST even under full consent.
    assert not create_route.called
    assert result.verdict is Verdict.VALID


def test_gated_probe_tagged_gated() -> None:
    assert digitalocean._do_create_droplet.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.digitalocean.com/v2/account").mock(
        return_value=httpx.Response(200, json={"account": {"email": "x@y", "status": "active"}})
    )
    respx.get("https://api.digitalocean.com/v2/droplets").mock(
        return_value=httpx.Response(200, json={"droplets": []})
    )
    result = await digitalocean.digitalocean_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("DigitalOceanV2") is digitalocean.digitalocean_ladder
    assert get_ladder("DigitalOceanToken") is digitalocean.digitalocean_ladder
    assert get_ladder("digitaloceanv2") is digitalocean.digitalocean_ladder
