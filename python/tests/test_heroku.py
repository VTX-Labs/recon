"""Tests for the Heroku Platform API capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs two SAFE rungs (/account -> /apps) to VALID, sent with the
  bearer key AND the Heroku versioned Accept header;
* a dead key (401) yields DENIED and stops after /account;
* the GATED config-vars dump is structurally blocked without consent (recorded
  ``blocked``, NO network call) and stays a MANUAL safe-curl note even WITH
  consent (its URL needs an APP_ID the engine cannot fill);
* a no-scope consent raises ScopeRequired;
* the raw key is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import heroku
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "HRKU" + "-00000000-0000-0000-0000-000000000000"


def _finding(detector: str = "Heroku", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await heroku.heroku_ladder(_finding(), Consent.denied())


@respx.mock
async def test_heroku_valid_key_climbs_safe_rungs() -> None:
    account = respx.get("https://api.heroku.com/account").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "acc_1",
                "email": "owner@victim.example",
                "name": "Owner",
                "two_factor_authentication": True,
            },
        )
    )
    respx.get("https://api.heroku.com/apps").mock(
        return_value=httpx.Response(200, json=[{"name": "victim-prod"}, {"name": "victim-staging"}])
    )

    result = await heroku.heroku_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "heroku"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["account", "list-apps"]
    assert all(r.success for r in safe)
    req = account.calls.last.request
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert req.headers["Accept"] == "application/vnd.heroku+json; version=3"
    apps = next(r for r in result.rungs if r.name == "list-apps")
    assert apps.evidence["app_count"] == 2


@respx.mock
async def test_heroku_dead_key_is_denied_and_stops_early() -> None:
    account = respx.get("https://api.heroku.com/account").mock(
        return_value=httpx.Response(401, json={"id": "unauthorized"})
    )
    apps = respx.get("https://api.heroku.com/apps").mock(return_value=httpx.Response(200, json=[]))

    result = await heroku.heroku_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["account"]
    assert account.called
    assert not apps.called


@respx.mock
async def test_heroku_gated_config_vars_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.heroku.com/account").mock(
        return_value=httpx.Response(200, json={"id": "acc_1", "email": "o@x.example"})
    )
    respx.get("https://api.heroku.com/apps").mock(
        return_value=httpx.Response(200, json=[{"name": "victim-prod"}])
    )
    cfg_route = respx.get("https://api.heroku.com/apps/APP_ID/config-vars").mock(
        return_value=httpx.Response(200, json={"DATABASE_URL": "postgres://LEAK"})
    )

    result = await heroku.heroku_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    cfg = next(r for r in result.rungs if r.name == "read-config-vars")
    assert cfg.tier is ProbeTier.GATED
    assert cfg.blocked is True
    assert cfg.success is False
    assert cfg.evidence["manual"] is True
    assert "$KEY" in cfg.evidence["safe_curl"]
    assert FAKE_KEY not in cfg.evidence["safe_curl"]
    assert not cfg_route.called


@respx.mock
async def test_heroku_gated_config_vars_with_consent_stays_manual_no_call() -> None:
    respx.get("https://api.heroku.com/account").mock(
        return_value=httpx.Response(200, json={"id": "acc_1", "email": "o@x.example"})
    )
    respx.get("https://api.heroku.com/apps").mock(
        return_value=httpx.Response(200, json=[{"name": "victim-prod"}])
    )
    cfg_route = respx.get("https://api.heroku.com/apps/APP_ID/config-vars").mock(
        return_value=httpx.Response(200, json={"DATABASE_URL": "postgres://LEAK"})
    )

    result = await heroku.heroku_ladder(_finding(), FULL_CONSENT)

    # The gated rung is MANUAL (needs APP_ID), so even with consent no live call.
    assert result.verdict is Verdict.VALID
    cfg = next(r for r in result.rungs if r.name == "read-config-vars")
    assert cfg.blocked is False
    assert cfg.success is False
    assert cfg.evidence["manual"] is True
    assert not cfg_route.called


async def test_heroku_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await heroku._heroku_read_config_vars(SAFE_CONSENT, FAKE_KEY)
    assert heroku._heroku_read_config_vars.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_heroku_result_is_redacted() -> None:
    respx.get("https://api.heroku.com/account").mock(
        return_value=httpx.Response(200, json={"id": "acc_1", "email": "o@x.example"})
    )
    respx.get("https://api.heroku.com/apps").mock(return_value=httpx.Response(200, json=[]))

    result = await heroku.heroku_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Heroku") is heroku.heroku_ladder
    assert get_ladder("heroku") is heroku.heroku_ladder
