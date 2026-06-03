"""Tests for the Netlify capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (/user -> /sites) to VALID with the bearer
  header and real JSON evidence;
* a dead token (401) yields DENIED and stops after /user;
* the GATED env-var read is structurally blocked without consent (recorded
  ``blocked``, NO network call) and stays a MANUAL safe-curl note even WITH
  consent (its URL needs an ACCOUNT_ID the engine cannot fill);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import netlify
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "nfp" + "_EXAMPLEFAKEKEYNOTREAL000000000000000"


def _finding(detector: str = "Netlify", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await netlify.netlify_ladder(_finding(), Consent.denied())


@respx.mock
async def test_netlify_valid_token_climbs_safe_rungs() -> None:
    user = respx.get("https://api.netlify.com/api/v1/user").mock(
        return_value=httpx.Response(
            200, json={"id": "u1", "email": "v@x.example", "full_name": "Victim"}
        )
    )
    respx.get("https://api.netlify.com/api/v1/sites").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name": "victim", "custom_domain": "victim.example", "account_id": "acc1"},
            ],
        )
    )

    result = await netlify.netlify_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "netlify"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["netlify.user", "netlify.list-sites"]
    assert all(r.success for r in safe)
    assert user.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    sites = next(r for r in result.rungs if r.name == "netlify.list-sites")
    assert sites.evidence["site_count"] == 1


@respx.mock
async def test_netlify_dead_token_is_denied_and_stops_early() -> None:
    user = respx.get("https://api.netlify.com/api/v1/user").mock(
        return_value=httpx.Response(401, json={"message": "Unauthorized"})
    )
    sites = respx.get("https://api.netlify.com/api/v1/sites").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await netlify.netlify_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["netlify.user"]
    assert user.called
    assert not sites.called


@respx.mock
async def test_netlify_gated_env_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.netlify.com/api/v1/user").mock(
        return_value=httpx.Response(200, json={"id": "u1", "email": "v@x.example"})
    )
    respx.get("https://api.netlify.com/api/v1/sites").mock(
        return_value=httpx.Response(200, json=[{"name": "victim", "account_id": "acc1"}])
    )
    env_route = respx.get("https://api.netlify.com/api/v1/accounts/ACCOUNT_ID/env").mock(
        return_value=httpx.Response(200, json=[{"key": "SECRET", "value": "LEAK"}])
    )

    result = await netlify.netlify_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    env = next(r for r in result.rungs if r.name == "netlify.read-site-env")
    assert env.tier is ProbeTier.GATED
    assert env.blocked is True
    assert env.success is False
    assert env.evidence["manual"] is True
    assert "$KEY" in env.evidence["safe_curl"]
    assert FAKE_KEY not in env.evidence["safe_curl"]
    assert not env_route.called


@respx.mock
async def test_netlify_gated_env_with_consent_stays_manual_no_call() -> None:
    respx.get("https://api.netlify.com/api/v1/user").mock(
        return_value=httpx.Response(200, json={"id": "u1", "email": "v@x.example"})
    )
    respx.get("https://api.netlify.com/api/v1/sites").mock(
        return_value=httpx.Response(200, json=[{"name": "victim", "account_id": "acc1"}])
    )
    env_route = respx.get("https://api.netlify.com/api/v1/accounts/ACCOUNT_ID/env").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await netlify.netlify_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.VALID
    env = next(r for r in result.rungs if r.name == "netlify.read-site-env")
    assert env.blocked is False
    assert env.success is False
    assert env.evidence["manual"] is True
    assert not env_route.called


async def test_netlify_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await netlify._netlify_read_site_env(SAFE_CONSENT, FAKE_KEY)
    assert netlify._netlify_read_site_env.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_netlify_result_is_redacted() -> None:
    respx.get("https://api.netlify.com/api/v1/user").mock(
        return_value=httpx.Response(200, json={"id": "u1", "email": "v@x.example"})
    )
    respx.get("https://api.netlify.com/api/v1/sites").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await netlify.netlify_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Netlify") is netlify.netlify_ladder
    assert get_ladder("netlify") is netlify.netlify_ladder
