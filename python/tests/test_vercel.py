"""Tests for the Vercel capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (/v2/user -> /v9/projects) to VALID with
  the bearer header and real JSON evidence;
* a dead token (403) yields DENIED and stops after /v2/user;
* the GATED decrypted-env read is structurally blocked without consent (recorded
  ``blocked``, NO network call) and stays a MANUAL safe-curl note even WITH
  consent (its URL needs a PROJECT_ID the engine cannot fill);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import vercel
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "A1b2C3d4E5f6G7h8I9j0K1l2"


def _finding(detector: str = "Vercel", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await vercel.vercel_ladder(_finding(), Consent.denied())


@respx.mock
async def test_vercel_valid_token_climbs_safe_rungs() -> None:
    user = respx.get("https://api.vercel.com/v2/user").mock(
        return_value=httpx.Response(
            200, json={"user": {"id": "u1", "username": "victim", "email": "v@x.example"}}
        )
    )
    respx.get("https://api.vercel.com/v9/projects").mock(
        return_value=httpx.Response(
            200,
            json={"projects": [{"id": "prj_1", "name": "victim-app"}], "pagination": {}},
        )
    )

    result = await vercel.vercel_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "vercel"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["user", "list-projects"]
    assert all(r.success for r in safe)
    assert user.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    identity = next(r for r in result.rungs if r.name == "user")
    assert identity.evidence["username"] == "victim"
    projects = next(r for r in result.rungs if r.name == "list-projects")
    assert projects.evidence["project_count"] == 1


@respx.mock
async def test_vercel_dead_token_is_denied_and_stops_early() -> None:
    user = respx.get("https://api.vercel.com/v2/user").mock(
        return_value=httpx.Response(403, json={"error": {"code": "forbidden"}})
    )
    projects = respx.get("https://api.vercel.com/v9/projects").mock(
        return_value=httpx.Response(200, json={"projects": []})
    )

    result = await vercel.vercel_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["user"]
    assert user.called
    assert not projects.called


@respx.mock
async def test_vercel_gated_env_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://api.vercel.com/v2/user").mock(
        return_value=httpx.Response(200, json={"user": {"id": "u1", "username": "v"}})
    )
    respx.get("https://api.vercel.com/v9/projects").mock(
        return_value=httpx.Response(200, json={"projects": [{"id": "prj_1", "name": "app"}]})
    )
    env_route = respx.get("https://api.vercel.com/v9/projects/PROJECT_ID/env").mock(
        return_value=httpx.Response(200, json={"envs": [{"key": "SECRET", "value": "LEAK"}]})
    )

    result = await vercel.vercel_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    env = next(r for r in result.rungs if r.name == "read-project-env")
    assert env.tier is ProbeTier.GATED
    assert env.blocked is True
    assert env.success is False
    assert env.evidence["manual"] is True
    assert "$KEY" in env.evidence["safe_curl"]
    assert FAKE_KEY not in env.evidence["safe_curl"]
    assert not env_route.called


@respx.mock
async def test_vercel_gated_env_with_consent_stays_manual_no_call() -> None:
    respx.get("https://api.vercel.com/v2/user").mock(
        return_value=httpx.Response(200, json={"user": {"id": "u1", "username": "v"}})
    )
    respx.get("https://api.vercel.com/v9/projects").mock(
        return_value=httpx.Response(200, json={"projects": [{"id": "prj_1", "name": "app"}]})
    )
    env_route = respx.get("https://api.vercel.com/v9/projects/PROJECT_ID/env").mock(
        return_value=httpx.Response(200, json={"envs": []})
    )

    result = await vercel.vercel_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.VALID
    env = next(r for r in result.rungs if r.name == "read-project-env")
    assert env.blocked is False
    assert env.success is False
    assert env.evidence["manual"] is True
    assert not env_route.called


async def test_vercel_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await vercel._vercel_read_project_env(SAFE_CONSENT)
    assert vercel._vercel_read_project_env.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_vercel_result_is_redacted() -> None:
    respx.get("https://api.vercel.com/v2/user").mock(
        return_value=httpx.Response(200, json={"user": {"id": "u1", "username": "v"}})
    )
    respx.get("https://api.vercel.com/v9/projects").mock(
        return_value=httpx.Response(200, json={"projects": []})
    )

    result = await vercel.vercel_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Vercel") is vercel.vercel_ladder
    assert get_ladder("vercel") is vercel.vercel_ladder
