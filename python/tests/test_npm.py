"""Tests for the npm capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (whoami -> tokens) to VALID with the
  bearer header and real JSON evidence;
* a dead token (401) yields DENIED and stops after whoami;
* the GATED publish rung is structurally blocked without consent (recorded
  ``blocked``, NO network call) and stays a MANUAL safe-curl note even WITH
  consent (its URL needs a package name the engine cannot fill);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import npm
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "npm" + "_EXAMPLEFAKEKEYNOTREAL000000000000000"


def _finding(detector: str = "NpmToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await npm.npm_ladder(_finding(), Consent.denied())


@respx.mock
async def test_npm_valid_token_climbs_safe_rungs() -> None:
    whoami = respx.get("https://registry.npmjs.org/-/whoami").mock(
        return_value=httpx.Response(200, json={"username": "victim"})
    )
    respx.get("https://registry.npmjs.org/-/npm/v1/tokens").mock(
        return_value=httpx.Response(
            200,
            json={
                "objects": [
                    {"readonly": False, "automation": True},
                    {"readonly": True, "automation": False},
                ]
            },
        )
    )

    result = await npm.npm_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "npm"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["npm.whoami", "npm.tokens"]
    assert all(r.success for r in safe)
    assert whoami.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    identity = next(r for r in result.rungs if r.name == "npm.whoami")
    assert identity.evidence["username"] == "victim"
    tokens = next(r for r in result.rungs if r.name == "npm.tokens")
    assert tokens.evidence["token_count"] == 2
    assert tokens.evidence["automation_count"] == 1


@respx.mock
async def test_npm_dead_token_is_denied_and_stops_early() -> None:
    whoami = respx.get("https://registry.npmjs.org/-/whoami").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    tokens = respx.get("https://registry.npmjs.org/-/npm/v1/tokens").mock(
        return_value=httpx.Response(200, json={"objects": []})
    )

    result = await npm.npm_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["npm.whoami"]
    assert whoami.called
    assert not tokens.called


@respx.mock
async def test_npm_gated_publish_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://registry.npmjs.org/-/whoami").mock(
        return_value=httpx.Response(200, json={"username": "victim"})
    )
    respx.get("https://registry.npmjs.org/-/npm/v1/tokens").mock(
        return_value=httpx.Response(200, json={"objects": []})
    )
    publish_route = respx.put("https://registry.npmjs.org/PACKAGE_NAME").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    result = await npm.npm_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    publish = next(r for r in result.rungs if r.name == "npm.publish")
    assert publish.tier is ProbeTier.GATED
    assert publish.blocked is True
    assert publish.success is False
    assert publish.evidence["manual"] is True
    assert "$KEY" in publish.evidence["safe_curl"]
    assert FAKE_KEY not in publish.evidence["safe_curl"]
    assert not publish_route.called


@respx.mock
async def test_npm_gated_publish_with_consent_stays_manual_no_call() -> None:
    respx.get("https://registry.npmjs.org/-/whoami").mock(
        return_value=httpx.Response(200, json={"username": "victim"})
    )
    respx.get("https://registry.npmjs.org/-/npm/v1/tokens").mock(
        return_value=httpx.Response(200, json={"objects": []})
    )
    publish_route = respx.put("https://registry.npmjs.org/PACKAGE_NAME").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    result = await npm.npm_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.VALID
    publish = next(r for r in result.rungs if r.name == "npm.publish")
    assert publish.blocked is False
    assert publish.success is False
    assert publish.evidence["manual"] is True
    assert not publish_route.called


async def test_npm_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await npm.npm_gated_publish(SAFE_CONSENT)
    assert npm.npm_gated_publish.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_npm_result_is_redacted() -> None:
    respx.get("https://registry.npmjs.org/-/whoami").mock(
        return_value=httpx.Response(200, json={"username": "victim"})
    )
    respx.get("https://registry.npmjs.org/-/npm/v1/tokens").mock(
        return_value=httpx.Response(200, json={"objects": []})
    )

    result = await npm.npm_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("NpmToken") is npm.npm_ladder
    assert get_ladder("npmtoken") is npm.npm_ladder
