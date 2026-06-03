"""Tests for the Sentry capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs the SAFE ``list-organizations`` rung live (Bearer auth) to
  VALID, then emits a SAFE/MANUAL ``list-org-projects`` note and a GATED/MANUAL
  ``read-project-issues`` note (both needing slugs the engine cannot fill);
* a dead token (401) yields DENIED and stops after list-organizations;
* the GATED issues rung is blocked (no network) without consent and stays a
  manual ``$KEY`` safe curl WITH consent;
* the ladder refuses to run without an authorized scope;
* both SentryToken / SentryOrgToken detectors route here;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import sentry
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "sntryu_" + "deadbeef" * 8

_ORGS = "https://sentry.io/api/0/organizations/"


def _finding(detector: str = "SentryToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await sentry.sentry_ladder(_finding(), Consent.denied())


@respx.mock
async def test_sentry_valid_token_climbs_safe_then_manual_rungs() -> None:
    orgs = respx.get(_ORGS).mock(
        return_value=httpx.Response(200, json=[{"slug": "victim-org"}, {"slug": "victim-eng"}])
    )

    result = await sentry.sentry_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "sentry"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == [
        "list-organizations",
        "list-org-projects",
        "read-project-issues",
    ]

    req = orgs.calls.last.request
    assert req.url.host == "sentry.io"
    assert req.url.path == "/api/0/organizations/"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"

    identity = result.rungs[0]
    assert identity.tier is ProbeTier.SAFE
    assert identity.success is True
    assert identity.evidence["organization_count"] == 2
    assert identity.evidence["organization_slugs_sample"] == ["victim-org", "victim-eng"]

    projects = result.rungs[1]
    assert projects.tier is ProbeTier.SAFE
    assert projects.success is False
    assert projects.evidence["manual"] is True
    assert "$KEY" in projects.evidence["safe_curl"]

    issues = result.rungs[2]
    assert issues.tier is ProbeTier.GATED
    assert issues.blocked is True
    assert issues.success is False
    assert "$KEY" in issues.evidence["safe_curl"]
    assert FAKE_KEY not in issues.evidence["safe_curl"]


@respx.mock
async def test_sentry_dead_token_is_denied_and_stops_early() -> None:
    orgs = respx.get(_ORGS).mock(return_value=httpx.Response(401, json={"detail": "Invalid token"}))

    result = await sentry.sentry_ladder(_finding(raw="sntryu_deadtoken"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["list-organizations"]
    assert orgs.called


@respx.mock
async def test_sentry_gated_issues_with_consent_stays_manual() -> None:
    respx.get(_ORGS).mock(return_value=httpx.Response(200, json=[{"slug": "o"}]))

    result = await sentry.sentry_ladder(_finding(), FULL_CONSENT)

    # Manual gated rung: never fires, verdict stays VALID (no gated success).
    assert result.verdict is Verdict.VALID
    issues = next(r for r in result.rungs if r.name == "read-project-issues")
    assert issues.blocked is False
    assert issues.success is False
    assert issues.evidence["manual"] is True


async def test_sentry_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await sentry.sentry_gated_read_issues(SAFE_CONSENT)
    assert sentry.sentry_gated_read_issues.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_sentry_no_raw_secret_in_public_result() -> None:
    respx.get(_ORGS).mock(return_value=httpx.Response(200, json=[{"slug": "o"}]))
    result = await sentry.sentry_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("SentryToken") is sentry.sentry_ladder
    assert get_ladder("SentryOrgToken") is sentry.sentry_ladder
    assert get_ladder("sentrytoken") is sentry.sentry_ladder
