"""Tests for the Google AI / Gemini capability ladder.

ALL HTTP is mocked with respx — no real Google API is ever contacted, and no
real key is used. We assert three behaviours required by the spec:

  1. A *valid* key climbs the SAFE rungs and the ladder reports VALID.
  2. A *dead* key (every rung 4xx) reports DENIED.
  3. A GATED rung is BLOCKED without consent (no network call is issued),
     and reachable only with full consent (--prove + authorized scope).

We also cover the read-only HTTP-referer bypass attempt and the structural
guarantee that the safe ladder cannot reach a gated endpoint.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import get_ladder
from vtx_recon.providers.google import (
    GATED_RUNGS,
    gated_generate_content,
    google_ladder,
)
from vtx_recon.safety import (
    Consent,
    GatedProbeBlocked,
    ProbeTier,
)

_GLA = "https://generativelanguage.googleapis.com/v1beta"
_FAKE_KEY = "AIza" + "FAKE0000000000000000000000000000000"
_SCOPE = "h1:example-program"


def _finding() -> Finding:
    return Finding(detector_name="GoogleAI", verified=True, raw=_FAKE_KEY)


def _consent_safe() -> Consent:
    # Scope present (required to ladder at all) but no --prove: gated blocked.
    return Consent(prove=False, authorized_scope=_SCOPE)


def _consent_full() -> Consent:
    return Consent(prove=True, authorized_scope=_SCOPE)


# --------------------------------------------------------------------------
# Registry wiring
# --------------------------------------------------------------------------


def test_provider_is_registered_for_google_detectors():
    # The Gemini/AI Studio API-key ladder owns the AI-Studio detectors. The "GCP"
    # detector is deliberately claimed by the dedicated service-account-key ladder
    # (gcp.py, imported last so it wins last-write-wins), so it is excluded here.
    for detector in ("GoogleAI", "google", "Gemini"):
        assert get_ladder(detector) is google_ladder


# --------------------------------------------------------------------------
# 1. Valid key climbs safe rungs -> VALID
# --------------------------------------------------------------------------


@respx.mock
async def test_valid_key_climbs_safe_rungs_to_valid():
    respx.get(f"{_GLA}/models").mock(
        return_value=httpx.Response(200, json={"models": [{"name": "models/x"}]})
    )
    respx.get(f"{_GLA}/files").mock(return_value=httpx.Response(200, json={"files": []}))
    respx.get(f"{_GLA}/cachedContents").mock(
        return_value=httpx.Response(200, json={"cachedContents": []})
    )
    respx.get(f"{_GLA}/corpora").mock(
        return_value=httpx.Response(200, json={"corpora": [{"name": "corpora/a"}]})
    )

    result = await google_ladder(_finding(), _consent_safe())

    assert result.provider == "google"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == _SCOPE
    # All four safe rungs ran, all succeeded, none gated.
    names = [r.name for r in result.rungs]
    assert names == ["ListModels", "ListFiles", "ListCachedContents", "ListCorpora"]
    assert all(r.tier is ProbeTier.SAFE for r in result.rungs)
    assert all(r.success for r in result.rungs)
    # The x-goog-api-key header carried the raw key on the first call.
    first_req = respx.calls[0].request
    assert first_req.headers["x-goog-api-key"] == _FAKE_KEY
    # Item count surfaced as non-secret evidence.
    list_models = result.rungs[0]
    assert list_models.evidence["item_count"] == 1


@respx.mock
async def test_evidence_redacts_secret_keys_on_serialisation():
    respx.get(f"{_GLA}/models").mock(return_value=httpx.Response(200, json={"models": []}))
    respx.get(f"{_GLA}/files").mock(return_value=httpx.Response(200, json={"files": []}))
    respx.get(f"{_GLA}/cachedContents").mock(
        return_value=httpx.Response(200, json={"cachedContents": []})
    )
    respx.get(f"{_GLA}/corpora").mock(return_value=httpx.Response(200, json={"corpora": []}))

    result = await google_ladder(_finding(), _consent_safe())
    public = result.to_public()
    # The raw key never appears anywhere in the serialised bundle.
    assert _FAKE_KEY not in repr(public)
    # The finding shows only a redacted form.
    assert public["finding"]["redacted"].startswith("AIza")
    assert public["finding"]["redacted"] != _FAKE_KEY


# --------------------------------------------------------------------------
# 2. Dead key -> DENIED
# --------------------------------------------------------------------------


@respx.mock
async def test_dead_key_is_denied():
    # Every safe rung rejected (401/403) -> no capability proven.
    for path in ("models", "files", "cachedContents", "corpora"):
        respx.get(f"{_GLA}/{path}").mock(
            return_value=httpx.Response(
                400, json={"error": {"code": 400, "message": "API key not valid"}}
            )
        )

    result = await google_ladder(_finding(), _consent_safe())

    assert result.verdict is Verdict.DENIED
    assert all(not r.success for r in result.rungs)
    # No referer-bypass attempted (these were plain 400s, not referer 403s).
    assert "RefererBypass" not in [r.name for r in result.rungs]


@respx.mock
async def test_network_error_does_not_raise_and_is_denied():
    for path in ("models", "files", "cachedContents", "corpora"):
        respx.get(f"{_GLA}/{path}").mock(side_effect=httpx.ConnectError("boom"))

    # Must not raise across the public boundary.
    result = await google_ladder(_finding(), _consent_safe())
    assert result.verdict is Verdict.DENIED
    assert all(not r.success for r in result.rungs)


# --------------------------------------------------------------------------
#    Read-only HTTP-referer bypass on a referer-restricted 403
# --------------------------------------------------------------------------


@respx.mock
async def test_referer_restricted_key_triggers_readonly_bypass():
    # ListModels is referer-blocked; the bypass re-GET (with Referer) succeeds.
    route = respx.get(f"{_GLA}/models")
    route.side_effect = [
        httpx.Response(
            403,
            json={
                "error": {"status": "PERMISSION_DENIED", "message": "API_KEY_HTTP_REFERRER_BLOCKED"}
            },
        ),
        httpx.Response(200, json={"models": [{"name": "models/x"}]}),
    ]
    for path in ("files", "cachedContents", "corpora"):
        respx.get(f"{_GLA}/{path}").mock(return_value=httpx.Response(403, json={}))

    result = await google_ladder(_finding(), _consent_safe())

    names = [r.name for r in result.rungs]
    assert "RefererBypass" in names
    bypass = next(r for r in result.rungs if r.name == "RefererBypass")
    assert bypass.tier is ProbeTier.SAFE  # still read-only
    assert bypass.success is True
    # The bypass attempt carried a forged Referer header.
    last_req = respx.calls.last.request
    assert "Referer" in last_req.headers
    # A successful read-only rung means the key is usable -> VALID.
    assert result.verdict is Verdict.VALID


# --------------------------------------------------------------------------
# 3. GATED rung blocked without consent; reachable with full consent
# --------------------------------------------------------------------------


def test_gated_rungs_are_tagged_gated():
    for probe in GATED_RUNGS:
        assert getattr(probe, "__vtx_tier__", None) is ProbeTier.GATED


@respx.mock
async def test_gated_generate_content_blocked_without_consent():
    # Route exists, but it must NEVER be called: the guard blocks first.
    route = respx.post(f"{_GLA}/models/gemini-1.5-flash-latest:generateContent").mock(
        return_value=httpx.Response(200, json={})
    )

    async with httpx.AsyncClient() as client:
        # No --prove -> blocked.
        with pytest.raises(GatedProbeBlocked):
            await gated_generate_content(_consent_safe(), client, _FAKE_KEY)
        # No scope at all -> still blocked.
        with pytest.raises(GatedProbeBlocked):
            await gated_generate_content(Consent.denied(), client, _FAKE_KEY)

    # The structural guarantee: no billable network call was ever issued.
    assert not route.called


@respx.mock
async def test_gated_generate_content_runs_with_full_consent():
    route = respx.post(f"{_GLA}/models/gemini-1.5-flash-latest:generateContent").mock(
        return_value=httpx.Response(200, json={"candidates": [{"content": {}}]})
    )

    async with httpx.AsyncClient() as client:
        rung = await gated_generate_content(_consent_full(), client, _FAKE_KEY)

    assert route.called
    assert rung.tier is ProbeTier.GATED
    assert rung.success is True


@respx.mock
async def test_safe_ladder_never_calls_gated_endpoints():
    # Wire all safe rungs to succeed.
    respx.get(f"{_GLA}/models").mock(return_value=httpx.Response(200, json={"models": []}))
    respx.get(f"{_GLA}/files").mock(return_value=httpx.Response(200, json={"files": []}))
    respx.get(f"{_GLA}/cachedContents").mock(
        return_value=httpx.Response(200, json={"cachedContents": []})
    )
    respx.get(f"{_GLA}/corpora").mock(return_value=httpx.Response(200, json={"corpora": []}))
    # Wire the gated endpoints too; they must NOT be hit by the safe ladder.
    gen = respx.post(f"{_GLA}/models/gemini-1.5-flash-latest:generateContent").mock(
        return_value=httpx.Response(200, json={})
    )
    upload = respx.post("https://generativelanguage.googleapis.com/upload/v1beta/files").mock(
        return_value=httpx.Response(200, json={})
    )
    signup = respx.post("https://identitytoolkit.googleapis.com/v1/accounts:signUp").mock(
        return_value=httpx.Response(200, json={})
    )

    # Even with FULL consent, google_ladder runs only the safe tier.
    result = await google_ladder(_finding(), _consent_full())

    assert result.verdict is Verdict.VALID
    assert all(r.tier is ProbeTier.SAFE for r in result.rungs)
    assert not gen.called
    assert not upload.called
    assert not signup.called


# --------------------------------------------------------------------------
#    Ladder refuses to run without an authorized scope
# --------------------------------------------------------------------------


async def test_ladder_requires_authorized_scope():
    from vtx_recon.safety import ScopeRequired

    with pytest.raises(ScopeRequired):
        # prove=True but no scope: laddering itself is refused.
        await google_ladder(_finding(), Consent(prove=True, authorized_scope=None))
