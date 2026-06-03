"""Tests for the Anthropic capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs the SAFE ``list-models`` rung to VALID, with the correct
  ``x-api-key`` / ``anthropic-version`` headers and parsed model evidence;
* a dead key (401) yields DENIED and never attempts the gated billable rung;
* the GATED ``create-message`` rung is blocked (no network) without consent, and
  PROVEN with full consent (live billable message);
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import anthropic
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "sk-ant-api03-" + "EXAMPLEFAKEKEYNOTREAL000"


def _finding(detector: str = "Anthropic", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await anthropic.anthropic_ladder(_finding(), Consent.denied())


@respx.mock
async def test_anthropic_valid_key_climbs_safe_rung() -> None:
    models = respx.get("https://api.anthropic.com/v1/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "claude-3-5-haiku-latest"}, {"id": "claude-3-5-sonnet-latest"}]},
        )
    )
    # Gated billable endpoint must never be touched without consent.
    message_route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"id": "msg_LEAK"})
    )

    result = await anthropic.anthropic_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "anthropic"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == SCOPE
    assert models.called

    req = models.calls.last.request
    assert req.url.host == "api.anthropic.com"
    assert req.url.path == "/v1/models"
    assert req.headers["x-api-key"] == FAKE_KEY
    assert req.headers["anthropic-version"] == "2023-06-01"

    rung = result.rungs[0]
    assert rung.name == "anthropic.list_models"
    assert rung.tier is ProbeTier.SAFE
    assert rung.success is True
    assert rung.evidence["model_count"] == 2
    assert "claude-3-5-haiku-latest" in rung.evidence["sample_models"]

    # GATED create-message blocked without consent: no billable request issued.
    gated = next(r for r in result.rungs if r.name == "anthropic.create_message")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert not message_route.called


@respx.mock
async def test_anthropic_dead_key_is_denied_and_skips_gated() -> None:
    models = respx.get("https://api.anthropic.com/v1/models").mock(
        return_value=httpx.Response(401, json={"error": {"message": "invalid x-api-key"}})
    )
    message_route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"id": "msg_LEAK"})
    )

    result = await anthropic.anthropic_ladder(_finding(raw="sk-ant-api03-deadkey"), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["anthropic.list_models"]
    assert models.called
    assert not message_route.called


@respx.mock
async def test_anthropic_full_consent_reaches_gated_and_is_proven() -> None:
    respx.get("https://api.anthropic.com/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "claude-3-5-haiku-latest"}]})
    )
    message_route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"id": "msg_1", "type": "message"})
    )

    result = await anthropic.anthropic_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.PROVEN
    assert message_route.called
    gated = next(r for r in result.rungs if r.name == "anthropic.create_message")
    assert gated.blocked is False
    assert gated.success is True
    assert gated.evidence["billable"] is True


@respx.mock
async def test_anthropic_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    message_route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"id": "msg_LEAK"})
    )
    with pytest.raises(GatedProbeBlocked):
        await anthropic._anthropic_create_message(SAFE_CONSENT, FAKE_KEY)
    assert not message_route.called
    assert anthropic._anthropic_create_message.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_anthropic_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.anthropic.com/v1/models").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await anthropic.anthropic_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Anthropic") is anthropic.anthropic_ladder
    assert get_ladder("anthropic") is anthropic.anthropic_ladder
