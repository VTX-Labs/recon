"""Tests for the OpenAI capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs the SAFE ``list-models`` rung to VALID, with the
  ``Authorization: Bearer`` header and parsed model evidence;
* a dead key (401) yields DENIED and never attempts the gated billable rung;
* the GATED ``chat-completion`` rung is blocked (no network) without consent, and
  PROVEN with full consent (live billable completion);
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import openai
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "sk-proj-" + "EXAMPLEFAKEKEYNOTREAL0000000"


def _finding(detector: str = "OpenAI", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await openai.openai_ladder(_finding(), Consent.denied())


@respx.mock
async def test_openai_valid_key_climbs_safe_rung() -> None:
    models = respx.get("https://api.openai.com/v1/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}, {"id": "o1-mini"}]},
        )
    )
    completion_route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"id": "chatcmpl_LEAK"})
    )

    result = await openai.openai_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "openai"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == SCOPE
    assert models.called

    req = models.calls.last.request
    assert req.url.host == "api.openai.com"
    assert req.url.path == "/v1/models"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"

    rung = result.rungs[0]
    assert rung.name == "openai.list_models"
    assert rung.tier is ProbeTier.SAFE
    assert rung.success is True
    assert rung.evidence["model_count"] == 3
    assert "gpt-4o-mini" in rung.evidence["sample_models"]

    gated = next(r for r in result.rungs if r.name == "openai.chat_completion")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert not completion_route.called


@respx.mock
async def test_openai_dead_key_is_denied_and_skips_gated() -> None:
    models = respx.get("https://api.openai.com/v1/models").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Incorrect API key"}})
    )
    completion_route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"id": "chatcmpl_LEAK"})
    )

    result = await openai.openai_ladder(_finding(raw="sk-deadkey0000"), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["openai.list_models"]
    assert models.called
    assert not completion_route.called


@respx.mock
async def test_openai_full_consent_reaches_gated_and_is_proven() -> None:
    respx.get("https://api.openai.com/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}]})
    )
    completion_route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"id": "chatcmpl_1", "object": "chat.completion"})
    )

    result = await openai.openai_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.PROVEN
    assert completion_route.called
    gated = next(r for r in result.rungs if r.name == "openai.chat_completion")
    assert gated.blocked is False
    assert gated.success is True
    assert gated.evidence["billable"] is True


@respx.mock
async def test_openai_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    completion_route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"id": "chatcmpl_LEAK"})
    )
    with pytest.raises(GatedProbeBlocked):
        await openai._openai_chat_completion(SAFE_CONSENT, FAKE_KEY)
    assert not completion_route.called
    assert openai._openai_chat_completion.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_openai_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.openai.com/v1/models").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await openai.openai_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("OpenAI") is openai.openai_ladder
    assert get_ladder("openai") is openai.openai_ladder
