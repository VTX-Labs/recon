"""Tests for the Datadog capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid API key climbs the SAFE ``validate-api-key`` rung live (only
  ``DD-API-KEY`` needed) to VALID, then emits two SAFE/MANUAL app-key rungs as
  safe-curl notes that fire NO network request;
* a 200 body with ``valid != true`` is treated as DENIED;
* a dead key (403) yields DENIED and stops after the validate rung;
* the MANUAL rungs keep the secret as ``$KEY`` / app key as ``$APP_KEY`` (raw key
  absent);
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import datadog
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)

FAKE_KEY = "deadbeefdeadbeefdeadbeefdeadbeef"

_VALIDATE = "https://api.datadoghq.com/api/v1/validate"


def _finding(detector: str = "DatadogToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await datadog.datadog_ladder(_finding(), Consent.denied())


@respx.mock
async def test_datadog_valid_key_validates_then_manual_rungs() -> None:
    validate = respx.get(_VALIDATE).mock(return_value=httpx.Response(200, json={"valid": True}))

    result = await datadog.datadog_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "datadog"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == [
        "validate-api-key",
        "list-current-user",
        "list-monitors",
    ]

    req = validate.calls.last.request
    assert req.url.host == "api.datadoghq.com"
    assert req.url.path == "/api/v1/validate"
    assert req.headers["DD-API-KEY"] == FAKE_KEY

    identity = result.rungs[0]
    assert identity.tier is ProbeTier.SAFE
    assert identity.success is True
    assert identity.evidence["valid"] is True

    # The two deeper rungs are MANUAL app-key notes: no network, both placeholders.
    for rung in result.rungs[1:]:
        assert rung.tier is ProbeTier.SAFE
        assert rung.success is False
        assert rung.evidence["manual"] is True
        curl = rung.evidence["safe_curl"]
        assert "$KEY" in curl
        assert "$APP_KEY" in curl
        assert FAKE_KEY not in curl


@respx.mock
async def test_datadog_valid_false_body_is_denied() -> None:
    respx.get(_VALIDATE).mock(return_value=httpx.Response(200, json={"valid": False}))

    result = await datadog.datadog_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["validate-api-key"]


@respx.mock
async def test_datadog_dead_key_is_denied_and_stops_early() -> None:
    validate = respx.get(_VALIDATE).mock(
        return_value=httpx.Response(403, json={"errors": ["Forbidden"]})
    )

    result = await datadog.datadog_ladder(
        _finding(raw="deadkey00deadkey00deadkey00dead00"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["validate-api-key"]
    assert validate.called


@respx.mock
async def test_datadog_no_raw_secret_in_public_result() -> None:
    respx.get(_VALIDATE).mock(return_value=httpx.Response(200, json={"valid": True}))
    result = await datadog.datadog_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("DatadogToken") is datadog.datadog_ladder
    assert get_ladder("datadogtoken") is datadog.datadog_ladder
