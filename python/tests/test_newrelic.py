"""Tests for the New Relic capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs two SAFE NerdGraph rungs (viewer-identity -> list-accounts)
  to VALID, using ``POST`` to the GraphQL endpoint with the ``Api-Key`` header
  and parsed evidence;
* a populated GraphQL ``errors`` array (HTTP 200) is treated as a dead key ->
  DENIED, stopping after the identity rung;
* a transport-level HTTP error on identity also yields DENIED;
* the ladder refuses to run without an authorized scope;
* the raw key never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import newrelic
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)

FAKE_KEY = "NRAK" + "-EXAMPLEFAKEKEYNOTREAL000000"

_URL = "https://api.newrelic.com/graphql"


def _finding(detector: str = "NewRelicPersonalApiKey", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await newrelic.newrelic_ladder(_finding(), Consent.denied())


@respx.mock
async def test_newrelic_valid_key_climbs_two_safe_rungs() -> None:
    route = respx.post(_URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "data": {
                        "actor": {
                            "user": {"id": 12345, "name": "Victim", "email": "v@victim.example"}
                        }
                    }
                },
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "actor": {
                            "accounts": [
                                {"id": 1, "name": "Prod"},
                                {"id": 2, "name": "Staging"},
                            ]
                        }
                    }
                },
            ),
        ]
    )

    result = await newrelic.newrelic_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "newrelic"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == ["viewer-identity", "list-accounts"]
    assert all(r.tier is ProbeTier.SAFE and r.success for r in result.rungs)

    req = route.calls[0].request
    assert req.url.host == "api.newrelic.com"
    assert req.url.path == "/graphql"
    assert req.method == "POST"
    assert req.headers["Api-Key"] == FAKE_KEY

    identity = result.rungs[0]
    assert identity.evidence["user_id"] == 12345
    assert identity.evidence["user_name"] == "Victim"
    accounts = result.rungs[1]
    assert accounts.evidence["account_count"] == 2
    assert accounts.evidence["account_ids"] == [1, 2]


@respx.mock
async def test_newrelic_graphql_errors_treated_as_dead_key() -> None:
    route = respx.post(_URL).mock(
        return_value=httpx.Response(200, json={"errors": [{"message": "Invalid API key"}]})
    )

    result = await newrelic.newrelic_ladder(
        _finding(raw="NRAK-DEADKEY00000000000000"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["viewer-identity"]
    assert route.call_count == 1
    assert result.rungs[0].evidence["errors"] == ["Invalid API key"]


@respx.mock
async def test_newrelic_transport_error_is_denied() -> None:
    respx.post(_URL).mock(side_effect=httpx.ConnectError("boom"))

    result = await newrelic.newrelic_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["viewer-identity"]
    assert result.rungs[0].evidence["error"] == "ConnectError"


@respx.mock
async def test_newrelic_no_raw_secret_in_public_result() -> None:
    respx.post(_URL).mock(
        return_value=httpx.Response(200, json={"data": {"actor": {"user": {"id": 1, "name": "v"}}}})
    )
    result = await newrelic.newrelic_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("NewRelicPersonalApiKey") is newrelic.newrelic_ladder
    assert get_ladder("newrelicpersonalapikey") is newrelic.newrelic_ladder
