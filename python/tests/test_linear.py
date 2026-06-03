"""Tests for the Linear (GraphQL) capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid key climbs two SAFE GraphQL rungs (viewer -> organization) to VALID,
  sent with ``Authorization: <key>`` WITHOUT a ``Bearer `` prefix;
* a key that returns HTTP 200 with a top-level GraphQL ``errors`` array is a
  FAILURE (DENIED), not a success — Linear reports auth failures on 200;
* the GATED member-PII enumeration is structurally blocked without consent
  (recorded ``blocked``, NO network call), and WITH full consent it actually
  FIRES and the result is PROVEN (a live gated rung), with PII summarised;
* a no-scope consent raises ScopeRequired;
* the raw key is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import linear
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

GRAPHQL = "https://api.linear.app/graphql"
FAKE_KEY = "lin_api_" + "EXAMPLEFAKEKEYNOTREAL0000000000000000000"


def _finding(detector: str = "LinearAPI", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await linear.linear_ladder(_finding(), Consent.denied())


@respx.mock
async def test_linear_valid_key_climbs_safe_rungs() -> None:
    route = respx.post(GRAPHQL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={"data": {"viewer": {"id": "u1", "name": "Victim", "email": "v@x.example"}}},
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "organization": {
                            "id": "o1",
                            "name": "Acme",
                            "urlKey": "acme",
                            "userCount": 42,
                        }
                    }
                },
            ),
        ]
    )

    result = await linear.linear_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "linear"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["viewer-identity", "organization"]
    assert all(r.success for r in safe)
    # Linear auth is the raw key with NO Bearer prefix.
    assert route.calls[0].request.headers["Authorization"] == FAKE_KEY
    org = next(r for r in result.rungs if r.name == "organization")
    assert org.evidence["user_count"] == 42
    # Without consent the gated PII rung is blocked.
    users = next(r for r in result.rungs if r.name == "list-org-users")
    assert users.blocked is True


@respx.mock
async def test_linear_graphql_errors_on_200_is_denied() -> None:
    # Linear returns HTTP 200 with a top-level `errors` array for an invalid key.
    route = respx.post(GRAPHQL).mock(
        return_value=httpx.Response(200, json={"errors": [{"message": "Authentication required"}]})
    )

    result = await linear.linear_ladder(
        _finding(raw="lin_api_deadkeydeadkeydeadkeydeadkeydeadkey0"), SAFE_CONSENT
    )

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["viewer-identity"]
    identity = result.rungs[0]
    assert identity.success is False
    assert "Authentication required" in identity.detail
    # Ordered ladder: identity failed, so org/users rungs were never attempted.
    assert route.call_count == 1


@respx.mock
async def test_linear_gated_users_blocked_without_consent_makes_no_call() -> None:
    route = respx.post(GRAPHQL).mock(
        side_effect=[
            httpx.Response(200, json={"data": {"viewer": {"id": "u1", "name": "V"}}}),
            httpx.Response(
                200, json={"data": {"organization": {"id": "o1", "name": "Acme", "userCount": 3}}}
            ),
        ]
    )

    result = await linear.linear_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    users = next(r for r in result.rungs if r.name == "list-org-users")
    assert users.tier is ProbeTier.GATED
    assert users.blocked is True
    assert users.success is False
    # Only the two SAFE GraphQL POSTs ran; the gated PII query never fired.
    assert route.call_count == 2


@respx.mock
async def test_linear_gated_users_fires_with_full_consent_is_proven() -> None:
    route = respx.post(GRAPHQL).mock(
        side_effect=[
            httpx.Response(200, json={"data": {"viewer": {"id": "u1", "name": "V"}}}),
            httpx.Response(
                200, json={"data": {"organization": {"id": "o1", "name": "Acme", "userCount": 2}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "users": {
                            "nodes": [
                                {"name": "Alice", "email": "alice@victim.example"},
                                {"name": "Bob", "email": "bob@victim.example"},
                            ]
                        }
                    }
                },
            ),
        ]
    )

    result = await linear.linear_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.PROVEN
    users = next(r for r in result.rungs if r.name == "list-org-users")
    assert users.tier is ProbeTier.GATED
    assert users.blocked is False
    assert users.success is True
    assert users.evidence["user_count"] == 2
    # PII is summarised (a sample), not the raw email dump on every key.
    assert "names_sample" in users.evidence
    # The gated query fired with the same no-Bearer auth header.
    assert route.calls[2].request.headers["Authorization"] == FAKE_KEY
    assert route.call_count == 3


async def test_linear_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await linear._linear_list_org_users(SAFE_CONSENT, FAKE_KEY)
    assert linear._linear_list_org_users.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_linear_result_is_redacted() -> None:
    respx.post(GRAPHQL).mock(
        side_effect=[
            httpx.Response(200, json={"data": {"viewer": {"id": "u1", "name": "V"}}}),
            httpx.Response(200, json={"data": {"organization": {"id": "o1", "name": "Acme"}}}),
        ]
    )

    result = await linear.linear_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("LinearAPI") is linear.linear_ladder
    assert get_ladder("linearapi") is linear.linear_ladder
