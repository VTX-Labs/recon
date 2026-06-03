"""Tests for the Zendesk capability ladder.

Zendesk Basic auth is ``base64(email/token:apitoken)`` and BOTH the subdomain
and account email are absent from the raw 40-char API token — so EVERY rung is
MANUAL and the ladder makes NO live HTTP call. The tests run inside
``respx.mock`` (which rejects any unmocked request) to PROVE no network traffic
ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: current-user, list-users; one
  GATED: list-tickets), so the verdict is DENIED;
* each safe_curl keeps the token as ``$KEY`` and the email as ``$EMAIL`` (never
  the raw token), with a ``{subdomain}`` placeholder for the operator;
* the GATED list-tickets rung is recorded ``blocked`` without consent and stays a
  manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import zendesk
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"


def _finding(detector: str = "ZendeskApi", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await zendesk.zendesk_ladder(_finding(), Consent.denied())


@respx.mock
async def test_zendesk_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await zendesk.zendesk_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "zendesk"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["current-user", "list-users", "list-tickets"]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["current-user", "list-users"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        curl = rung.evidence["safe_curl"]
        assert "$KEY" in curl
        assert "$EMAIL" in curl
        assert "{subdomain}" in curl
        assert FAKE_KEY not in curl


@respx.mock
async def test_zendesk_gated_tickets_blocked_without_consent() -> None:
    result = await zendesk.zendesk_ladder(_finding(), SAFE_CONSENT)

    tickets = next(r for r in result.rungs if r.name == "list-tickets")
    assert tickets.tier is ProbeTier.GATED
    assert tickets.blocked is True
    assert tickets.success is False
    assert "$KEY" in tickets.evidence["safe_curl"]


@respx.mock
async def test_zendesk_gated_tickets_with_consent_stays_manual() -> None:
    result = await zendesk.zendesk_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    tickets = next(r for r in result.rungs if r.name == "list-tickets")
    assert tickets.blocked is False
    assert tickets.success is False
    assert tickets.evidence["manual"] is True


async def test_zendesk_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await zendesk._zendesk_list_tickets(SAFE_CONSENT)
    assert zendesk._zendesk_list_tickets.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_zendesk_result_is_redacted() -> None:
    result = await zendesk.zendesk_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("ZendeskApi") is zendesk.zendesk_ladder
    assert get_ladder("zendeskapi") is zendesk.zendesk_ladder
