"""Tests for the Twilio capability ladder.

Twilio is a FULLY MANUAL provider: the raw secret is only the Account SID (the
paired AuthToken is NOT in the finding), so NO authenticated request can be
issued. respx proves no network request leaves the process. The tests assert:

* the ladder makes zero network calls and lands on DENIED;
* the two SAFE rungs and the GATED balance rung are manual safe-curl notes;
* the GATED balance rung is blocked without consent and stays a manual safe curl
  WITH consent — no live call either way;
* the ladder refuses to run without an authorized scope.

REDACTION EXCEPTION: the Account SID is a public-ish identifier and is
intentionally INLINED in the curls. The secret material here is the AuthToken,
which is kept as the ``$TWILIO_AUTH_TOKEN`` shell-variable placeholder — that is
what we assert appears in the curls (and never a raw token value).
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import twilio
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# AC<32 hex> Account SID; random padding, not a real SID.
FAKE_SID = "AC" + "deadbeef" * 4


def _finding(raw: str = FAKE_SID) -> Finding:
    return Finding(detector_name="Twilio", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await twilio.twilio_ladder(_finding(), Consent.denied())


@respx.mock(assert_all_called=False)
async def test_all_rungs_manual_no_network_denied() -> None:
    # No routes registered: any live request would raise, proving no network call.
    result = await twilio.twilio_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "twilio"
    assert result.verdict is Verdict.DENIED  # all manual -> nothing succeeds
    assert len(respx.calls) == 0

    assert [r.name for r in result.rungs] == [
        "twilio.account.fetch",
        "twilio.phone_numbers",
        "twilio.balance",
    ]

    for name in ("twilio.account.fetch", "twilio.phone_numbers"):
        rung = next(r for r in result.rungs if r.name == name)
        assert rung.tier is ProbeTier.SAFE
        assert rung.success is False
        assert rung.evidence["manual"] is True
        # The AuthToken (the real secret) is kept as a placeholder; the SID is
        # intentionally shown as a public-ish identifier.
        curl = rung.evidence["safe_curl"]
        assert "$TWILIO_AUTH_TOKEN" in curl
        assert FAKE_SID in curl  # SID intentionally inlined

    # GATED balance rung is blocked without consent.
    gated = next(r for r in result.rungs if r.name == "twilio.balance")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert "$TWILIO_AUTH_TOKEN" in gated.evidence["safe_curl"]


@respx.mock(assert_all_called=False)
async def test_gated_balance_with_consent_is_manual_no_network() -> None:
    result = await twilio.twilio_ladder(_finding(), FULL_CONSENT)

    assert len(respx.calls) == 0
    assert result.verdict is Verdict.DENIED
    gated = next(r for r in result.rungs if r.name == "twilio.balance")
    assert gated.blocked is False
    assert gated.success is False
    assert gated.evidence["manual"] is True
    assert "$TWILIO_AUTH_TOKEN" in gated.evidence["safe_curl"]


def test_gated_probe_tagged_gated() -> None:
    assert twilio.twilio_gated_balance.__vtx_tier__ is ProbeTier.GATED


async def test_auth_token_placeholder_in_curls_not_a_raw_token() -> None:
    # Redaction exception: SID is shown, but the AuthToken stays a placeholder in
    # every curl across the public result.
    result = await twilio.twilio_ladder(_finding(), FULL_CONSENT)
    blob = repr(result.to_public())
    assert "$TWILIO_AUTH_TOKEN" in blob


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Twilio") is twilio.twilio_ladder
    assert get_ladder("twilio") is twilio.twilio_ladder
