"""Tests for the Supabase capability ladder.

Supabase is a FULLY MANUAL provider: every impact endpoint lives on the project's
``{ref}`` subdomain that is NOT in the raw JWT, so NO rung ever issues a live
call. respx proves no network request leaves the process. The tests assert:

* the ladder makes zero network calls and lands on DENIED;
* the SAFE OpenAPI rung renders a ``$KEY`` safe curl (raw JWT never present);
* the two GATED rungs are blocked without consent, and stay MANUAL ``$KEY`` safe
  curls WITH consent — no live call either way;
* the ladder refuses to run without an authorized scope;
* the raw JWT never appears in the public result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import supabase
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# A three-segment JWT (service_role); random padding, not a real key.
FAKE_KEY = (
    "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJ" + "yb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjAwMDAwMDAwfQ."
    "EXAMPLEFAKEKEYNOTREAL0000000000000000000"
)


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Supabase", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await supabase.supabase_ladder(_finding(), Consent.denied())


@respx.mock(assert_all_called=False)
async def test_all_rungs_manual_no_network_gated_blocked() -> None:
    # No routes registered: any live request would raise, proving no network call.
    result = await supabase.supabase_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "supabase"
    assert result.verdict is Verdict.DENIED  # all manual -> nothing succeeds
    assert len(respx.calls) == 0

    assert [r.name for r in result.rungs] == [
        "rest-root-openapi",
        "list-table-rows",
        "list-auth-users",
    ]

    safe = result.rungs[0]
    assert safe.tier is ProbeTier.SAFE
    assert safe.success is False
    assert safe.evidence["manual"] is True
    assert "$KEY" in safe.evidence["safe_curl"]
    assert FAKE_KEY not in safe.evidence["safe_curl"]

    # Both GATED rungs are blocked without consent.
    for name in ("list-table-rows", "list-auth-users"):
        gated = next(r for r in result.rungs if r.name == name)
        assert gated.tier is ProbeTier.GATED
        assert gated.blocked is True
        assert gated.success is False
        assert "$KEY" in gated.evidence["safe_curl"]


@respx.mock(assert_all_called=False)
async def test_gated_rungs_with_consent_are_manual_no_network() -> None:
    result = await supabase.supabase_ladder(_finding(), FULL_CONSENT)

    assert len(respx.calls) == 0
    assert result.verdict is Verdict.DENIED
    for name in ("list-table-rows", "list-auth-users"):
        gated = next(r for r in result.rungs if r.name == name)
        assert gated.blocked is False
        assert gated.success is False
        assert gated.evidence["manual"] is True
        assert "$KEY" in gated.evidence["safe_curl"]
        assert FAKE_KEY not in gated.evidence["safe_curl"]


def test_gated_probes_tagged_gated() -> None:
    assert supabase._list_table_rows.__vtx_tier__ is ProbeTier.GATED
    assert supabase._list_auth_users.__vtx_tier__ is ProbeTier.GATED


async def test_no_raw_secret_in_public_result() -> None:
    result = await supabase.supabase_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Supabase") is supabase.supabase_ladder
    assert get_ladder("supabase") is supabase.supabase_ladder
