"""Tests for the Snowflake capability ladder.

The Snowflake SQL/REST APIs authenticate with a KEYPAIR_JWT minted from a
private key that is NOT in the raw multipart credential, so EVERY rung is
MANUAL and the ladder makes NO live HTTP call. The tests run inside
``respx.mock`` (which rejects any unmocked request) to PROVE no network traffic
ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: whoami-current-user,
  list-databases; one GATED: exfil-table-data), so the verdict is DENIED;
* each safe_curl keeps the secret as the ``$JWT`` placeholder (never the raw
  credential) — Snowflake uses ``$JWT``, not ``$KEY``;
* the GATED exfil-table-data rung is recorded ``blocked`` without consent and
  stays a manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw credential is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import snowflake
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "account=ab12345.us-east-1;user=VICTIM;" + "password=" + "EXAMPLE_FAKE_PASSWORD_NOT_REAL"


def _finding(detector: str = "Snowflake", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await snowflake.snowflake_ladder(_finding(), Consent.denied())


@respx.mock
async def test_snowflake_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await snowflake.snowflake_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "snowflake"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "whoami-current-user",
        "list-databases",
        "exfil-table-data",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["whoami-current-user", "list-databases"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        curl = rung.evidence["safe_curl"]
        # Snowflake uses the $JWT placeholder, not $KEY.
        assert "$JWT" in curl
        assert FAKE_KEY not in curl


@respx.mock
async def test_snowflake_gated_exfil_blocked_without_consent() -> None:
    result = await snowflake.snowflake_ladder(_finding(), SAFE_CONSENT)

    exfil = next(r for r in result.rungs if r.name == "exfil-table-data")
    assert exfil.tier is ProbeTier.GATED
    assert exfil.blocked is True
    assert exfil.success is False
    assert "$JWT" in exfil.evidence["safe_curl"]


@respx.mock
async def test_snowflake_gated_exfil_with_consent_stays_manual() -> None:
    result = await snowflake.snowflake_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    exfil = next(r for r in result.rungs if r.name == "exfil-table-data")
    assert exfil.blocked is False
    assert exfil.success is False
    assert exfil.evidence["manual"] is True


async def test_snowflake_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await snowflake._snowflake_exfil_table_data(SAFE_CONSENT)
    assert snowflake._snowflake_exfil_table_data.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_snowflake_result_is_redacted() -> None:
    result = await snowflake.snowflake_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Snowflake") is snowflake.snowflake_ladder
    assert get_ladder("snowflake") is snowflake.snowflake_ladder
