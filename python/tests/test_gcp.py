"""Tests for the GCP service-account-key capability ladder.

A GCP service-account JSON key is not a bearer token: you must sign a JWT with
the embedded RSA private key and exchange it for a short-lived OAuth2 token the
engine cannot mint — so EVERY rung is MANUAL and the ladder makes NO live HTTP
call. The tests run inside ``respx.mock`` (which rejects any unmocked request) to
PROVE no network traffic ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (three SAFE: mint-access-token,
  tokeninfo, list-projects; one GATED: list-storage-buckets), so the verdict is
  DENIED;
* the safe curls carry only placeholders (``$KEY`` / ``$TOKEN`` / ``$SIGNED_JWT``
  / ``PROJECT_ID``) and never the raw JSON key material;
* the GATED bucket-list rung is recorded ``blocked`` without consent and stays a
  manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* both GCP / GCPApplicationDefaultCredentials detectors route here;
* the raw key is never present in the public, redacted result.
"""

from __future__ import annotations

import json

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import gcp
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# A realistic (fake) service-account JSON key blob.
_PRIVATE_KEY = (
    "-----BEGIN "
    + "PRIVATE KEY-----\n"
    + "MIIBVf4k3PrivateMaterialXYZ=="
    + "\n-----END PRIVATE KEY-----\n"
)
FAKE_KEY = json.dumps(
    {
        "type": "service_account",
        "project_id": "victim-proj",
        "private_key_id": "abc123",
        "private_key": _PRIVATE_KEY,
        "client_email": "sa@victim-proj.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
)


def _finding(detector: str = "GCP", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await gcp.gcp_ladder(_finding(), Consent.denied())


@respx.mock
async def test_gcp_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await gcp.gcp_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "gcp"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "mint-access-token",
        "tokeninfo",
        "list-projects",
        "list-storage-buckets",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["mint-access-token", "tokeninfo", "list-projects"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        curl = rung.evidence["safe_curl"]
        # No raw key material ever appears in a safe curl.
        assert _PRIVATE_KEY not in curl
        assert "MIIBVf4k3PrivateMaterialXYZ" not in curl


@respx.mock
async def test_gcp_placeholders_present_in_curls() -> None:
    result = await gcp.gcp_ladder(_finding(), SAFE_CONSENT)

    mint = next(r for r in result.rungs if r.name == "mint-access-token")
    assert "$SIGNED_JWT" in mint.evidence["safe_curl"]
    # The minted-token / project rungs carry $TOKEN and PROJECT_ID placeholders.
    projects = next(r for r in result.rungs if r.name == "list-projects")
    assert "$TOKEN" in projects.evidence["safe_curl"]
    buckets = next(r for r in result.rungs if r.name == "list-storage-buckets")
    assert "$TOKEN" in buckets.evidence["safe_curl"]
    assert "PROJECT_ID" in buckets.evidence["safe_curl"]


@respx.mock
async def test_gcp_gated_buckets_blocked_without_consent() -> None:
    result = await gcp.gcp_ladder(_finding(), SAFE_CONSENT)

    buckets = next(r for r in result.rungs if r.name == "list-storage-buckets")
    assert buckets.tier is ProbeTier.GATED
    assert buckets.blocked is True
    assert buckets.success is False
    assert "$TOKEN" in buckets.evidence["safe_curl"]


@respx.mock
async def test_gcp_gated_buckets_with_consent_stays_manual() -> None:
    result = await gcp.gcp_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    buckets = next(r for r in result.rungs if r.name == "list-storage-buckets")
    assert buckets.blocked is False
    assert buckets.success is False
    assert buckets.evidence["manual"] is True


async def test_gcp_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await gcp._gated_list_storage_buckets(SAFE_CONSENT)
    assert gcp._gated_list_storage_buckets.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_gcp_result_is_redacted() -> None:
    result = await gcp.gcp_ladder(_finding(), SAFE_CONSENT)
    blob = repr(result.to_public())
    assert _PRIVATE_KEY not in blob
    assert "MIIBVf4k3PrivateMaterialXYZ" not in blob


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("GCP") is gcp.gcp_ladder
    assert get_ladder("GCPApplicationDefaultCredentials") is gcp.gcp_ladder
    assert get_ladder("gcp") is gcp.gcp_ladder
