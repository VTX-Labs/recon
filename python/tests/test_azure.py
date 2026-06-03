"""Tests for the Azure Storage SAS capability ladder.

An Azure SAS needs the storage ACCOUNT/CONTAINER (and an Azure AD secret needs
the paired tenant/client id), none of which are in the raw finding, so EVERY
rung is MANUAL — the ladder makes NO live HTTP call. The tests run inside
``respx.mock`` (which rejects any unmocked request) to PROVE no network traffic
ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note (two SAFE: sas-resource-probe,
  service-principal-token; one GATED: list-blobs), so the verdict is DENIED;
* each safe_curl keeps the secret as ``$KEY`` (never the raw SAS);
* the GATED list-blobs rung is recorded ``blocked`` without consent and stays a
  manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw SAS is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import azure
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = (
    "sp=r&st=2024-01-01T00:00:00Z&se=2030-01-01T00:00:00Z&spr=https&sv=2022-11-02&sr=c&"
    + "sig="
    + "EXAMPLEFAKEKEYNOTREAL00000000000000%3D"
)


def _finding(detector: str = "AzureSasToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await azure.azure_ladder(_finding(), Consent.denied())


@respx.mock
async def test_azure_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await azure.azure_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "azure"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "sas-resource-probe",
        "list-blobs",
        "service-principal-token",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["sas-resource-probe", "service-principal-token"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
        assert FAKE_KEY not in rung.evidence["safe_curl"]


@respx.mock
async def test_azure_gated_list_blobs_blocked_without_consent() -> None:
    result = await azure.azure_ladder(_finding(), SAFE_CONSENT)

    blobs = next(r for r in result.rungs if r.name == "list-blobs")
    assert blobs.tier is ProbeTier.GATED
    assert blobs.blocked is True
    assert blobs.success is False
    assert "$KEY" in blobs.evidence["safe_curl"]


@respx.mock
async def test_azure_gated_list_blobs_with_consent_stays_manual() -> None:
    result = await azure.azure_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    blobs = next(r for r in result.rungs if r.name == "list-blobs")
    assert blobs.blocked is False
    assert blobs.success is False
    assert blobs.evidence["manual"] is True


async def test_azure_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await azure._list_blobs_gated(SAFE_CONSENT)
    assert azure._list_blobs_gated.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_azure_result_is_redacted() -> None:
    result = await azure.azure_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("AzureSasToken") is azure.azure_ladder
    assert get_ladder("AzureStorage") is azure.azure_ladder
    assert get_ladder("azuresastoken") is azure.azure_ladder
