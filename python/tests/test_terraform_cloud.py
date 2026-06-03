"""Tests for the HCP Terraform / Terraform Cloud capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (/account/details -> /organizations) to
  VALID, sent with the bearer token and the JSON:API content-type header;
* a dead token (401) yields DENIED and stops after /account/details;
* the GATED create-run is structurally blocked without consent (recorded
  ``blocked``, NO network call) and stays a MANUAL safe-curl note even WITH
  consent (its body needs a WORKSPACE_ID the engine cannot fill);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import terraform_cloud
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "aBcDeFgHiJkLmN.atlasv1." + "Z" * 67


def _finding(detector: str = "TerraformCloudPersonalToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await terraform_cloud.terraform_cloud_ladder(_finding(), Consent.denied())


@respx.mock
async def test_terraform_cloud_valid_token_climbs_safe_rungs() -> None:
    account = respx.get("https://app.terraform.io/api/v2/account/details").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": "user-1",
                    "type": "users",
                    "attributes": {"username": "victim", "email": "v@x.example"},
                }
            },
        )
    )
    respx.get("https://app.terraform.io/api/v2/organizations").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "acme-org", "type": "organizations"}]},
        )
    )

    result = await terraform_cloud.terraform_cloud_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "terraform-cloud"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["account-details", "list-organizations"]
    assert all(r.success for r in safe)
    req = account.calls.last.request
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert req.headers["Content-Type"] == "application/vnd.api+json"
    orgs = next(r for r in result.rungs if r.name == "list-organizations")
    assert orgs.evidence["organization_count"] == 1
    assert orgs.evidence["organizations_sample"] == ["acme-org"]


@respx.mock
async def test_terraform_cloud_dead_token_is_denied_and_stops_early() -> None:
    account = respx.get("https://app.terraform.io/api/v2/account/details").mock(
        return_value=httpx.Response(401, json={"errors": [{"status": "401"}]})
    )
    orgs = respx.get("https://app.terraform.io/api/v2/organizations").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    result = await terraform_cloud.terraform_cloud_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["account-details"]
    assert account.called
    assert not orgs.called


@respx.mock
async def test_terraform_cloud_gated_run_blocked_without_consent_makes_no_call() -> None:
    respx.get("https://app.terraform.io/api/v2/account/details").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"id": "user-1", "type": "users", "attributes": {"username": "v"}}},
        )
    )
    respx.get("https://app.terraform.io/api/v2/organizations").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "acme-org"}]})
    )
    run_route = respx.post("https://app.terraform.io/api/v2/runs").mock(
        return_value=httpx.Response(201, json={"data": {"id": "run-LEAK"}})
    )

    result = await terraform_cloud.terraform_cloud_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    run = next(r for r in result.rungs if r.name == "create-run")
    assert run.tier is ProbeTier.GATED
    assert run.blocked is True
    assert run.success is False
    assert run.evidence["manual"] is True
    assert "$KEY" in run.evidence["safe_curl"]
    assert FAKE_KEY not in run.evidence["safe_curl"]
    assert not run_route.called


@respx.mock
async def test_terraform_cloud_gated_run_with_consent_stays_manual_no_call() -> None:
    respx.get("https://app.terraform.io/api/v2/account/details").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"id": "user-1", "type": "users", "attributes": {"username": "v"}}},
        )
    )
    respx.get("https://app.terraform.io/api/v2/organizations").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "acme-org"}]})
    )
    run_route = respx.post("https://app.terraform.io/api/v2/runs").mock(
        return_value=httpx.Response(201, json={"data": {"id": "run-LEAK"}})
    )

    result = await terraform_cloud.terraform_cloud_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.VALID
    run = next(r for r in result.rungs if r.name == "create-run")
    assert run.blocked is False
    assert run.success is False
    assert run.evidence["manual"] is True
    assert not run_route.called


async def test_terraform_cloud_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await terraform_cloud._terraform_cloud_create_run(SAFE_CONSENT)
    assert terraform_cloud._terraform_cloud_create_run.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_terraform_cloud_result_is_redacted() -> None:
    respx.get("https://app.terraform.io/api/v2/account/details").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"id": "user-1", "type": "users", "attributes": {"username": "v"}}},
        )
    )
    respx.get("https://app.terraform.io/api/v2/organizations").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    result = await terraform_cloud.terraform_cloud_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("TerraformCloudPersonalToken") is terraform_cloud.terraform_cloud_ladder
    assert get_ladder("terraformcloudpersonaltoken") is terraform_cloud.terraform_cloud_ladder
