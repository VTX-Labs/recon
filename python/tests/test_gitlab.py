"""Tests for the GitLab capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (identity -> token scopes) to VALID;
* a dead token yields DENIED and stops after the identity rung.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import gitlab
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")


def _finding(detector: str, raw: str) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await gitlab.gitlab_ladder(_finding("GitLab", "glpat-abc"), Consent.denied())


@respx.mock
async def test_gitlab_valid_token_climbs_two_safe_rungs() -> None:
    respx.get("https://gitlab.com/api/v4/user").mock(
        return_value=httpx.Response(200, json={"id": 7, "username": "victim", "is_admin": False})
    )
    respx.get("https://gitlab.com/api/v4/personal_access_tokens/self").mock(
        return_value=httpx.Response(
            200, json={"active": True, "scopes": ["api", "read_repository"]}
        )
    )

    result = await gitlab.gitlab_ladder(_finding("GitLab", "glpat-valid"), SAFE_CONSENT)

    assert result.provider == "gitlab"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == ["gitlab.user", "gitlab.token.scopes"]
    assert all(r.tier is ProbeTier.SAFE for r in result.rungs)
    assert all(r.success for r in result.rungs)
    assert result.rungs[1].evidence["scopes"] == ["api", "read_repository"]


@respx.mock
async def test_gitlab_dead_token_is_denied_and_stops_early() -> None:
    user_route = respx.get("https://gitlab.com/api/v4/user").mock(
        return_value=httpx.Response(401, json={"message": "401 Unauthorized"})
    )
    scopes_route = respx.get("https://gitlab.com/api/v4/personal_access_tokens/self").mock(
        return_value=httpx.Response(200, json={"scopes": []})
    )

    result = await gitlab.gitlab_ladder(_finding("GitLab", "glpat-dead"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    # Ordered ladder: identity failed, so the depth rung was never attempted.
    assert [r.name for r in result.rungs] == ["gitlab.user"]
    assert user_route.called
    assert not scopes_route.called


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("GitLab") is gitlab.gitlab_ladder
    # Detector matching is case-insensitive.
    assert get_ladder("gitlab") is gitlab.gitlab_ladder
