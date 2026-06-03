"""Tests for the Notion capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs the SAFE bot-user rung (whoami) to VALID, using Bearer
  auth pinned to ``Notion-Version: 2022-06-28``;
* a dead token (401) yields DENIED and stops after the identity rung;
* the two GATED reads (list-users, search) are blocked (no network) without
  consent, and WITH full consent they FIRE live -> PROVEN with PII/content
  summarised, not dumped;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import notion
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# secret_<43+ chars> shape; random padding, not a real token.
FAKE_KEY = "secret_" + "EXAMPLEFAKEKEYNOTREAL0000000000000000000000"


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Notion", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await notion.notion_ladder(_finding(), Consent.denied())


@respx.mock
async def test_valid_token_climbs_safe_identity_rung() -> None:
    bot = respx.get("https://api.notion.com/v1/users/me").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "bot-1",
                "name": "Acme Integration",
                "type": "bot",
                "bot": {"owner": {"type": "workspace"}, "workspace_name": "Acme"},
            },
        )
    )

    result = await notion.notion_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "notion"
    assert result.verdict is Verdict.VALID
    assert bot.called

    req = bot.calls.last.request
    assert req.url.host == "api.notion.com"
    assert req.url.path == "/v1/users/me"
    assert req.headers["Authorization"] == f"Bearer {FAKE_KEY}"
    assert req.headers["Notion-Version"] == "2022-06-28"

    identity = result.rungs[0]
    assert identity.name == "bot-user"
    assert identity.tier is ProbeTier.SAFE
    assert identity.evidence["owner_type"] == "workspace"
    assert identity.evidence["workspace_name"] == "Acme"


@respx.mock
async def test_dead_token_is_denied_and_stops_early() -> None:
    bot = respx.get("https://api.notion.com/v1/users/me").mock(
        return_value=httpx.Response(401, json={"object": "error", "status": 401})
    )
    users = respx.get("https://api.notion.com/v1/users").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    result = await notion.notion_ladder(_finding(raw="secret_dead"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["bot-user"]
    assert bot.called
    assert not users.called


@respx.mock
async def test_gated_reads_blocked_without_consent_make_no_call() -> None:
    respx.get("https://api.notion.com/v1/users/me").mock(
        return_value=httpx.Response(200, json={"id": "bot-1", "bot": {}})
    )
    users_route = respx.get("https://api.notion.com/v1/users").mock(
        return_value=httpx.Response(200, json={"results": [{"type": "person"}]})
    )
    search_route = respx.post("https://api.notion.com/v1/search").mock(
        return_value=httpx.Response(200, json={"results": [{"object": "page"}]})
    )

    result = await notion.notion_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    for name in ("list-users", "search-shared-content"):
        rung = next(r for r in result.rungs if r.name == name)
        assert rung.tier is ProbeTier.GATED
        assert rung.blocked is True
        assert rung.success is False
    assert not users_route.called
    assert not search_route.called


@respx.mock
async def test_full_consent_fires_gated_reads_to_proven() -> None:
    respx.get("https://api.notion.com/v1/users/me").mock(
        return_value=httpx.Response(200, json={"id": "bot-1", "bot": {}})
    )
    users_route = respx.get("https://api.notion.com/v1/users").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"type": "person", "name": "Jane", "person": {"email": "jane@victim.example"}},
                    {"type": "bot", "name": "Bot"},
                ]
            },
        )
    )
    search_route = respx.post("https://api.notion.com/v1/search").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"object": "page"}, {"object": "database"}], "has_more": True},
        )
    )

    result = await notion.notion_ladder(_finding(), FULL_CONSENT)

    assert users_route.called
    assert search_route.called
    assert result.verdict is Verdict.PROVEN

    users = next(r for r in result.rungs if r.name == "list-users")
    assert users.success is True
    assert users.evidence["user_count"] == 2
    assert users.evidence["person_count"] == 1
    # Member emails are never recorded.
    assert "jane@victim.example" not in repr(users.evidence)

    search = next(r for r in result.rungs if r.name == "search-shared-content")
    assert search.success is True
    assert search.evidence["sample_count"] == 2
    assert search.evidence["object_types"] == ["database", "page"]
    assert search.evidence["has_more"] is True


@respx.mock
async def test_gated_probes_raise_without_consent() -> None:
    with pytest.raises(GatedProbeBlocked):
        await notion._notion_list_users(SAFE_CONSENT, FAKE_KEY)
    with pytest.raises(GatedProbeBlocked):
        await notion._notion_search_shared_content(SAFE_CONSENT, FAKE_KEY)


def test_gated_probes_tagged_gated() -> None:
    assert notion._notion_list_users.__vtx_tier__ is ProbeTier.GATED
    assert notion._notion_search_shared_content.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.get("https://api.notion.com/v1/users/me").mock(
        return_value=httpx.Response(200, json={"id": "bot-1", "bot": {}})
    )
    result = await notion.notion_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Notion") is notion.notion_ladder
    assert get_ladder("notion") is notion.notion_ladder
