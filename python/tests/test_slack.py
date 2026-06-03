"""Tests for the Slack capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs its SAFE rungs (auth.test -> conversations -> users ->
  files) to VALID, with real JSON evidence (team, channel/member/file counts);
* a dead token yields DENIED and stops after auth.test;
* the GATED history/post rungs are *structurally* blocked without consent — they
  are recorded ``blocked`` with a manual safe-curl and fire NO network request.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import slack
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")


def _finding(detector: str, raw: str) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await slack.slack_ladder(_finding("Slack", "xoxb-abc"), Consent.denied())


@respx.mock
async def test_slack_valid_token_climbs_safe_rungs() -> None:
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(
            200,
            json={
                "ok": True,
                "team": "Acme",
                "team_id": "T123",
                "user": "leaky-bot",
                "user_id": "U456",
            },
        )
    )
    respx.get("https://slack.com/api/conversations.list").mock(
        return_value=httpx.Response(
            200, json={"ok": True, "channels": [{"id": "C1"}, {"id": "C2"}]}
        )
    )
    respx.get("https://slack.com/api/users.list").mock(
        return_value=httpx.Response(
            200, json={"ok": True, "members": [{"id": "U1"}, {"id": "U2"}, {"id": "U3"}]}
        )
    )
    respx.get("https://slack.com/api/files.list").mock(
        return_value=httpx.Response(200, json={"ok": True, "files": [{"id": "F1"}]})
    )

    result = await slack.slack_ladder(_finding("Slack", "xoxb-valid"), SAFE_CONSENT)

    assert result.provider == "slack"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == "acme h1 program #4242"
    assert [r.name for r in result.rungs] == [
        "slack.auth.test",
        "slack.conversations.list",
        "slack.users.list",
        "slack.files.list",
        "slack.conversations.history",
        "slack.chat.postMessage",
    ]
    assert result.rungs[0].evidence["team_id"] == "T123"
    assert result.rungs[0].evidence["user_id"] == "U456"
    assert result.rungs[1].evidence["channel_count"] == 2
    assert result.rungs[2].evidence["member_count"] == 3
    assert result.rungs[3].evidence["file_count"] == 1


@respx.mock
async def test_slack_dead_token_is_denied_and_stops_early() -> None:
    auth_route = respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
    )
    channels_route = respx.get("https://slack.com/api/conversations.list").mock(
        return_value=httpx.Response(200, json={"ok": True, "channels": []})
    )

    result = await slack.slack_ladder(_finding("Slack", "xoxb-dead"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["slack.auth.test"]
    assert "invalid_auth" in result.rungs[0].detail
    assert auth_route.called
    assert not channels_route.called


@respx.mock
async def test_slack_gated_rungs_blocked_without_consent_make_no_call() -> None:
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(200, json={"ok": True, "team": "Acme", "user": "bot"})
    )
    respx.get("https://slack.com/api/conversations.list").mock(
        return_value=httpx.Response(200, json={"ok": True, "channels": []})
    )
    respx.get("https://slack.com/api/users.list").mock(
        return_value=httpx.Response(200, json={"ok": True, "members": []})
    )
    respx.get("https://slack.com/api/files.list").mock(
        return_value=httpx.Response(200, json={"ok": True, "files": []})
    )
    # If the boundary ever leaked, these would be hit. They must not be.
    history_route = respx.get("https://slack.com/api/conversations.history").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    post_route = respx.post("https://slack.com/api/chat.postMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    result = await slack.slack_ladder(_finding("Slack", "xoxb-valid"), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    history = next(r for r in result.rungs if r.name == "slack.conversations.history")
    post = next(r for r in result.rungs if r.name == "slack.chat.postMessage")
    for rung in (history, post):
        assert rung.tier is ProbeTier.GATED
        assert rung.blocked is True
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
    # The hard guarantee: no PII/send request was ever issued.
    assert not history_route.called
    assert not post_route.called


@respx.mock
async def test_slack_gated_probes_raise_when_called_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probes themselves refuse."""
    with pytest.raises(GatedProbeBlocked):
        await slack.slack_gated_read_history(SAFE_CONSENT)
    with pytest.raises(GatedProbeBlocked):
        await slack.slack_gated_post_message(SAFE_CONSENT)


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Slack") is slack.slack_ladder
    assert get_ladder("SlackWebhook") is slack.slack_ladder
    # Detector matching is case-insensitive.
    assert get_ladder("slack") is slack.slack_ladder


def test_slack_gated_probes_tagged_gated() -> None:
    assert slack.slack_gated_read_history.__vtx_tier__ is ProbeTier.GATED
    assert slack.slack_gated_post_message.__vtx_tier__ is ProbeTier.GATED
