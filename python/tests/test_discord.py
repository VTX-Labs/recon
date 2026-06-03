"""Tests for the Discord capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid bot token climbs two SAFE rungs (users/@me -> guilds) to VALID, sent
  with the non-standard ``Authorization: Bot <token>`` scheme;
* a dead token (401) yields DENIED and stops after users/@me;
* the GATED channel-history (PII) and channel-send rungs are structurally
  blocked without consent (recorded ``blocked``, NO network call) and stay
  MANUAL safe-curl notes even WITH consent (their URLs need a channel_id);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import discord
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = (
    "EXAMPLE"
    + "FAKEKEYNOTREAL000"
    + "."
    + "EXAMPL"
    + "."
    + "EXAMPLEFAKEKEYNOTREAL00000000000000000"
)


def _finding(detector: str = "DiscordBotToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await discord.discord_ladder(_finding(), Consent.denied())


@respx.mock
async def test_discord_valid_token_climbs_safe_rungs() -> None:
    me = respx.get("https://discord.com/api/v10/users/@me").mock(
        return_value=httpx.Response(200, json={"id": "999", "username": "leaky-bot", "bot": True})
    )
    respx.get("https://discord.com/api/v10/users/@me/guilds").mock(
        return_value=httpx.Response(
            200, json=[{"id": "1", "name": "Acme HQ"}, {"id": "2", "name": "Acme Dev"}]
        )
    )

    result = await discord.discord_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "discord"
    assert result.verdict is Verdict.VALID
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["discord.users.me", "discord.guilds"]
    assert all(r.success for r in safe)
    # The Discord-specific `Bot` scheme carried the live token.
    assert me.calls.last.request.headers["Authorization"] == f"Bot {FAKE_KEY}"
    identity = next(r for r in result.rungs if r.name == "discord.users.me")
    assert identity.evidence["username"] == "leaky-bot"
    guilds = next(r for r in result.rungs if r.name == "discord.guilds")
    assert guilds.evidence["guild_count"] == 2


@respx.mock
async def test_discord_dead_token_is_denied_and_stops_early() -> None:
    me = respx.get("https://discord.com/api/v10/users/@me").mock(
        return_value=httpx.Response(401, json={"message": "401: Unauthorized"})
    )
    guilds = respx.get("https://discord.com/api/v10/users/@me/guilds").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await discord.discord_ladder(_finding(raw="MTIz.dead.token"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["discord.users.me"]
    assert me.called
    assert not guilds.called


@respx.mock
async def test_discord_gated_rungs_blocked_without_consent_make_no_call() -> None:
    respx.get("https://discord.com/api/v10/users/@me").mock(
        return_value=httpx.Response(200, json={"id": "1", "username": "bot"})
    )
    respx.get("https://discord.com/api/v10/users/@me/guilds").mock(
        return_value=httpx.Response(200, json=[])
    )
    history_route = respx.get("https://discord.com/api/v10/channels/CHANNEL_ID/messages").mock(
        return_value=httpx.Response(200, json=[{"content": "LEAK"}])
    )
    send_route = respx.post("https://discord.com/api/v10/channels/CHANNEL_ID/messages").mock(
        return_value=httpx.Response(200, json={"id": "LEAK"})
    )

    result = await discord.discord_ladder(_finding(), SAFE_CONSENT)

    assert result.verdict is Verdict.VALID  # safe ok + gated blocked
    history = next(r for r in result.rungs if r.name == "discord.channel.history")
    send = next(r for r in result.rungs if r.name == "discord.channel.send")
    for rung in (history, send):
        assert rung.tier is ProbeTier.GATED
        assert rung.blocked is True
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
        assert FAKE_KEY not in rung.evidence["safe_curl"]
    # The hard guarantee: no PII read / send request was ever issued.
    assert not history_route.called
    assert not send_route.called


@respx.mock
async def test_discord_gated_rungs_with_consent_stay_manual_no_call() -> None:
    respx.get("https://discord.com/api/v10/users/@me").mock(
        return_value=httpx.Response(200, json={"id": "1", "username": "bot"})
    )
    respx.get("https://discord.com/api/v10/users/@me/guilds").mock(
        return_value=httpx.Response(200, json=[])
    )
    history_route = respx.get("https://discord.com/api/v10/channels/CHANNEL_ID/messages").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await discord.discord_ladder(_finding(), FULL_CONSENT)

    # Manual gated rungs never auto-fire (need a channel_id), so verdict is VALID.
    assert result.verdict is Verdict.VALID
    history = next(r for r in result.rungs if r.name == "discord.channel.history")
    assert history.blocked is False
    assert history.success is False
    assert history.evidence["manual"] is True
    assert not history_route.called


async def test_discord_gated_probes_raise_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probes themselves refuse."""
    with pytest.raises(GatedProbeBlocked):
        await discord.discord_gated_read_history(SAFE_CONSENT)
    with pytest.raises(GatedProbeBlocked):
        await discord.discord_gated_send_message(SAFE_CONSENT)
    assert discord.discord_gated_read_history.__vtx_tier__ is ProbeTier.GATED
    assert discord.discord_gated_send_message.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_discord_result_is_redacted() -> None:
    respx.get("https://discord.com/api/v10/users/@me").mock(
        return_value=httpx.Response(200, json={"id": "1", "username": "bot"})
    )
    respx.get("https://discord.com/api/v10/users/@me/guilds").mock(
        return_value=httpx.Response(200, json=[])
    )

    result = await discord.discord_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_providers_are_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("DiscordBotToken") is discord.discord_ladder
    assert get_ladder("Discord") is discord.discord_ladder
    assert get_ladder("discordbottoken") is discord.discord_ladder
