"""Discord capability ladder — prove depth of access for a leaked bot token.

Handles TruffleHog ``DiscordBotToken`` (and ``Discord``/``DiscordWebhook``)
findings. A Discord bot token authenticates with the non-standard
``Authorization: Bot <token>`` scheme against the v10 REST API.

The ordered ladder (depth of access, least -> most revealing):

  1. ``discord.users.me``      ``GET /users/@me`` — confirms the token and
     reveals the bot's identity (id, username). Decides VALID vs DENIED.
  2. ``discord.guilds``        ``GET /users/@me/guilds?limit=200`` — enumerates
     the guilds (servers) the bot has joined — reach into the estate. Read-only;
     we keep only the guild count and names.
  3. ``discord.channel.history`` ``GET /channels/{channel_id}/messages`` — GATED.
     Reading message content is third-party PII; needs a ``{channel_id}`` the
     engine cannot fill, so it is a MANUAL safe-curl note (never auto-fired).
  4. ``discord.channel.send``  ``POST /channels/{channel_id}/messages`` — GATED,
     state-changing (sends a message). Needs a ``{channel_id}``, so it is a
     MANUAL safe-curl note (never auto-fired).

Every live rung is READ-ONLY, the ladder never raises across the public
boundary, and the raw token never lands in evidence.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "discord_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("DiscordBotToken", "Discord", "DiscordWebhook")

API_BASE = "https://discord.com/api/v10"

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)


def _network_failure(name: str, tier: ProbeTier, exc: Exception) -> ProbeResult:
    """Turn an httpx/transport error into a non-success rung (never raise)."""
    return ProbeResult(
        name=name,
        tier=tier,
        success=False,
        detail=f"probe could not complete: {type(exc).__name__}",
        evidence={"error": type(exc).__name__},
    )


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


def _bot_auth(token: str) -> dict[str, str]:
    """Discord bot auth header — note the ``Bot`` scheme, not ``Bearer``."""
    return {"Authorization": f"Bot {token}"}


@register("DiscordBotToken", "Discord", "DiscordWebhook")
async def discord_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Discord capability ladder for one finding.

    Refuses to ladder without an authorized scope. Climbs ``users/@me`` first
    and only enumerates guilds if the token authenticated. The message-reading
    and message-sending rungs are GATED and, because their URLs need a
    ``{channel_id}`` the engine cannot fill, are emitted as manual safe-curl
    notes rather than live calls. Never raises across the boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    token = finding.raw

    # --- Rung 1: users/@me (SAFE) — decides live/dead ------------------------
    identity = await _discord_users_me(token)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: guilds (SAFE) -------------------------------------------
        rungs.append(await _discord_guilds(token))

        # --- Rung 3: channel history (GATED, manual safe-curl) ---------------
        rungs.append(await _maybe_read_history(consent))

        # --- Rung 4: channel send (GATED, manual safe-curl) ------------------
        rungs.append(await _maybe_send_message(consent))

    return LadderResult(
        finding=finding,
        provider="discord",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _discord_users_me(token: str) -> ProbeResult:
    """SAFE: ``GET /users/@me`` confirms the bot token and returns its identity."""
    name = "discord.users.me"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{API_BASE}/users/@me", headers=_bot_auth(token))
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"token rejected (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"authenticated as bot {body.get('username') or '?'} (id {body.get('id') or '?'})",
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "username": body.get("username"),
            "bot": body.get("bot"),
        },
    )


async def _discord_guilds(token: str) -> ProbeResult:
    """SAFE: ``GET /users/@me/guilds`` enumerates the guilds the bot reaches."""
    name = "discord.guilds"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/users/@me/guilds",
                headers=_bot_auth(token),
                params={"limit": "200"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list guilds (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    guilds = body if isinstance(body, list) else []
    # Record only non-sensitive identifiers (guild names), never member data.
    names = [g.get("name") for g in guilds if isinstance(g, dict) and g.get("name")]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"{len(names)} guild(s) reachable: {', '.join(names[:5])}"
            if names
            else "no guilds reachable"
        ),
        evidence={
            "status": resp.status_code,
            "guild_count": len(names),
            "guilds_sample": names[:25],
        },
    )


# --- gated (manual) rungs ----------------------------------------------------


def _read_history_safe_curl() -> str:
    """Safe curl for the manual gated channel-history read (secret as $KEY)."""
    return (
        "curl -X GET "
        f"'{API_BASE}/channels/CHANNEL_ID/messages?limit=10' "
        '-H "Authorization: Bot $KEY"'
    )


def _send_message_safe_curl() -> str:
    """Safe curl for the manual gated channel-send (secret as $KEY)."""
    return (
        "curl -X POST "
        f"'{API_BASE}/channels/CHANNEL_ID/messages' "
        '-H "Authorization: Bot $KEY" '
        '-H "Content-Type: application/json" '
        '--data \'{"content":"vtx-recon authorized probe"}\''
    )


@gated
async def discord_gated_read_history(consent: Consent) -> ProbeResult:
    """GATED: ``GET /channels/{channel_id}/messages`` reads message content (PII).

    MANUAL because the URL needs a ``{channel_id}`` the engine cannot fill, so
    it never auto-fires — only returns a safe curl.
    """
    return ProbeResult(
        name="discord.channel.history",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: reads channel message content (PII); needs a channel_id; "
            "run the safe curl by hand to exercise the read"
        ),
        evidence={"manual": True, "safe_curl": _read_history_safe_curl()},
    )


@gated
async def discord_gated_send_message(consent: Consent) -> ProbeResult:
    """GATED: ``POST /channels/{channel_id}/messages`` sends a message.

    State-changing impact. MANUAL because its body needs a ``{channel_id}``, so
    it never auto-fires.
    """
    return ProbeResult(
        name="discord.channel.send",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: sends a message (state-changing); needs a channel_id; "
            "run the safe curl by hand to exercise the impact"
        ),
        evidence={"manual": True, "safe_curl": _send_message_safe_curl()},
    )


async def _maybe_read_history(consent: Consent) -> ProbeResult:
    """Attempt the gated history read; report it as blocked when consent absent."""
    try:
        return await discord_gated_read_history(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="discord.channel.history",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _read_history_safe_curl(),
            },
        )


async def _maybe_send_message(consent: Consent) -> ProbeResult:
    """Attempt the gated message send; report it as blocked when consent absent."""
    try:
        return await discord_gated_send_message(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="discord.channel.send",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _send_message_safe_curl(),
            },
        )
