"""Slack capability ladder — prove depth of access for a leaked Slack token.

Handles TruffleHog ``Slack`` and ``SlackWebhook`` findings. A Slack bot/user
token (``xox...``) authenticates with ``Authorization: Bearer <token>`` against
the Web API, which answers ``{"ok": true|false, ...}`` with HTTP 200 even on
auth failure — so each rung inspects the ``ok`` flag, not the status code.

The ordered ladder (depth of access, least -> most revealing):

  1. ``slack.auth.test``            ``POST auth.test`` — confirms the token and
     reveals the team / user it belongs to. Decides VALID vs DENIED.
  2. ``slack.conversations.list``   ``GET conversations.list`` — channels
     reachable (workspace topology). Read-only enumeration of metadata.
  3. ``slack.users.list``           ``GET users.list`` — directory reachable
     (member count). Read-only; we keep only the count, never the roster.
  4. ``slack.files.list``           ``GET files.list`` — files reachable (file
     count). Read-only; we keep only the count, never file contents.
  5. ``slack.conversations.history`` ``GET conversations.history`` — GATED.
     Reading message content is third-party PII; needs a ``{channel_id}`` the
     engine cannot fill, so it is a MANUAL safe-curl note (never auto-fired).
  6. ``slack.chat.postMessage``     ``POST chat.postMessage`` — GATED,
     state-changing (sends a message). Needs a ``{channel_id}``, so it is a
     MANUAL safe-curl note (never auto-fired).

Every rung is ordered (identity first, then depth), the live rungs are all
READ-ONLY, and the ladder never raises across the public boundary: failures
become a :class:`ProbeResult` with ``success=False`` so one dead key cannot
crash a batch run. The raw token is held only transiently for the HTTP call and
never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "slack_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Slack", "SlackWebhook")

API_BASE = "https://slack.com/api"

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


def _bearer(token: str) -> dict[str, str]:
    """Standard Slack bearer header for a bot/user token."""
    return {"Authorization": f"Bearer {token}"}


@register("Slack", "SlackWebhook")
async def slack_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Slack capability ladder for one finding.

    Refuses to ladder without an authorized scope. Climbs ``auth.test`` first
    and only descends into the deeper SAFE rungs if the token authenticated.
    The message-reading and message-sending rungs are GATED and, because their
    URLs need a ``{channel_id}`` the engine cannot fill, are emitted as manual
    safe-curl notes rather than live calls. Never raises across the boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    token = finding.raw

    # --- Rung 1: auth.test (SAFE) — decides live/dead ------------------------
    identity = await _slack_auth_test(token)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: conversations.list (SAFE) -------------------------------
        rungs.append(await _slack_conversations_list(token))

        # --- Rung 3: users.list (SAFE) ---------------------------------------
        rungs.append(await _slack_users_list(token))

        # --- Rung 4: files.list (SAFE) ---------------------------------------
        rungs.append(await _slack_files_list(token))

        # --- Rung 5: conversations.history (GATED, manual safe-curl) ---------
        rungs.append(await _maybe_read_history(consent))

        # --- Rung 6: chat.postMessage (GATED, manual safe-curl) --------------
        rungs.append(await _maybe_post_message(consent))

    return LadderResult(
        finding=finding,
        provider="slack",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _slack_auth_test(token: str) -> ProbeResult:
    """SAFE: ``POST auth.test`` confirms the token and returns team/user ids."""
    name = "slack.auth.test"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{API_BASE}/auth.test", headers=_bearer(token))
            body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if not body.get("ok"):
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"token rejected: {body.get('error', 'not_authed')}",
            evidence={"status": resp.status_code, "error": body.get("error")},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"authenticated as {body.get('user')} on team {body.get('team')}",
        evidence={
            "status": resp.status_code,
            "team": body.get("team"),
            "team_id": body.get("team_id"),
            "user": body.get("user"),
            "user_id": body.get("user_id"),
        },
    )


async def _slack_get(
    name: str, method: str, token: str, params: dict[str, str]
) -> dict | ProbeResult:
    """Shared SAFE GET helper.

    Returns the parsed body on ``{"ok": true}``, or a non-success
    :class:`ProbeResult` on transport failure / bad JSON / ``ok:false``.
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{API_BASE}/{method}", headers=_bearer(token), params=params)
            body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if not body.get("ok"):
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"not reachable: {body.get('error', 'error')}",
            evidence={"status": resp.status_code, "error": body.get("error")},
        )
    return body


async def _slack_conversations_list(token: str) -> ProbeResult:
    """SAFE: ``GET conversations.list`` — channels reachable (topology)."""
    name = "slack.conversations.list"
    body = await _slack_get(
        name,
        "conversations.list",
        token,
        {"limit": "200", "types": "public_channel,private_channel"},
    )
    if isinstance(body, ProbeResult):
        return body

    channels = body.get("channels") if isinstance(body.get("channels"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"{len(channels)} channel(s) reachable",
        evidence={"status": 200, "channel_count": len(channels)},
    )


async def _slack_users_list(token: str) -> ProbeResult:
    """SAFE: ``GET users.list`` — directory reachable (member count only)."""
    name = "slack.users.list"
    body = await _slack_get(name, "users.list", token, {"limit": "200"})
    if isinstance(body, ProbeResult):
        return body

    members = body.get("members") if isinstance(body.get("members"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"{len(members)} directory member(s) reachable",
        evidence={"status": 200, "member_count": len(members)},
    )


async def _slack_files_list(token: str) -> ProbeResult:
    """SAFE: ``GET files.list`` — files reachable (file count only)."""
    name = "slack.files.list"
    body = await _slack_get(name, "files.list", token, {"count": "200"})
    if isinstance(body, ProbeResult):
        return body

    files = body.get("files") if isinstance(body.get("files"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"{len(files)} file(s) reachable",
        evidence={"status": 200, "file_count": len(files)},
    )


# --- gated (manual) rungs ----------------------------------------------------


def _read_history_safe_curl() -> str:
    """Safe curl for the manual gated history read (secret as $KEY)."""
    return (
        "curl -X GET "
        f"'{API_BASE}/conversations.history?channel=CHANNEL_ID&limit=10' "
        '-H "Authorization: Bearer $KEY"'
    )


def _post_message_safe_curl() -> str:
    """Safe curl for the manual gated message send (secret as $KEY)."""
    return (
        "curl -X POST "
        f"'{API_BASE}/chat.postMessage' "
        '-H "Authorization: Bearer $KEY" '
        '-H "Content-Type: application/json; charset=utf-8" '
        '--data \'{"channel":"CHANNEL_ID","text":"vtx-recon authorized probe"}\''
    )


@gated
async def slack_gated_read_history(consent: Consent) -> ProbeResult:
    """GATED: ``GET conversations.history`` reads live message content (PII).

    Decorated with :func:`vtx_recon.safety.gated`, so the safety boundary runs
    *before* this body; without consent it raises :class:`GatedProbeBlocked`.
    Even with consent this rung is MANUAL: the URL needs a ``{channel_id}`` the
    engine cannot fill, so it never fires a live request — it only returns a
    safe curl (secret kept as ``$KEY``).
    """
    return ProbeResult(
        name="slack.conversations.history",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: reads message content (PII); needs a channel_id from "
            "conversations.list; run the safe curl by hand to exercise the read"
        ),
        evidence={"manual": True, "safe_curl": _read_history_safe_curl()},
    )


@gated
async def slack_gated_post_message(consent: Consent) -> ProbeResult:
    """GATED: ``POST chat.postMessage`` sends a message — state-changing impact.

    MANUAL because its body needs a ``{channel_id}`` the engine cannot fill, so
    it never auto-fires.
    """
    return ProbeResult(
        name="slack.chat.postMessage",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: sends a message (state-changing); needs a channel_id; "
            "run the safe curl by hand to exercise the impact"
        ),
        evidence={"manual": True, "safe_curl": _post_message_safe_curl()},
    )


async def _maybe_read_history(consent: Consent) -> ProbeResult:
    """Attempt the gated history read; report it as blocked when consent absent."""
    try:
        return await slack_gated_read_history(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="slack.conversations.history",
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


async def _maybe_post_message(consent: Consent) -> ProbeResult:
    """Attempt the gated message send; report it as blocked when consent absent."""
    try:
        return await slack_gated_post_message(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="slack.chat.postMessage",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _post_message_safe_curl(),
            },
        )
