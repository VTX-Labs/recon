"""Pusher Channels capability ladder — prove depth of access from a leaked key.

A TruffleHog ``PusherChannelKey`` finding is the app's **public key** (the
20-char ``key``). On its own that key is NOT sufficient to call the Channels
HTTP API: every request to ``api-{cluster}.pusher.com`` must be **HMAC-SHA256
signed** with the paired app **SECRET**, and the signature plus
``auth_key``/``auth_timestamp``/``auth_version`` query params must be appended
to the URL (see
https://pusher.com/docs/channels/library_auth_reference/rest-api/). The signing
also needs the numeric ``app_id``. None of ``secret``, ``app_id``, or
``cluster`` are present in the raw finding, and every rung's URL carries the
``{cluster}``/``{app_id}`` placeholders the engine cannot fill.

Per the manual-rung rule, that means **every rung is MANUAL**: no rung issues a
live call. Each rung instead emits a copy-pasteable, safe ``curl`` an operator
can run by hand once they have recovered the paired secret + app_id and produced
the HMAC signature, with the key kept as a ``$KEY`` placeholder (and
``$SIGNATURE``/``$TIMESTAMP`` placeholders for the per-request HMAC) so nothing
sensitive is ever stored.

Rungs (ordered, identity / read first):

#. ``list-channels`` — SAFE/MANUAL. ``GET /apps/{app_id}/channels`` lists the
   app's occupied realtime channels (read-only). Proves the credential set
   reaches live app data. Non-billable.
#. ``channel-info`` — SAFE/MANUAL. ``GET /apps/{app_id}/channels/{channel_name}``
   reads a specific channel's attributes (occupancy, subscription count) — a
   deeper read into the app. Read-only, non-billable.
#. ``trigger-event`` — GATED/MANUAL. ``POST /apps/{app_id}/events`` publishes an
   event to all subscribers of a channel — state-changing, pushes arbitrary
   payloads to every connected client. Routed through
   :func:`vtx_recon.safety.gated` so it is structurally unreachable without BOTH
   ``--prove`` and ``--i-am-authorized "<scope>"``; even when consent is granted
   it never auto-fires (placeholders + HMAC cannot be filled) — it renders the
   safe curl for the operator.

The ladder never raises across its public boundary: every failure becomes a
:class:`ProbeResult`. Secrets are never persisted; only non-secret values land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["pusher_ladder"]


# --------------------------------------------------------------------------- #
# safe-curl rendering (no live call is ever made by this provider)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(method: str, url: str, headers: dict[str, str], body: str | None = None) -> str:
    """Build a copy-pasteable curl with the key kept as a ``$KEY`` placeholder.

    The per-request HMAC is kept as ``$SIGNATURE``/``$TIMESTAMP`` placeholders
    and the ``{cluster}``/``{app_id}`` URL placeholders are left for the operator
    to substitute. The string never contains a live secret, so it is safe to
    print and to store.
    """
    parts = ["curl", "-sS", "-X", method]
    for header_name, header_value in headers.items():
        parts.extend(["-H", _shquote(f"{header_name}: {header_value}")])
    if body is not None:
        parts.extend(["--data", _shquote(body)])
    parts.append(_shquote(url))
    return " ".join(parts)


# Every Pusher REST request must carry HMAC-SHA256 auth as query params.
# ``$KEY`` is the leaked public key; ``$TIMESTAMP`` and ``$SIGNATURE`` are the
# per-request HMAC the engine cannot compute (it needs the paired app SECRET).
_AUTH_QUERY = "auth_key=$KEY&auth_timestamp=$TIMESTAMP&auth_version=1.0&auth_signature=$SIGNATURE"


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID.
    * Nothing succeeded -> DENIED.

    NOTE: every Pusher rung is manual and never makes a live call, so no rung is
    ever ``success=True``. The verdict is therefore always DENIED — the ladder
    cannot prove live access without the out-of-band secret + app_id and a
    computed HMAC signature.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# rung 1 — SAFE / MANUAL: list-channels
# --------------------------------------------------------------------------- #


def _pusher_list_channels() -> ProbeResult:
    """SAFE/MANUAL: ``GET /apps/{app_id}/channels`` lists occupied channels.

    Lists the app's occupied realtime channels (read-only). Proves the
    credential set reaches live app data — confirms the key is for a real,
    reachable app. Non-billable. MANUAL because it needs the paired app SECRET
    to HMAC-sign the request (not in the raw finding) plus the
    ``{cluster}``/``{app_id}`` host/path placeholders — no live call is made;
    the operator is handed the exact safe curl.
    """
    name = "list-channels"
    url = f"https://api-{{cluster}}.pusher.com/apps/{{app_id}}/channels?{_AUTH_QUERY}"
    curl = _safe_curl("GET", url, {})
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the paired app SECRET to HMAC-sign (not in the raw "
            "finding) and the {cluster}/{app_id} host; run this by hand to list "
            f"occupied channels: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE / MANUAL: channel-info
# --------------------------------------------------------------------------- #


def _pusher_channel_info() -> ProbeResult:
    """SAFE/MANUAL: ``GET /apps/{app_id}/channels/{channel_name}`` reads a channel.

    Reads a specific channel's attributes (occupancy, subscription count) — a
    deeper read into the app's live state. Read-only, idempotent, non-billable.
    MANUAL (HMAC secret + ``{cluster}``/``{app_id}``/``{channel_name}``
    placeholders); no live call is made — the operator is handed the safe curl.
    """
    name = "channel-info"
    url = (
        "https://api-{cluster}.pusher.com/apps/{app_id}/channels/{channel_name}"
        f"?info=user_count,subscription_count&{_AUTH_QUERY}"
    )
    curl = _safe_curl("GET", url, {})
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the paired app SECRET to HMAC-sign and the "
            "{cluster}/{app_id}/{channel_name} host/path; run this by hand to "
            f"read a channel's occupancy/subscription count: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 3 — GATED / MANUAL: trigger-event (state-changing broadcast)
# --------------------------------------------------------------------------- #


@gated
async def _pusher_trigger_event(consent: Consent) -> ProbeResult:
    """GATED/MANUAL: ``POST /apps/{app_id}/events`` publishes an event.

    State-changing: pushes an arbitrary payload to every subscriber of a channel
    — the impact rung. Decorated with :func:`vtx_recon.safety.gated`: the safety
    boundary runs *before* this body, so without BOTH ``--prove`` and an
    authorized scope it raises :class:`GatedProbeBlocked` and nothing is rendered
    as runnable. Even with consent it is MANUAL — the engine cannot HMAC-sign
    with the secret or fill the ``{cluster}``/``{app_id}`` placeholders, so it
    returns the safe curl rather than firing.
    """
    name = "trigger-event"
    url = f"https://api-{{cluster}}.pusher.com/apps/{{app_id}}/events?{_AUTH_QUERY}"
    body = '{"name":"vtx-recon-probe","channels":["my-channel"],"data":"{\\"ping\\":1}"}'
    curl = _safe_curl("POST", url, {"Content-Type": "application/json"}, body)
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would broadcast an arbitrary event to every subscriber "
            "(state-changing). Needs the app SECRET to HMAC-sign and "
            f"{{cluster}}/{{app_id}}; run by hand only when authorized: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("PusherChannelKey")
async def pusher_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Pusher capability ladder for one finding.

    Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
    call): the SAFE rungs always render their safe curl; the GATED rung is
    reached only through the safety boundary — when consent is missing it is
    recorded as a blocked rung, when consent is present it still only renders a
    safe curl.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE/MANUAL): reachability — list occupied channels. Manual rungs
    # always render, so subsequent rungs are not gated on a (never-true) success
    # — the operator gets the full hand-run plan.
    rungs.append(_pusher_list_channels())
    # Rung 2 (SAFE/MANUAL): deeper read — a specific channel's attributes.
    rungs.append(_pusher_channel_info())

    # Rung 3 (GATED/MANUAL): state-changing broadcast. Reachable only via the
    # @gated wrapper; without full consent it raises GatedProbeBlocked, recorded
    # as a blocked rung (the safe curl is still surfaced as evidence). The ladder
    # never raises across its public boundary.
    trigger_body = '{"name":"vtx-recon-probe","channels":["my-channel"],"data":"{\\"ping\\":1}"}'
    trigger_curl = _safe_curl(
        "POST",
        f"https://api-{{cluster}}.pusher.com/apps/{{app_id}}/events?{_AUTH_QUERY}",
        {"Content-Type": "application/json"},
        trigger_body,
    )
    try:
        rungs.append(await _pusher_trigger_event(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="trigger-event",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "reason": blocked.reason,
                    "manual": True,
                    "billable": False,
                    "safe_curl": trigger_curl,
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="pusher",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
