"""Zendesk capability ladder — prove depth of access from a leaked API token.

Handles the TruffleHog ``ZendeskApi`` finding: a 40-char API token used with
Zendesk **Basic auth**. The wire credential is ``Basic base64(email/token:apitoken)``
— i.e. the account email and the literal ``/token`` suffix are combined with the
API token, then base64-encoded. Two values needed to authenticate are *not*
present in the raw token:

* the **subdomain** (``{subdomain}.zendesk.com``) — which Zendesk instance, and
* the **account email** — the first half of the ``email/token:apitoken`` pair.

Because every rung's URL embeds ``{subdomain}`` and every header embeds the
account email, the engine cannot fill those placeholders. Per the manual-rung
rule that makes **every rung MANUAL**: no rung issues a live call. Each rung
instead emits a copy-pasteable, safe ``curl`` an operator can run by hand once
they know the subdomain + email, with the secret kept as a ``$KEY`` placeholder
(and the email as ``$EMAIL``) so nothing sensitive is ever stored.

Ordered ladder (identity first, then depth):

#. ``current-user`` — SAFE/MANUAL. ``GET /api/v2/users/me.json`` returns the
   authenticated user (role, email, org) — identity / whoami. Read-only,
   non-billable.
#. ``list-users`` — SAFE/MANUAL. ``GET /api/v2/users.json`` lists agents /
   end-users reachable by the token — confirms account-wide read depth.
   Read-only, non-billable.
#. ``list-tickets`` — GATED/MANUAL. ``GET /api/v2/tickets.json`` reads support
   tickets — third-party customer PII and conversation content. The impact the
   program cares about; read-only but GATED because it exfiltrates customer
   data. Routed through :func:`vtx_recon.safety.gated` so it is structurally
   unreachable without BOTH ``--prove`` and ``--i-am-authorized "<scope>"``;
   even when consent is granted it never auto-fires (placeholders cannot be
   filled) — it renders the safe curl for the operator.

The ladder never raises across its public boundary: every failure becomes a
:class:`ProbeResult`. Secrets are never persisted; only non-secret values land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["zendesk_ladder"]


# --------------------------------------------------------------------------- #
# safe-curl rendering (no live call is ever made by this provider)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(method: str, url: str) -> str:
    """Build a copy-pasteable curl for a Zendesk Basic-auth call.

    The token is kept as a ``$KEY`` placeholder and the account email as
    ``$EMAIL``; the subdomain is left as the ``{subdomain}`` placeholder the
    operator must substitute. The string never contains a live secret, so it is
    safe to print and to store.
    """
    parts = ["curl", "-sS", "-X", method]
    # Zendesk Basic auth is `email/token:apitoken`; -u renders it without us ever
    # base64-encoding (let curl do it) and keeps both secrets as shell vars.
    parts.extend(["-u", _shquote("$EMAIL/token:$KEY")])
    parts.extend(["-H", _shquote("Accept: application/json")])
    parts.append(_shquote(url))
    return " ".join(parts)


# The list-tickets URL (embeds the {subdomain} placeholder the engine cannot fill).
_LIST_TICKETS_URL = "https://{subdomain}.zendesk.com/api/v2/tickets.json?page[size]=5"


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID.
    * Nothing succeeded -> DENIED.

    NOTE: every Zendesk rung is manual and never makes a live call, so no rung
    is ever ``success=True``. The verdict is therefore always DENIED — the
    ladder cannot prove live access without the out-of-band subdomain + account
    email.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# rung 1 — SAFE / MANUAL: current-user (identity / whoami)
# --------------------------------------------------------------------------- #


def _zendesk_current_user() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/v2/users/me.json`` returns the authenticated user
    (role, email, org) — identity / whoami.

    Read-only, non-billable. MANUAL because it needs the ``{subdomain}`` host and
    the account email (not in the raw token), so no live call is made — the
    operator is handed the exact safe curl.
    """
    name = "current-user"
    url = "https://{subdomain}.zendesk.com/api/v2/users/me.json"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {subdomain} host and account email (Basic "
            "email/token:apitoken; not in the raw token); run this by hand to "
            f"confirm identity/role: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE / MANUAL: list-users (account-wide read depth)
# --------------------------------------------------------------------------- #


def _zendesk_list_users() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/v2/users.json`` lists agents / end-users reachable
    by the token — confirms account-wide read depth.

    Read-only, idempotent, non-billable. MANUAL (needs ``{subdomain}`` + account
    email); no live call is made — the operator is handed the safe curl.
    """
    name = "list-users"
    url = "https://{subdomain}.zendesk.com/api/v2/users.json?page[size]=10"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {subdomain} host + account email + token; run this "
            f"by hand to enumerate reachable agents/end-users (read depth): {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 3 — GATED / MANUAL: list-tickets (customer PII read)
# --------------------------------------------------------------------------- #


@gated
async def _zendesk_list_tickets(consent: Consent) -> ProbeResult:
    """GATED/MANUAL: ``GET /api/v2/tickets.json`` reads support tickets —
    third-party customer PII and conversation content.

    The impact the program cares about; read-only but GATED because it
    exfiltrates customer data. Decorated with :func:`vtx_recon.safety.gated`: the
    safety boundary runs *before* this body, so without BOTH ``--prove`` and an
    authorized scope it raises :class:`GatedProbeBlocked` and nothing is rendered
    as runnable. Even with consent it is MANUAL — the engine cannot fill the
    ``{subdomain}`` host or supply the account email, so it returns the safe curl
    rather than firing.
    """
    name = "list-tickets"
    curl = _safe_curl("GET", _LIST_TICKETS_URL)
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would read support tickets (third-party customer PII and "
            "conversation content). Needs the {subdomain} host + account email + "
            f"token; run by hand only when authorized: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("ZendeskApi")
async def zendesk_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Zendesk capability ladder for one finding.

    Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
    call): the SAFE rungs always render their safe curl; the GATED rung is
    reached only through the safety boundary — when consent is missing it is
    recorded as a blocked rung, when consent is present it still only renders a
    safe curl.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE/MANUAL): identity. Manual rungs always render, so subsequent
    # rungs are not gated on a (never-true) success — the operator gets the full
    # hand-run plan.
    rungs.append(_zendesk_current_user())
    # Rung 2 (SAFE/MANUAL): account-wide read depth.
    rungs.append(_zendesk_list_users())

    # Rung 3 (GATED/MANUAL): customer-PII read. Reachable only via the @gated
    # wrapper; without full consent it raises GatedProbeBlocked, recorded as a
    # blocked rung (the safe curl is still surfaced as evidence). The ladder
    # never raises across its public boundary.
    tickets_curl = _safe_curl("GET", _LIST_TICKETS_URL)
    try:
        rungs.append(await _zendesk_list_tickets(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="list-tickets",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "reason": blocked.reason,
                    "manual": True,
                    "billable": False,
                    "safe_curl": tickets_curl,
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="zendesk",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
