"""Snowflake capability ladder — prove depth of access from a leaked credential.

A TruffleHog ``Snowflake`` finding is **multipart**: an account identifier plus
a username and password. It is NOT a single standalone-recognizable token, so
routing is via the ``Snowflake`` detector and ``key_regex`` is empty. Crucially,
the Snowflake SQL API and resource-management REST API authenticate with a
**KEYPAIR_JWT** generated from a private key that is *not present* in the raw
credential. vtx-recon therefore cannot mint that JWT, and every rung's URL or
headers reference placeholders the engine cannot fill (``{account}``, ``{jwt}``).

Per the manual-rung rule, that means **every rung is MANUAL**: no rung issues a
live call. Each rung instead emits a copy-pasteable, safe ``curl`` an operator
can run by hand once they have produced a KEYPAIR_JWT, with the secret kept as a
``$JWT`` placeholder so nothing sensitive is ever stored.

Rungs (ordered, identity first):

#. ``whoami-current-user`` — SAFE/MANUAL. ``POST /api/v2/statements`` running
   ``SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()`` — a SELECT-only
   identity probe, no state change, non-billable.
#. ``list-databases`` — SAFE/MANUAL. ``GET /api/v2/databases`` enumerates every
   database the role can see (reachable data surface). Read-only, idempotent,
   non-billable.
#. ``exfil-table-data`` — GATED/MANUAL. ``POST /api/v2/statements`` running
   ``SELECT * FROM <db>.<schema>.<table> LIMIT N`` — reads warehouse-stored
   business/customer data (third-party PII risk) and spins billable compute.
   Routed through :func:`vtx_recon.safety.gated` so it is structurally
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

__all__ = ["snowflake_ladder"]


# --------------------------------------------------------------------------- #
# safe-curl rendering (no live call is ever made by this provider)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(method: str, url: str, headers: dict[str, str], body: str | None = None) -> str:
    """Build a copy-pasteable curl with the JWT kept as a ``$JWT`` placeholder.

    The account is left as the ``{account}`` placeholder the operator must
    substitute. The string never contains a live secret, so it is safe to print
    and to store.
    """
    parts = ["curl", "-sS", "-X", method]
    for header_name, header_value in headers.items():
        parts.extend(["-H", _shquote(f"{header_name}: {header_value}")])
    if body is not None:
        parts.extend(["--data", _shquote(body)])
    parts.append(_shquote(url))
    return " ".join(parts)


# Shared header sets. ``$JWT`` is a placeholder — the engine cannot mint the
# KEYPAIR_JWT from the raw credential, so it is never replaced with a secret.
_STATEMENTS_HEADERS = {
    "Authorization": "Bearer $JWT",
    "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

_REST_HEADERS = {
    "Authorization": "Bearer $JWT",
    "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
    "Accept": "application/json",
}


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID.
    * Nothing succeeded -> DENIED.

    NOTE: every Snowflake rung is manual and never makes a live call, so no rung
    is ever ``success=True``. The verdict is therefore always DENIED — the
    ladder cannot prove live access without an out-of-band KEYPAIR_JWT.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# rung 1 — SAFE / MANUAL: whoami-current-user
# --------------------------------------------------------------------------- #


def _snowflake_whoami() -> ProbeResult:
    """SAFE/MANUAL: ``POST /api/v2/statements`` running
    ``SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()``.

    Confirms identity and effective role. SELECT-only context query, no state
    change, non-billable. MANUAL because it needs a KEYPAIR_JWT not present in
    the raw credential and an ``{account}`` URL placeholder — no live call is
    made; the operator is handed the exact safe curl.
    """
    name = "whoami-current-user"
    url = "https://{account}.snowflakecomputing.com/api/v2/statements"
    body = '{"statement":"SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()","timeout":60}'
    curl = _safe_curl("POST", url, _STATEMENTS_HEADERS, body)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs a KEYPAIR_JWT (not in the raw credential) and the "
            f"{{account}} host; run this by hand to confirm identity/role: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE / MANUAL: list-databases
# --------------------------------------------------------------------------- #


def _snowflake_list_databases() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/v2/databases`` — resource-management REST API
    enumerating every database the role can see (reachable data surface /
    depth). Read-only, idempotent, non-billable. MANUAL (KEYPAIR_JWT +
    ``{account}``); no live call is made — the operator is handed the safe curl.
    """
    name = "list-databases"
    url = "https://{account}.snowflakecomputing.com/api/v2/databases"
    curl = _safe_curl("GET", url, _REST_HEADERS)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs a KEYPAIR_JWT (not in the raw credential) and the "
            f"{{account}} host; run this by hand to enumerate visible databases: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 3 — GATED / MANUAL: exfil-table-data (billable PII read)
# --------------------------------------------------------------------------- #


@gated
async def _snowflake_exfil_table_data(consent: Consent) -> ProbeResult:
    """GATED/MANUAL: ``POST /api/v2/statements`` running
    ``SELECT * FROM <db>.<schema>.<table> LIMIT N``.

    Reads warehouse-stored business/customer data (third-party PII risk) and
    spins billable compute. Decorated with :func:`vtx_recon.safety.gated`: the
    safety boundary runs *before* this body, so without BOTH ``--prove`` and an
    authorized scope it raises :class:`GatedProbeBlocked` and nothing is
    rendered as runnable. Even with consent it is MANUAL — the engine cannot
    mint the JWT or fill the ``{account}``/``<db>.<schema>.<table>``
    placeholders, so it returns the safe curl rather than firing.
    """
    del consent  # consumed by the @gated boundary; no live call is made
    name = "exfil-table-data"
    url = "https://{account}.snowflakecomputing.com/api/v2/statements"
    body = '{"statement":"SELECT * FROM <db>.<schema>.<table> LIMIT 10","timeout":60}'
    curl = _safe_curl("POST", url, _STATEMENTS_HEADERS, body)
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would read warehouse data and spin billable compute. "
            "Needs a KEYPAIR_JWT and {account}/<db>.<schema>.<table>; run by hand "
            f"only when authorized: {curl}"
        ),
        evidence={"manual": True, "billable": True, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("Snowflake")
async def snowflake_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Snowflake capability ladder for one finding.

    Refuses to ladder without an authorized scope. Every rung is MANUAL (no
    live call): the SAFE rungs always render their safe curl; the GATED rung is
    reached only through the safety boundary — when consent is missing it is
    recorded as a blocked rung, when consent is present it still only renders a
    safe curl.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE/MANUAL): identity. Manual rungs always render, so subsequent
    # rungs are not gated on a (never-true) success — the operator gets the full
    # hand-run plan.
    rungs.append(_snowflake_whoami())
    # Rung 2 (SAFE/MANUAL): reachable database surface.
    rungs.append(_snowflake_list_databases())

    # Rung 3 (GATED/MANUAL): billable PII read. Reachable only via the @gated
    # wrapper; without full consent it raises GatedProbeBlocked, recorded as a
    # blocked rung (the safe curl is still surfaced as evidence). The ladder
    # never raises across its public boundary.
    exfil_body = '{"statement":"SELECT * FROM <db>.<schema>.<table> LIMIT 10","timeout":60}'
    exfil_curl = _safe_curl(
        "POST",
        "https://{account}.snowflakecomputing.com/api/v2/statements",
        _STATEMENTS_HEADERS,
        exfil_body,
    )
    try:
        rungs.append(await _snowflake_exfil_table_data(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="exfil-table-data",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "reason": blocked.reason,
                    "manual": True,
                    "billable": True,
                    "safe_curl": exfil_curl,
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="snowflake",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
