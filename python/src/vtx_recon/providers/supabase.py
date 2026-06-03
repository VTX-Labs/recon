"""Capability ladder for Supabase service_role JWTs (``eyJ...``).

A Supabase finding is a long, three-segment JWT. The dangerous one is the
``service_role`` key: it bypasses Row-Level Security and can read every table
and every end-user account in the project. This module describes the depth of
access such a key grants — but every rung here is **manual**.

Why every rung is manual: the impact endpoints all live on the project's own
subdomain (``https://{ref}.supabase.co/...``) and the project ``ref`` is NOT
present in the raw JWT, so the engine cannot fill the ``{ref}`` placeholder
(and ``list-table-rows`` additionally needs a ``{table}`` name discovered from
the OpenAPI schema). Per the ladder conventions, a rung whose URL/headers carry
any placeholder other than ``{key}`` MUST NOT fire a live call: instead it
records a :class:`ProbeResult` with ``success=False`` carrying a safe ``curl``
the operator can run by hand, with the secret kept as the shell variable
``$KEY`` (never the raw value).

Rungs (ordered, identity/reachability first):

  1. ``rest-root-openapi``  ``GET /rest/v1/``             — SAFE, manual. Proves
     the project is reachable and PostgREST accepts the JWT; returns the
     auto-generated OpenAPI schema (every table/view/RPC/column). Read-only,
     idempotent, no PII, non-billable.
  2. ``list-table-rows``    ``GET /rest/v1/{table}?limit=1`` — GATED, manual. A
     row read of a discovered table; the data may be third-party PII.
  3. ``list-auth-users``    ``GET /auth/v1/admin/users``  — GATED, manual.
     GoTrue admin listing of every end-user (emails, phones, identities,
     metadata).

The two GATED rungs are routed through the :func:`gated` boundary so they can
never auto-fire without consent; even WITH consent they make no network call
(their URLs need ``{ref}``/``{table}`` the engine cannot fill) and are rendered
as manual safe-curl notes. The ladder never raises across its public boundary:
every outcome is a :class:`ProbeResult` reflected in the :class:`Verdict`.

Docs: https://supabase.com/docs/guides/api ;
https://supabase.com/docs/reference/javascript/auth-admin-listusers

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["supabase_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
# (Kept for parity with the other ladders; this provider is fully manual and
# issues no live request, but the constant documents the intended bound.)
_TIMEOUT = httpx.Timeout(10.0)

# The placeholder host: the engine cannot resolve ``{ref}`` from the JWT, so the
# real URLs are only ever rendered into a manual curl, never fetched.
_REST_ROOT_URL = "https://{ref}.supabase.co/rest/v1/"
_LIST_TABLE_URL = "https://{ref}.supabase.co/rest/v1/{table}?limit=1"
_LIST_AUTH_USERS_URL = "https://{ref}.supabase.co/auth/v1/admin/users"


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.

    Because every Supabase rung is manual (no live call), no rung succeeds and
    the verdict is DENIED until an operator runs the emitted curls by hand.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


def _safe_curl(method: str, url: str) -> str:
    """Render a safe curl for a manual rung, keeping the secret as ``$KEY``.

    The caller exports ``KEY=<service_role jwt>`` before running it; the raw
    secret never appears in the command we emit.
    """
    return f"curl -s -X {method} '{url}' -H 'apikey: $KEY' -H 'Authorization: Bearer $KEY'"


def _rest_root_openapi() -> ProbeResult:
    """SAFE (manual): ``GET /rest/v1/`` returns the project's OpenAPI schema.

    The URL needs ``{ref}`` (the project subdomain), which is not in the JWT,
    so we never call it — we emit a runnable curl instead. Proves reachability
    + that PostgREST accepts the service_role JWT; read-only, idempotent, no
    PII.
    """
    return ProbeResult(
        name="rest-root-openapi",
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "manual rung: project ref subdomain is not in the JWT — run the safe "
            "curl to fetch the OpenAPI schema (every table/view/RPC/column). "
            "Replace {ref}."
        ),
        evidence={
            "manual": True,
            "tier": "safe",
            "method": "GET",
            "url": _REST_ROOT_URL,
            "success_status": [200],
            "safe_curl": _safe_curl("GET", _REST_ROOT_URL),
        },
    )


@gated
async def _list_table_rows(consent: Consent) -> ProbeResult:
    """GATED + MANUAL: ``GET /rest/v1/{table}?limit=1`` reads application data.

    A successful read proves the service_role key bypasses RLS. Decorated with
    :func:`vtx_recon.safety.gated`: the safety boundary runs *before* this body,
    so without BOTH ``--prove`` and an authorized scope it raises
    :class:`GatedProbeBlocked` and nothing happens. Even WITH consent it never
    fires a live request — its URL needs ``{ref}`` and a ``{table}`` discovered
    from the OpenAPI schema the engine cannot fill — so it returns a manual
    safe-curl note. A row may be third-party PII, which is why it is gated.
    """
    del consent  # consumed by the @gated boundary; no live call is made
    return ProbeResult(
        name="list-table-rows",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "gated manual rung: a service_role row read bypasses RLS and may "
            "return third-party PII. Needs {ref} and a {table} from the OpenAPI "
            "schema; run the safe curl by hand under explicit authorization "
            "(expect HTTP 200/206)."
        ),
        evidence={
            "manual": True,
            "tier": "gated",
            "method": "GET",
            "url": _LIST_TABLE_URL,
            "success_status": [200, 206],
            "safe_curl": _safe_curl("GET", _LIST_TABLE_URL),
        },
    )


@gated
async def _list_auth_users(consent: Consent) -> ProbeResult:
    """GATED + MANUAL: ``GET /auth/v1/admin/users`` lists every end-user.

    The GoTrue admin endpoint returns every end-user account (emails, phones,
    identities, metadata) — the impact that matters. Decorated with
    :func:`vtx_recon.safety.gated`: without full consent it raises
    :class:`GatedProbeBlocked` before any work. Even WITH consent it never fires
    a live request — its URL needs ``{ref}`` the engine cannot fill — so it
    returns a manual safe-curl note. It reads third-party PII, hence gated.
    """
    del consent  # consumed by the @gated boundary; no live call is made
    return ProbeResult(
        name="list-auth-users",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "gated manual rung: the GoTrue admin endpoint lists every end-user "
            "(emails, phones, identities, metadata). Needs {ref}; run the safe "
            "curl by hand under explicit authorization (expect HTTP 200)."
        ),
        evidence={
            "manual": True,
            "tier": "gated",
            "method": "GET",
            "url": _LIST_AUTH_USERS_URL,
            "success_status": [200],
            "safe_curl": _safe_curl("GET", _LIST_AUTH_USERS_URL),
        },
    )


@register("Supabase")
async def supabase_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Climb the Supabase capability ladder for a finding.

    Every rung is manual (the project ``ref`` subdomain is not in the JWT), so
    no network call is made: the ladder emits ordered, runnable safe curls —
    the SAFE OpenAPI probe first, then the two GATED PII reads routed through
    the :func:`gated` boundary (blocked unless consent is granted; manual even
    with it). Never raises across this boundary; the worst case is DENIED.
    """
    # The ladder (even its manual tier) refuses to run without a named scope.
    scope = consent.require_ladder_scope()
    # The secret is read but never persisted; the printed curls keep ``$KEY``.
    _ = finding.raw

    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE, manual): reachability + JWT acceptance + DB surface area.
    rungs.append(_rest_root_openapi())

    # Rungs 2 & 3 (GATED, manual): RLS-bypassing data read, then the auth-user
    # dump. Each is routed through the @gated boundary so it can never auto-fire
    # without consent; if consent is missing the wrapper raises GatedProbeBlocked
    # and we record a blocked note. Even with consent the body fires no live call
    # (its URL needs {ref}/{table} the engine cannot fill) — it returns a manual
    # safe-curl note. The ladder never raises across the public boundary.
    try:
        rungs.append(await _list_table_rows(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="list-table-rows",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "manual": True,
                    "safe_curl": _safe_curl("GET", _LIST_TABLE_URL),
                },
            )
        )

    try:
        rungs.append(await _list_auth_users(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="list-auth-users",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "manual": True,
                    "safe_curl": _safe_curl("GET", _LIST_AUTH_USERS_URL),
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="supabase",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
