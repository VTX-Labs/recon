"""Docker Hub capability ladder — prove depth of access for a leaked PAT.

Handles TruffleHog ``Dockerhub`` / ``Docker`` findings. A Docker Hub personal
access token has the shape ``dckr_pat_<27>``. Crucially, the PAT is **not** a
Bearer credential on its own: the management API at ``hub.docker.com`` is driven
by a short-lived JWT that you must first mint by exchanging ``username`` + PAT at
``POST /v2/auth/token``. That username is **not** carried in the token, and the
JWT itself is produced only by that exchange — both are placeholders the engine
cannot fill (``<username>``, ``{jwt}``).

Per the manual-rung rule, that means **every rung is MANUAL**: no rung issues a
live call. Each rung instead emits a copy-pasteable, safe ``curl`` an operator
can run by hand, with the PAT kept as a ``$KEY`` placeholder and the minted JWT
kept as ``$JWT``, so nothing sensitive is ever stored.

Rungs (ordered, identity first):

#. ``auth-token-exchange`` — SAFE/MANUAL. ``POST /v2/auth/token`` exchanges
   ``{"identifier":"<username>","secret":"$KEY"}`` for a short-lived JWT. A 200
   proves the PAT is live and the decoded JWT scope claim reveals the permission
   level (read / read-write / read-write-delete) plus the bound username.
   Idempotent session mint, no state change, non-billable.
#. ``list-namespace-repos`` — SAFE/MANUAL. ``GET /v2/namespaces/{namespace}/
   repositories`` lists the public+private repositories under a reachable
   namespace using the JWT from rung 1 — read-only depth of access.
#. ``delete-repository`` — GATED/MANUAL. ``DELETE /v2/repositories/{namespace}/
   {repository}`` wipes a repository (only succeeds for delete-scoped PATs).
   Destructive, state-changing supply-chain impact (wipe/hijack images). Routed
   through :func:`vtx_recon.safety.gated` so it is structurally unreachable
   without BOTH ``--prove`` and ``--i-am-authorized "<scope>"``; even when
   consent is granted it never auto-fires (placeholders cannot be filled) — it
   renders the safe curl for the operator.

The ladder never raises across its public boundary: every failure becomes a
:class:`ProbeResult`. Secrets are never persisted; only non-secret values land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "dockerhub_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Dockerhub", "Docker")

API_BASE = "https://hub.docker.com"


# --------------------------------------------------------------------------- #
# safe-curl rendering (no live call is ever made by this provider)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(method: str, url: str, headers: dict[str, str], body: str | None = None) -> str:
    """Build a copy-pasteable curl.

    The PAT is kept as the ``$KEY`` placeholder and the minted JWT as ``$JWT``;
    ``{namespace}`` / ``{repository}`` are left for the operator to substitute.
    The string never contains a live secret, so it is safe to print and to store.
    """
    parts = ["curl", "-sS", "-X", method]
    for header_name, header_value in headers.items():
        parts.extend(["-H", _shquote(f"{header_name}: {header_value}")])
    if body is not None:
        parts.extend(["--data", _shquote(body)])
    parts.append(_shquote(url))
    return " ".join(parts)


# Shared header sets. ``$JWT`` is a placeholder — the engine cannot mint the
# session JWT from the raw PAT (the paired username is not in the token), so it
# is never replaced with a secret.
_EXCHANGE_HEADERS = {
    "Content-Type": "application/json",
}

_JWT_HEADERS = {
    "Authorization": "Bearer $JWT",
    "Accept": "application/json",
}


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID.
    * Nothing succeeded -> DENIED.

    NOTE: every Docker Hub rung is manual and never makes a live call, so no rung
    is ever ``success=True``. The verdict is therefore always DENIED — the ladder
    cannot prove live access without an out-of-band JWT (minted from the PAT plus
    the paired username, which is not in the token).
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# rung 1 — SAFE / MANUAL: auth-token-exchange
# --------------------------------------------------------------------------- #


def _dockerhub_auth_token_exchange() -> ProbeResult:
    """SAFE/MANUAL: ``POST /v2/auth/token`` exchanges
    ``{"identifier":"<username>","secret":"$KEY"}`` for a short-lived JWT.

    A 200 proves the PAT is live; the decoded JWT scope claim reveals the
    permission level (read / read-write / read-write-delete) and the bound
    username. Idempotent session mint, no state change, non-billable. MANUAL
    because the paired ``<username>`` is not present in the token, so the engine
    cannot build the request body — no live call is made; the operator is handed
    the exact safe curl.
    """
    name = "auth-token-exchange"
    url = f"{API_BASE}/v2/auth/token"
    body = '{"identifier":"<username>","secret":"$KEY"}'
    curl = _safe_curl("POST", url, _EXCHANGE_HEADERS, body)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the paired <username> (not in the token) to exchange the "
            "PAT for a JWT; run this by hand — a 200 proves the PAT is live and the "
            f"decoded JWT scope reveals read / read-write / read-write-delete: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE / MANUAL: list-namespace-repos
# --------------------------------------------------------------------------- #


def _dockerhub_list_namespace_repos() -> ProbeResult:
    """SAFE/MANUAL: ``GET /v2/namespaces/{namespace}/repositories`` lists the
    public+private repositories under a reachable namespace using the JWT from
    rung 1 — read-only depth of access. MANUAL because it needs the ``{jwt}``
    (which the engine cannot mint) and a ``{namespace}`` placeholder; no live
    call is made — the operator is handed the safe curl.
    """
    name = "list-namespace-repos"
    url = f"{API_BASE}/v2/namespaces/{{namespace}}/repositories"
    curl = _safe_curl("GET", url, _JWT_HEADERS)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the JWT from auth-token-exchange and a {namespace}; run "
            "this by hand to list the public+private repos reachable under that "
            f"namespace: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 3 — GATED / MANUAL: delete-repository (destructive, state-changing)
# --------------------------------------------------------------------------- #


def _delete_repository_safe_curl() -> str:
    """The safe curl printed for the manual gated repo-delete rung (JWT as $JWT)."""
    return _safe_curl(
        "DELETE",
        f"{API_BASE}/v2/repositories/{{namespace}}/{{repository}}",
        _JWT_HEADERS,
    )


@gated
async def dockerhub_delete_repository(consent: Consent) -> ProbeResult:
    """GATED/MANUAL: ``DELETE /v2/repositories/{namespace}/{repository}`` wipes a
    repository (only succeeds for delete-scoped PATs).

    Destructive, state-changing supply-chain impact: a leaked delete-scoped PAT
    lets an attacker wipe or hijack published images. Decorated with
    :func:`vtx_recon.safety.gated`: the safety boundary runs *before* this body,
    so without BOTH ``--prove`` and an authorized scope it raises
    :class:`GatedProbeBlocked` and nothing is rendered as runnable. Even with
    consent it is MANUAL — the engine cannot mint the JWT or fill the
    ``{namespace}``/``{repository}`` placeholders, so it returns the safe curl
    rather than firing.
    """
    name = "delete-repository"
    curl = _delete_repository_safe_curl()
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would permanently delete a repository (supply-chain "
            "wipe/hijack). Needs the JWT and {namespace}/{repository}; run by hand "
            f"only when authorized: {curl}"
        ),
        evidence={
            "manual": True,
            "billable": False,
            "safe_curl": curl,
            "success_status": [202, 204],
        },
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("Dockerhub", "Docker")
async def dockerhub_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Docker Hub capability ladder for one finding.

    Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
    call): the SAFE rungs always render their safe curl; the GATED rung is
    reached only through the safety boundary — when consent is missing it is
    recorded as a blocked rung, when consent is present it still only renders a
    safe curl.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE/MANUAL): identity / token-exchange. Manual rungs always
    # render, so subsequent rungs are not gated on a (never-true) success — the
    # operator gets the full hand-run plan.
    rungs.append(_dockerhub_auth_token_exchange())
    # Rung 2 (SAFE/MANUAL): reachable repository surface under a namespace.
    rungs.append(_dockerhub_list_namespace_repos())

    # Rung 3 (GATED/MANUAL): destructive repo delete. Reachable only via the
    # @gated wrapper; without full consent it raises GatedProbeBlocked, recorded
    # as a blocked rung (the safe curl is still surfaced as evidence). The ladder
    # never raises across its public boundary.
    try:
        rungs.append(await dockerhub_delete_repository(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="delete-repository",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "reason": blocked.reason,
                    "manual": True,
                    "billable": False,
                    "safe_curl": _delete_repository_safe_curl(),
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="dockerhub",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
