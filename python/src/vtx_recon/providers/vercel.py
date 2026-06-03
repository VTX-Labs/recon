"""Capability ladder for Vercel access tokens (24 chars ``[a-zA-Z0-9]``).

A Vercel access token authenticates via ``Authorization: Bearer <token>``
against the public REST API (``api.vercel.com``). Vercel PATs carry the FULL
permissions of the user who created them, so depth of access here is the
user's entire surface: every team, project, deployment, and — critically —
each project's decrypted environment variables (downstream API keys, DB URLs,
secrets). This module proves that depth with an ordered ladder.

SAFE rungs (run by default, read-only, non-billable, idempotent):

* ``user``          ``GET /v2/user``     — identity / whoami. Confirms the
  token authenticates and reveals who owns it (id, email, username).
* ``list-projects`` ``GET /v9/projects`` — enumerates every project the token
  can reach: depth across deployments (names, framework, linked git repos).

GATED rung (UNREACHABLE without BOTH ``--prove`` and ``--i-am-authorized``):

* ``read-project-env`` ``GET /v9/projects/PROJECT_ID/env?decrypt=true`` — dumps
  a project's DECRYPTED environment variables, enabling lateral movement. Its
  URL needs a ``PROJECT_ID`` (from ``list-projects``) that the engine cannot
  fill, so this rung is rendered as a MANUAL, gated safe-curl note: it never
  auto-fires. The note is emitted only behind the safety boundary (consent
  fully granted); without consent it is recorded as ``blocked``.

The public entry point is :func:`vercel_ladder`; it never raises across its
boundary — every failure becomes a :class:`ProbeResult` with ``success=False``
so one dead key cannot crash a batch run. Secrets are held only transiently
for the HTTP call and never land in evidence; the manual curl keeps the secret
as ``$KEY``.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["vercel_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# A copy/paste-safe curl the operator runs by hand once they have a PROJECT_ID
# from ``list-projects``. The secret stays a shell variable (``$KEY``); the
# engine never substitutes it and no request is fired automatically.
_SAFE_CURL_READ_ENV = (
    'curl -H "Authorization: Bearer $KEY" '
    '"https://api.vercel.com/v9/projects/PROJECT_ID/env?decrypt=true"'
)


def _headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


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


@register("Vercel")
async def vercel_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Vercel capability ladder for a single finding.

    Identity first (whoami); depth (project enumeration) only if the token
    authenticated. The gated env-var read is a manual safe-curl note: its URL
    needs a PROJECT_ID the engine cannot fill, so it never fires a live
    request. Even the note is gated — without full consent it is recorded as
    ``blocked``.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: identity / whoami (SAFE) ---
    identity = await _vercel_user(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: enumerate projects (SAFE) ---
        rungs.append(await _vercel_list_projects(key))

        # --- Rung 3: read decrypted project env vars (GATED, MANUAL) ---
        # The URL needs a PROJECT_ID the engine cannot fill, so this never
        # makes a live call. The @gated wrapper still enforces consent BEFORE
        # the body runs: without --prove + scope it raises GatedProbeBlocked,
        # captured here as a `blocked` rung so the ladder never raises across
        # the boundary.
        try:
            rungs.append(await _vercel_read_project_env(consent))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="read-project-env",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "manual": True,
                        "safe_curl": _SAFE_CURL_READ_ENV,
                        "reason": blocked.reason,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="vercel",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _vercel_user(key: str) -> ProbeResult:
    """SAFE: ``GET /v2/user`` confirms identity (documented whoami)."""
    name = "user"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.vercel.com/v2/user",
                headers=_headers(key),
            )
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

    # Vercel wraps the payload in a `user` object on /v2/user.
    user = body.get("user") if isinstance(body.get("user"), dict) else body

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {user.get('username') or user.get('email') or 'unknown'} "
            f"(id {user.get('id') or user.get('uid') or '?'})"
        ),
        evidence={
            "status": resp.status_code,
            "id": user.get("id") or user.get("uid"),
            "username": user.get("username"),
            "email": user.get("email"),
            "name": user.get("name"),
        },
    )


async def _vercel_list_projects(key: str) -> ProbeResult:
    """SAFE: ``GET /v9/projects`` enumerates reachable projects (depth)."""
    name = "list-projects"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.vercel.com/v9/projects",
                headers=_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list projects (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # The /v9/projects payload is `{ projects: [...], pagination: {...} }`.
    raw_projects = body.get("projects")
    projects = raw_projects if isinstance(raw_projects, list) else []
    names = [p["name"] for p in projects if isinstance(p, dict) and p.get("name")]
    # Record only non-secret identifiers (project names + a sample of ids), no
    # contents, no env vars.
    ids = [p["id"] for p in projects if isinstance(p, dict) and p.get("id")]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=bool(names),
        detail=(
            f"{len(names)} project(s) reachable: {', '.join(names[:10])}"
            if names
            else "no projects reachable"
        ),
        evidence={
            "status": resp.status_code,
            "project_count": len(names),
            "projects_sample": names[:25],
            "project_ids_sample": ids[:25],
        },
    )


@gated
async def _vercel_read_project_env(consent: Consent) -> ProbeResult:
    """GATED + MANUAL: ``GET /v9/projects/PROJECT_ID/env?decrypt=true``.

    Dumps a project's DECRYPTED environment variables (downstream API keys, DB
    URLs, secrets). The URL contains a ``PROJECT_ID`` placeholder the engine
    cannot fill, so this rung NEVER makes a live call — it emits a manual
    safe-curl note instead. It is still decorated with
    :func:`vtx_recon.safety.gated`: the boundary runs BEFORE this body, so
    without BOTH ``--prove`` and an authorized scope it raises
    :class:`GatedProbeBlocked` and even the note is withheld (the public ladder
    records a ``blocked`` rung).
    """
    return ProbeResult(
        name="read-project-env",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "MANUAL gated rung: needs a PROJECT_ID from list-projects, so no "
            "live call is made. Run the safe curl by hand to dump decrypted "
            "env vars."
        ),
        evidence={"manual": True, "safe_curl": _SAFE_CURL_READ_ENV},
    )
