"""Asana capability ladder — prove depth of access for a leaked Asana token.

Handles TruffleHog ``AsanaPersonalAccessToken`` and ``AsanaOauth`` findings.
Both authenticate the same way — ``Authorization: Bearer <token>`` against the
Asana REST API at ``https://app.asana.com/api/1.0`` — so one ladder serves both.

The ordered ladder (depth of access, least -> most revealing):

  1. ``users-me`` ``GET /users/me`` — whoami. Returns the token owner (gid,
     name, email) plus the workspaces they belong to. Read-only, idempotent,
     non-billable. SAFE.
  2. ``list-workspaces`` ``GET /workspaces`` — reachable-data depth: enumerates
     every workspace/organization the token can reach, proving the blast radius
     of accessible projects. Read-only. SAFE.
  3. ``list-workspace-users`` ``GET /users?workspace={workspace_gid}`` — IMPACT:
     reads the directory of all users (names, emails) in a workspace —
     third-party PII exposure. Read-only but reads org-member PII, so GATED. The
     URL needs a ``{workspace_gid}`` the engine cannot fill, so even with consent
     it is rendered as a MANUAL blocked safe-curl note (never auto-fired) — an
     operator supplies a gid from the prior rung and runs it by hand.

Every rung is ordered (identity first, then depth), READ-ONLY, and never raises
across the public boundary: failures become a :class:`ProbeResult` with
``success=False`` so one dead key cannot crash a batch run. The raw secret is
held only transiently for the HTTP call and never lands in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "asana_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("AsanaPersonalAccessToken", "AsanaOauth")

API_BASE = "https://app.asana.com/api/1.0"

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


@register("AsanaPersonalAccessToken", "AsanaOauth")
async def asana_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Asana capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Runs two SAFE read-only rungs (identity, then workspace enumeration), then
    the GATED PII directory rung — which is additionally MANUAL because its URL
    needs a ``{workspace_gid}`` the engine cannot fill. Never raises across the
    public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: users-me (SAFE) — identity / whoami -------------------------
    identity = await _asana_users_me(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-workspaces (SAFE) — reachable-data blast radius ----
        rungs.append(await _asana_list_workspaces(key))

        # --- Rung 3: list-workspace-users (GATED, manual safe-curl) ---------
        # Reads org-member PII. The @gated wrapper enforces consent first, so
        # without --prove + --i-am-authorized the rung is recorded as blocked.
        # Even with consent it stays MANUAL (URL needs {workspace_gid} the
        # engine cannot fill), so it never fires a live request.
        rungs.append(await _maybe_list_workspace_users(consent))

    return LadderResult(
        finding=finding,
        provider="asana",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- SAFE rungs --------------------------------------------------------------


async def _asana_users_me(key: str) -> ProbeResult:
    """SAFE: ``GET /users/me`` confirms the token and returns the owner's identity.

    This is the whoami rung — a 200 returns the token owner (gid, name, email)
    and the workspaces they belong to. Read-only, idempotent, non-billable.
    """
    name = "users-me"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/users/me",
                headers={"Authorization": f"Bearer {key}"},
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

    data = body.get("data") or {}
    workspaces = data.get("workspaces") or []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {data.get('name', '?')} (gid {data.get('gid', '?')}) "
            f"in {len(workspaces)} workspace(s)"
        ),
        evidence={
            "status": resp.status_code,
            "gid": data.get("gid"),
            "name": data.get("name"),
            "email": data.get("email"),
            "workspace_count": len(workspaces),
        },
    )


async def _asana_list_workspaces(key: str) -> ProbeResult:
    """SAFE: ``GET /workspaces`` enumerates every workspace the token can reach.

    Reachable-data depth — listing the workspaces/organizations the token can
    see proves the blast radius of accessible projects without touching any of
    them. Read-only.
    """
    name = "list-workspaces"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/workspaces",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list workspaces (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    data = body.get("data") or []
    # Keep non-secret identifiers only: gids + names map the reachable surface.
    workspaces = [{"gid": w.get("gid"), "name": w.get("name")} for w in data]
    listed = ", ".join(str(w["name"] or w["gid"]) for w in workspaces) or "(none)"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"token reaches {len(workspaces)} workspace(s): {listed}",
        evidence={
            "status": resp.status_code,
            "workspace_count": len(workspaces),
            "workspaces": workspaces,
        },
    )


# --- gated (manual) rung -----------------------------------------------------


def _list_workspace_users_safe_curl() -> str:
    """Safe curl for the manual gated list-workspace-users rung (secret kept as $KEY)."""
    return (
        f"curl -s '{API_BASE}/users?workspace=WORKSPACE_GID' "
        '-H "Accept: application/json" '
        '-H "Authorization: Bearer $KEY"'
    )


@gated
async def asana_gated_list_workspace_users(consent: Consent) -> ProbeResult:
    """GATED (manual): ``GET /users?workspace={workspace_gid}`` reads org-member PII.

    Reading the directory of all users (names, emails) in a workspace is
    third-party PII exposure. Decorated with :func:`vtx_recon.safety.gated`, so
    the safety boundary runs *before* this body and, without BOTH ``--prove``
    and an authorized scope, raises :class:`GatedProbeBlocked` and nothing
    executes. Even with consent this rung is MANUAL: the URL needs a
    ``{workspace_gid}`` the engine cannot fill (an operator supplies one from the
    prior ``list-workspaces`` rung), so it never fires a live request — it only
    returns a safe curl (secret kept as ``$KEY``) for an operator to run by hand.
    The public ladder records it as a blocked/manual note either way.
    """
    name = "list-workspace-users"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: reads every user (names, emails) in a workspace — "
            "third-party PII. Needs a {workspace_gid} from the prior "
            "list-workspaces rung, which the engine cannot fill, so run the safe "
            "curl by hand to exercise the PII read"
        ),
        evidence={
            "manual": True,
            "success_status": [200],
            "safe_curl": _list_workspace_users_safe_curl(),
        },
    )


async def _maybe_list_workspace_users(consent: Consent) -> ProbeResult:
    """Attempt the gated list-workspace-users rung; report it blocked when consent is absent.

    The gating happens inside :func:`asana_gated_list_workspace_users`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the PII read by hand.
    """
    try:
        return await asana_gated_list_workspace_users(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="list-workspace-users",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _list_workspace_users_safe_curl(),
            },
        )
