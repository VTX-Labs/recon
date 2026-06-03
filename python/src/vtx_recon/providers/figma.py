"""Capability ladder for Figma personal access tokens (PATs).

A Figma PAT is shaped ``figd_<40+ chars of [A-Za-z0-9_-]>`` and authenticates
via the ``X-Figma-Token: <token>`` header — NOT ``Authorization``. TruffleHog
surfaces these under the ``FigmaPersonalAccessToken`` detector. The ladder
climbs (depth of access, least -> most revealing):

  1. ``me``                 ``GET /v1/me`` is whoami: it returns the token owner
     (``id``, ``email``, ``handle``, account name). Confirms the token is live
     and reveals the identity behind it. Read-only, idempotent, non-billable.
     This is the rung that decides VALID vs DENIED.
  2. ``list-team-projects`` ``GET /v1/teams/{team_id}/projects`` enumerates the
     projects within a team the token can reach, proving file / design reach
     beyond bare identity. Its URL embeds a ``team_id`` the engine cannot fill
     (it comes from the Figma UI/URL, not the key), so this rung is NEVER
     auto-fired: it is rendered as a manual safe-curl note that keeps the secret
     as ``$KEY`` for an operator to run by hand.

Every rung is ordered (identity first, then depth), READ-ONLY, and never raises
across the public boundary: failures become a :class:`ProbeResult` with
``success=False`` so one dead key cannot crash a batch run. The raw token is
held only transiently for the HTTP call and never lands in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier
from . import register

__all__ = ["figma_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)


def _figma_headers(key: str) -> dict[str, str]:
    """Figma PATs authenticate with the ``X-Figma-Token`` header, not ``Authorization``."""
    return {"X-Figma-Token": key}


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


@register("FigmaPersonalAccessToken")
async def figma_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Figma capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs ``me`` first and only descends into the deeper rung if the token
    authenticated. The ``list-team-projects`` rung's URL needs a ``team_id`` the
    engine cannot fill, so it is emitted as a manual safe-curl note rather than a
    live call. Never raises across the public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: me (SAFE) — decides live/dead -------------------------------
    identity = await _me(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-team-projects (SAFE, manual safe-curl) -------------
        # The URL embeds a {team_id} the engine cannot fill, so this never fires
        # a live request: it is rendered as a manual note (secret kept as $KEY).
        rungs.append(_list_team_projects_manual())

    return LadderResult(
        finding=finding,
        provider="figma",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _me(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/me`` confirms the token and returns the owner identity.

    Returns id, email, handle, account name — whoami. Read-only, idempotent,
    non-billable.
    """
    name = "me"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.figma.com/v1/me",
                headers=_figma_headers(key),
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

    # Record only non-secret identity fields (id, handle, email, account name);
    # never the raw token. The handle/email are the owner's own account metadata.
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {body.get('handle') or body.get('email') or body.get('id')} "
            f"(id {body.get('id', '?')})"
        ),
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "handle": body.get("handle"),
            "email": body.get("email"),
            "img_url": body.get("img_url"),
        },
    )


def _list_team_projects_safe_curl() -> str:
    """The safe curl printed for the manual list-team-projects rung (secret as $KEY)."""
    return "curl 'https://api.figma.com/v1/teams/TEAM_ID/projects' -H \"X-Figma-Token: $KEY\""


def _list_team_projects_manual() -> ProbeResult:
    """SAFE (MANUAL): ``GET /v1/teams/{team_id}/projects`` enumerates team projects.

    Proves file/design reach beyond bare identity. The URL needs a ``team_id``
    the engine cannot fill (it is read from the Figma UI/URL, not the
    credential), so this rung NEVER fires a live request — it is rendered as a
    manual safe-curl note with the secret kept as ``$KEY`` for an authorized
    operator to run by hand.
    """
    return ProbeResult(
        name="list-team-projects",
        tier=ProbeTier.SAFE,
        success=False,
        detail=(
            "manual rung: needs a team_id from the Figma UI/URL (not in the key); "
            "run the safe curl by hand to enumerate team projects"
        ),
        evidence={"manual": True, "safe_curl": _list_team_projects_safe_curl()},
    )
