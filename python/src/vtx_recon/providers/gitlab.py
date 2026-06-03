"""GitLab capability ladder — prove depth of access for a leaked PAT.

Handles TruffleHog ``GitLab`` findings. A GitLab personal access token
(``glpat-...``) authenticates with the ``PRIVATE-TOKEN`` header. Two SAFE rungs:

  1. ``gitlab.user``         ``GET /api/v4/user`` — confirms identity. Decides
     VALID vs DENIED. Read-only, idempotent.
  2. ``gitlab.token.scopes`` ``GET /api/v4/personal_access_tokens/self`` —
     reveals the token's exact scopes (depth of access) without exercising any
     of them. Read-only.

Every rung is ordered (identity first, then depth), READ-ONLY, and the ladder
never raises across the public boundary: failures become a :class:`ProbeResult`
with ``success=False`` so one dead key cannot crash a batch run. The raw token
is held only transiently for the HTTP call and never lands in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier
from . import register

__all__ = ["DETECTORS", "gitlab_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("GitLab",)

API_BASE = "https://gitlab.com/api/v4"

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


@register("GitLab")
async def gitlab_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """GitLab ladder: SAFE identity (/user) -> SAFE token scopes (self)."""
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    token = finding.raw

    identity = await _gitlab_user(token)
    rungs.append(identity)
    # Only probe depth if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _gitlab_token_scopes(token))

    return LadderResult(
        finding=finding,
        provider="gitlab",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _gitlab_user(token: str) -> ProbeResult:
    """SAFE: ``GET /api/v4/user`` confirms identity."""
    name = "gitlab.user"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{API_BASE}/user", headers={"PRIVATE-TOKEN": token})
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
        detail=f"authenticated as {body.get('username')} (id {body.get('id')})",
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "username": body.get("username"),
            "is_admin": body.get("is_admin"),
        },
    )


async def _gitlab_token_scopes(token: str) -> ProbeResult:
    """SAFE: ``GET /api/v4/personal_access_tokens/self`` reveals scopes.

    Reading the token's own scopes proves depth of access without exercising
    any of them.
    """
    name = "gitlab.token.scopes"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/personal_access_tokens/self",
                headers={"PRIVATE-TOKEN": token},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not read token scopes (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    scopes = body.get("scopes") or []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"token scopes: {', '.join(scopes) if scopes else '(none)'}",
        evidence={
            "status": resp.status_code,
            "scopes": scopes,
            "active": body.get("active"),
        },
    )
