"""npm capability ladder — prove depth of access for a leaked npm token.

Handles TruffleHog ``NpmToken`` (and ``NPM``/``npm``) findings. An npm access
token authenticates against the registry with ``Authorization: Bearer <token>``.

The ordered ladder (depth of access, least -> most revealing):

  1. ``npm.whoami``  ``GET /-/whoami`` — confirms the token and reveals the npm
     username it belongs to. Decides VALID vs DENIED. Read-only.
  2. ``npm.tokens``  ``GET /-/npm/v1/tokens`` — reveals the token's type
     (automation / publish / read-only) and 2FA posture. Read-only enumeration
     of the account's tokens (we keep only counts, never raw token values).
  3. ``npm.publish`` ``PUT /{package}`` — GATED, state-changing (publishes a
     package version). Its URL needs a ``{package}`` the engine cannot fill, so
     this rung is a MANUAL safe-curl note: never auto-fired, prints a curl that
     keeps the secret as ``$KEY``.

Every live rung is READ-ONLY, the ladder never raises across the public
boundary, and the raw token never lands in evidence.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "npm_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("NpmToken", "NPM", "npm", "npmToken")

REGISTRY_BASE = "https://registry.npmjs.org"

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
    """Standard npm registry bearer header for an access token."""
    return {"Authorization": f"Bearer {token}"}


@register("NpmToken", "NPM", "npm", "npmToken")
async def npm_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered npm capability ladder for one finding.

    Refuses to ladder without an authorized scope. Climbs ``whoami`` first and
    only descends into the token-type rung if the token authenticated. The
    publish rung is GATED and, because its URL needs a ``{package}`` the engine
    cannot fill, is emitted as a manual safe-curl note rather than a live call.
    Never raises across the boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    token = finding.raw

    # --- Rung 1: whoami (SAFE) — decides live/dead ---------------------------
    identity = await _npm_whoami(token)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: tokens (SAFE) -------------------------------------------
        rungs.append(await _npm_tokens(token))

        # --- Rung 3: publish (GATED, manual safe-curl) -----------------------
        rungs.append(await _maybe_publish(consent))

    return LadderResult(
        finding=finding,
        provider="npm",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _npm_whoami(token: str) -> ProbeResult:
    """SAFE: ``GET /-/whoami`` confirms the token and returns the npm username."""
    name = "npm.whoami"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{REGISTRY_BASE}/-/whoami", headers=_bearer(token))
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
        detail=f"authenticated as npm user {body.get('username') or '?'}",
        evidence={"status": resp.status_code, "username": body.get("username")},
    )


async def _npm_tokens(token: str) -> ProbeResult:
    """SAFE: ``GET /-/npm/v1/tokens`` reveals the token's type / 2FA posture."""
    name = "npm.tokens"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{REGISTRY_BASE}/-/npm/v1/tokens", headers=_bearer(token))
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not read token list (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    objects = body.get("objects") if isinstance(body.get("objects"), list) else []
    # Record only non-secret metadata: never the token values themselves.
    readonly_count = sum(1 for o in objects if isinstance(o, dict) and o.get("readonly"))
    automation_count = sum(1 for o in objects if isinstance(o, dict) and o.get("automation"))
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"{len(objects)} token(s) on account "
            f"({readonly_count} read-only, {automation_count} automation)"
        ),
        evidence={
            "status": resp.status_code,
            "token_count": len(objects),
            "readonly_count": readonly_count,
            "automation_count": automation_count,
        },
    )


# --- gated (manual) rung -----------------------------------------------------


def _publish_safe_curl() -> str:
    """The safe curl printed for the manual gated publish rung (secret as $KEY)."""
    return (
        "curl -X PUT "
        f"'{REGISTRY_BASE}/PACKAGE_NAME' "
        '-H "Authorization: Bearer $KEY" '
        '-H "Content-Type: application/json" '
        "--data @package-publish-body.json"
    )


@gated
async def npm_gated_publish(consent: Consent) -> ProbeResult:
    """GATED: ``PUT /{package}`` would publish a package version.

    State-changing, supply-chain impact. Decorated with
    :func:`vtx_recon.safety.gated`, so the safety boundary runs *before* this
    body and, without consent, raises :class:`GatedProbeBlocked`. Even with
    consent this rung is MANUAL: the URL needs a ``{package}`` the engine cannot
    fill, so it never fires a live PUT — it only returns a safe curl (secret as
    ``$KEY``).
    """
    return ProbeResult(
        name="npm.publish",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: publishes a package version (supply-chain impact); needs "
            "a {package}; run the safe curl by hand to exercise the impact"
        ),
        evidence={"manual": True, "safe_curl": _publish_safe_curl()},
    )


async def _maybe_publish(consent: Consent) -> ProbeResult:
    """Attempt the gated publish rung; report it as blocked when consent absent."""
    try:
        return await npm_gated_publish(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="npm.publish",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _publish_safe_curl(),
            },
        )
