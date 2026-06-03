"""Fastly capability ladder — prove depth of access for a leaked API token.

Handles TruffleHog ``FastlyPersonalToken`` findings: a 32-char
``[A-Za-z0-9_-]`` Fastly API token. Fastly authenticates with the
**``Fastly-Key``** header (NOT ``Authorization: Bearer``); every rung here
uses that header and holds the secret only transiently for the call.

Ordered ladder (depth of access, least -> most impactful):

1. ``token-self``    ``GET /tokens/self`` (SAFE) — TruffleHog's own
   verification call. Returns the token's id, user_id, scoped services and
   scope (e.g. ``global:read``), created_at. Confirms auth and reveals
   exactly what the token can do. Read-only.
2. ``list-services`` ``GET /service`` (SAFE) — enumerates every Fastly
   service (CDN config) the token can reach: depth into the customer's edge
   config. Read-only listing of owned resources.
3. ``purge-all``     ``POST /service/SERVICE_ID/purge_all`` (GATED) — purges
   a service's entire cache: state-changing impact (origin-load spike /
   cache-poisoning prep). Its URL needs a ``SERVICE_ID`` the engine cannot
   fill from the secret, so this rung is **manual**: it never fires a live
   call. It is still wired through :func:`vtx_recon.safety.gated` so the
   safety boundary is enforced, and it renders as a blocked/manual rung
   carrying a safe ``curl`` that keeps the secret as ``$KEY``.

Every rung is ordered (identity first, then depth), READ-ONLY by default,
and never raises across the public boundary: failures become a
:class:`ProbeResult` with ``success=False`` so one dead key cannot crash a
batch run. Secrets are held only transiently for the HTTP call and only
non-secret values land in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["fastly_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

_API_BASE = "https://api.fastly.com"

# The safe, never-fired curl for the manual gated purge-all rung.
_PURGE_ALL_CURL = f'curl -X POST -H "Fastly-Key: $KEY" {_API_BASE}/service/SERVICE_ID/purge_all'


def _headers(key: str) -> dict[str, str]:
    """Build the Fastly auth header. Fastly uses ``Fastly-Key``, not Bearer."""
    return {"Fastly-Key": key, "Accept": "application/json"}


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


@register("FastlyPersonalToken")
async def fastly_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Fastly ladder: SAFE identity (/tokens/self) -> SAFE services -> GATED purge.

    Never raises across the public boundary: any error is captured into a
    :class:`ProbeResult`. The authorized scope is required (the whole ladder
    refuses to run without it).
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: token-self (SAFE) — identity + scope. TruffleHog's verify call.
    identity = await _fastly_token_self(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-services (SAFE) — reachable edge configs.
        rungs.append(await _fastly_list_services(key))

        # --- Rung 3: purge-all (GATED, MANUAL) — never auto-fires. The URL needs
        # a SERVICE_ID the engine cannot fill from the secret, so we render a
        # safe curl instead of issuing a live request. Still routed through the
        # @gated boundary so consent is enforced even for the manual rendering.
        try:
            rungs.append(await _fastly_purge_all(consent))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="purge-all",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "manual": True,
                        "reason": blocked.reason,
                        "safe_curl": _PURGE_ALL_CURL,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="fastly",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _fastly_token_self(key: str) -> ProbeResult:
    """SAFE: ``GET /tokens/self`` confirms the token and returns its id,
    user_id, scoped services, scope, and created_at.

    This is TruffleHog's verification call; it proves auth and reveals exactly
    what the token can do. Read-only.
    """
    name = "token-self"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/tokens/self",
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

    # `services` may be a list of service ids the token is scoped to, or null
    # (token has access to all services). Record only the count + ids (non-secret).
    services = body.get("services") if isinstance(body.get("services"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"token authenticates (id {body.get('id', '?')}, "
            f"scope {body.get('scope', '?')}, user {body.get('user_id', '?')})"
        ),
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "user_id": body.get("user_id"),
            "scope": body.get("scope"),
            "created_at": body.get("created_at"),
            "scoped_service_count": len(services),
            "scoped_services": services[:25],
        },
    )


async def _fastly_list_services(key: str) -> ProbeResult:
    """SAFE: ``GET /service`` enumerates every Fastly service (CDN config) the
    token can reach — depth into the customer's edge config.

    Read-only listing of owned resources. Only non-secret identifiers (ids,
    names) are recorded, never service config contents.
    """
    name = "list-services"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/service",
                headers=_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list services (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        services = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if not isinstance(services, list):
        services = []
    items = [s for s in services if isinstance(s, dict)]
    ids = [s["id"] for s in items if s.get("id")]
    names = [s["name"] for s in items if s.get("name")]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=len(items) > 0,
        detail=(
            f"{len(items)} reachable service(s): {', '.join(map(str, names[:5]))}"
            if items
            else "no services reachable with this token"
        ),
        evidence={
            "status": resp.status_code,
            "service_count": len(items),
            "service_ids": ids[:25],
            "service_names": names[:25],
        },
    )


@gated
async def _fastly_purge_all(consent: Consent) -> ProbeResult:
    """GATED + MANUAL: ``POST /service/SERVICE_ID/purge_all`` purges a service's
    entire cache — a state-changing impact (origin-load spike / cache-poisoning
    prep).

    The URL needs a ``SERVICE_ID`` the engine cannot fill from the secret, so
    this probe NEVER issues a live call: it only renders a safe ``curl`` that
    keeps the secret as ``$KEY``.

    It is still decorated with :func:`vtx_recon.safety.gated` so the safety
    boundary runs *before* the body: without BOTH ``--prove`` and an authorized
    scope it raises :class:`GatedProbeBlocked` and even the manual rendering is
    recorded as a blocked rung. With full consent it returns a manual,
    non-fired :class:`ProbeResult` (``success=False``) carrying the safe curl —
    the engine must not auto-mutate.
    """
    return ProbeResult(
        name="purge-all",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: purge_all needs a SERVICE_ID from list-services; "
            "run the safe curl yourself (no live call fired)"
        ),
        evidence={
            "manual": True,
            "needs": "SERVICE_ID",
            "safe_curl": _PURGE_ALL_CURL,
        },
    )
