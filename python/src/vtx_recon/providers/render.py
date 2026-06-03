"""Render capability ladder — prove depth of access for a leaked ``rnd_`` key.

Render API keys are prefixed ``rnd_`` + a random string and are presented as
``Authorization: Bearer <key>`` against ``https://api.render.com/v1``.
TruffleHog ships **no** Render detector, so this ladder is custom-routed off
the distinctive ``rnd_`` regex and registered for the synthetic ``"Render"``
detector name.

Ordered ladder (depth of access, least -> most revealing):

1. ``list-owners``   ``GET /v1/owners`` — identity/whoami equivalent. Lists the
   workspaces (owners: ids, names, emails) the key belongs to. Confirms the key
   authenticates and reveals the account footprint. READ-ONLY.
2. ``list-services`` ``GET /v1/services`` — enumerates every Render service the
   key can view (names, types, repos, URLs): depth into deployments. READ-ONLY
   listing of owned resources.
3. ``read-env-vars`` ``GET /v1/services/{serviceId}/env-vars`` — **GATED**.
   Dumps a service's environment variables (downstream DB URLs, API keys,
   secrets for lateral movement). Gated because it reads sensitive secret
   material. The URL needs a ``SERVICE_ID`` the engine cannot fill, so even
   under consent this rung never auto-fires: it renders a copy-pasteable safe
   curl (secret kept as ``$KEY``) for the operator to run by hand.

Every rung is ordered (identity first, then depth) and never raises across the
public boundary: failures become a :class:`ProbeResult` with ``success=False``
so one dead key cannot crash a batch run. Secrets are held only transiently for
the HTTP call and only non-secret values ever land in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["render_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# The exact, copy-pasteable safe curl for the manual gated rung. The secret is
# NEVER interpolated: it stays the literal ``$KEY`` shell variable, and the
# ``SERVICE_ID`` placeholder is left for the operator to fill from list-services.
_READ_ENV_VARS_SAFE_CURL = (
    'curl -sS -H "Authorization: Bearer $KEY" '
    "https://api.render.com/v1/services/SERVICE_ID/env-vars"
)


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


def _headers(key: str) -> dict[str, str]:
    """Bearer auth header for the Render API."""
    return {"Authorization": f"Bearer {key}", "Accept": "application/json"}


@register("Render")
async def render_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Render ladder: SAFE list-owners -> SAFE list-services -> GATED env-vars.

    The two SAFE rungs are read-only listings (identity, then service depth).
    The env-vars read is GATED because it dumps downstream secrets; its URL
    needs a ``SERVICE_ID`` the engine cannot fill, so it is rendered as a manual
    safe-curl rung that never auto-fires.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: list-owners (SAFE) — identity/whoami ---
    identity = await _render_list_owners(key)
    rungs.append(identity)

    # Only climb deeper if the key authenticated (ordered ladder).
    if identity.success:
        # --- Rung 2: list-services (SAFE) ---
        rungs.append(await _render_list_services(key))

        # --- Rung 3: read-env-vars (GATED, manual safe-curl) ---
        # The @gated wrapper enforces consent BEFORE the body runs; without BOTH
        # --prove and --i-am-authorized it raises GatedProbeBlocked, captured
        # here as a `blocked` rung so the ladder never raises across the public
        # boundary. When consent IS granted the body still makes no live call:
        # the URL needs a SERVICE_ID the engine cannot fill, so it returns a
        # manual safe-curl rung.
        try:
            rungs.append(await _render_read_env_vars(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="read-env-vars",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "reason": blocked.reason,
                        "manual": True,
                        "safe_curl": _READ_ENV_VARS_SAFE_CURL,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="render",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _render_list_owners(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/owners`` — identity/whoami equivalent.

    Lists the workspaces (owners) the key belongs to. Confirms auth and reveals
    the account footprint (ids, names, emails). Read-only.
    """
    name = "list-owners"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.render.com/v1/owners",
                headers=_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"key rejected (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # The endpoint returns a list of { owner: { id, name, email, type } } wrappers.
    items = body if isinstance(body, list) else []
    owners: list[dict] = []
    for item in items:
        if isinstance(item, dict):
            inner = item.get("owner")
            owners.append(inner if isinstance(inner, dict) else item)
    names = [o["name"] for o in owners if isinstance(o.get("name"), str)]
    ids = [o["id"] for o in owners if isinstance(o.get("id"), str)]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated; key belongs to {len(owners)} workspace(s): "
            f"{', '.join(names) or '(unnamed)'}"
            if owners
            else "authenticated; no workspaces visible"
        ),
        evidence={
            "status": resp.status_code,
            "owner_count": len(owners),
            "owner_ids": ids[:25],
            "owner_names": names[:25],
        },
    )


async def _render_list_services(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/services`` — enumerate every service the key can view.

    Read-only listing of owned resources: depth into deployments (names, types,
    repos). Only non-secret identifiers are kept in evidence.
    """
    name = "list-services"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.render.com/v1/services",
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
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # The endpoint returns a list of { service: { id, name, type, ... } } wrappers.
    items = body if isinstance(body, list) else []
    services: list[dict] = []
    for item in items:
        if isinstance(item, dict):
            inner = item.get("service")
            services.append(inner if isinstance(inner, dict) else item)
    service_names = [s["name"] for s in services if isinstance(s.get("name"), str)]
    service_ids = [s["id"] for s in services if isinstance(s.get("id"), str)]
    types = sorted({s["type"] for s in services if isinstance(s.get("type"), str)})

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=bool(services),
        detail=(
            f"{len(services)} service(s) reachable [{', '.join(types) or '?'}]: "
            f"{', '.join(service_names)}"
            if services
            else "no services reachable"
        ),
        evidence={
            "status": resp.status_code,
            "service_count": len(services),
            "service_ids": service_ids[:25],
            "service_names": service_names[:25],
            "service_types": types,
        },
    )


@gated
async def _render_read_env_vars(consent: Consent, key: str) -> ProbeResult:
    """GATED + MANUAL: ``GET /v1/services/{serviceId}/env-vars``.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary raises
    :class:`GatedProbeBlocked` *before* this body runs unless BOTH ``--prove``
    and ``--i-am-authorized`` were supplied. Even under full consent the body
    makes NO live call — the URL needs a ``SERVICE_ID`` (a non-``{key}``
    placeholder) the engine cannot fill — so it returns a manual safe-curl rung
    that keeps the secret as the literal ``$KEY`` shell variable for an operator
    to run by hand. Reading env-vars dumps downstream secrets (DB URLs, API
    keys) usable for lateral movement, which is exactly why it is gated.
    """
    return ProbeResult(
        name="read-env-vars",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs a SERVICE_ID from list-services; run this by hand: "
            f"{_READ_ENV_VARS_SAFE_CURL}"
        ),
        evidence={"manual": True, "safe_curl": _READ_ENV_VARS_SAFE_CURL},
    )
