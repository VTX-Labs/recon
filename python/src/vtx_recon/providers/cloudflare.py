"""Cloudflare capability ladder — prove depth of access for a leaked API token.

Handles TruffleHog ``CloudflareApiToken``, ``CloudflareGlobalApiKey``, and
``CloudflareCaKey`` findings. A Cloudflare scoped API token is 40 chars of
``[A-Za-z0-9_-]`` and authenticates with ``Authorization: Bearer <token>``.
The Global API Key (``X-Auth-Email`` + ``X-Auth-Key``) and the origin-CA key
route here too; the ladder below uses the Bearer form, which is the dominant
and TruffleHog-verified shape.

The ordered ladder (depth of access, least -> most revealing):

  1. ``verify-token``      ``GET /user/tokens/verify`` — TruffleHog's own
     verification call. Confirms the token authenticates and returns its id,
     ``status:active``, and ``not_before`` / ``expires_on``. Read-only,
     idempotent. This is the rung that decides VALID vs DENIED.
  2. ``token-permissions`` ``GET /user/tokens/permission_groups`` — enumerates
     the permission groups available/assignable, mapping the token's scope
     depth (DNS edit, Workers, zone read). Read-only enumeration.
  3. ``list-zones``        ``GET /zones`` — enumerates every domain/zone the
     token can reach (zone ids, names, account) — depth into the DNS estate.
     Read-only listing of owned resources.
  4. ``edit-dns-record``   ``POST /zones/{ZONE_ID}/dns_records`` — GATED,
     mutating. Creating/changing a DNS record is state-changing impact
     (subdomain takeover, MX/traffic hijack). Its URL needs a ``ZONE_ID`` the
     engine cannot fill, so this rung is rendered as a MANUAL safe-curl note:
     it is never auto-fired and prints a curl that keeps the secret as
     ``$KEY``.

Every rung is ordered (identity first, then depth), the live rungs are all
READ-ONLY GETs, and the ladder never raises across the public boundary:
failures become a :class:`ProbeResult` with ``success=False`` so one dead key
cannot crash a batch run. The raw token is held only transiently for the HTTP
call and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "cloudflare_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("CloudflareApiToken", "CloudflareGlobalApiKey", "CloudflareCaKey")

API_BASE = "https://api.cloudflare.com/client/v4"

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


def _bearer(key: str) -> dict[str, str]:
    """Standard Cloudflare bearer header for a scoped API token."""
    return {"Authorization": f"Bearer {key}"}


@register("CloudflareApiToken", "CloudflareGlobalApiKey", "CloudflareCaKey")
async def cloudflare_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Cloudflare capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs ``verify-token`` first and only descends into the deeper SAFE rungs
    if the token authenticated. The mutating ``edit-dns-record`` rung is GATED
    and, because its URL needs a ``ZONE_ID`` the engine cannot fill, is emitted
    as a manual safe-curl note rather than a live call. Never raises across the
    public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: verify-token (SAFE) — decides live/dead ---------------------
    identity = await _verify_token(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: token-permissions (SAFE) --------------------------------
        rungs.append(await _token_permissions(key))

        # --- Rung 3: list-zones (SAFE) ---------------------------------------
        rungs.append(await _list_zones(key))

        # --- Rung 4: edit-dns-record (GATED, manual safe-curl) ---------------
        # The URL embeds a ZONE_ID the engine cannot fill, so this never fires
        # a live request: it is rendered as a manual note. The @gated wrapper
        # still enforces consent first, so without --prove + --i-am-authorized
        # the rung is recorded as blocked.
        rungs.append(await _maybe_edit_dns_record(consent))

    return LadderResult(
        finding=finding,
        provider="cloudflare",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _verify_token(key: str) -> ProbeResult:
    """SAFE: ``GET /user/tokens/verify`` confirms the token and its status."""
    name = "verify-token"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/user/tokens/verify",
                headers=_bearer(key),
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

    # Cloudflare wraps payloads as { success, result, errors, messages }.
    result = body.get("result") or {}
    if body.get("success") is not True or result.get("status") != "active":
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"token not active (status {result.get('status') or 'unknown'})",
            evidence={"status": resp.status_code, "token_status": result.get("status")},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"token active (id {result.get('id') or '?'})",
        evidence={
            "status": resp.status_code,
            "token_id": result.get("id"),
            "token_status": result.get("status"),
            "not_before": result.get("not_before"),
            "expires_on": result.get("expires_on"),
        },
    )


async def _token_permissions(key: str) -> ProbeResult:
    """SAFE: ``GET /user/tokens/permission_groups`` maps the token's scope depth."""
    name = "token-permissions"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/user/tokens/permission_groups",
                headers=_bearer(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list permission groups (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    groups = body.get("result") if isinstance(body.get("result"), list) else []
    # Record only non-secret identifiers (group names), never raw payloads.
    names = [g.get("name") for g in groups if isinstance(g, dict) and g.get("name")]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"{len(names)} permission group(s) assignable to this token",
        evidence={
            "status": resp.status_code,
            "permission_group_count": len(names),
            "permission_groups_sample": names[:25],
        },
    )


async def _list_zones(key: str) -> ProbeResult:
    """SAFE: ``GET /zones`` enumerates every zone/domain the token can reach."""
    name = "list-zones"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/zones",
                headers=_bearer(key),
                params={"per_page": "50"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list zones (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    zones = body.get("result") if isinstance(body.get("result"), list) else []
    # Record only non-sensitive identifiers (zone names), never DNS contents.
    names = [z.get("name") for z in zones if isinstance(z, dict) and z.get("name")]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=len(names) > 0,
        detail=(
            f"{len(names)} zone(s) reachable: {', '.join(names[:5])}"
            if names
            else "no zones reachable"
        ),
        evidence={
            "status": resp.status_code,
            "zone_count": len(names),
            "zones_sample": names[:25],
        },
    )


# --- gated (manual) rung -----------------------------------------------------


def _edit_dns_safe_curl() -> str:
    """The safe curl printed for the manual gated DNS-write rung (secret as $KEY)."""
    return (
        "curl -X POST "
        f"'{API_BASE}/zones/ZONE_ID/dns_records' "
        '-H "Authorization: Bearer $KEY" '
        '-H "Content-Type: application/json" '
        '--data \'{"type":"A","name":"probe.example.com",'
        '"content":"192.0.2.1","ttl":60,"proxied":false}\''
    )


@gated
async def cloudflare_gated_edit_dns(consent: Consent) -> ProbeResult:
    """GATED: ``POST /zones/{ZONE_ID}/dns_records`` would create/change a record.

    State-changing impact (subdomain takeover, MX/traffic hijack). Decorated
    with :func:`vtx_recon.safety.gated`, so the safety boundary runs *before*
    this body and, without BOTH ``--prove`` and an authorized scope, raises
    :class:`GatedProbeBlocked` and nothing executes. Even with consent this
    rung is MANUAL: the URL needs a ``ZONE_ID`` the engine cannot fill, so it
    never fires a live request — it only returns a safe curl (with the secret
    kept as ``$KEY``) for an operator to run by hand. The public ladder records
    it as a blocked/manual note either way.
    """
    name = "edit-dns-record"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: needs a ZONE_ID from list-zones; run the safe curl by "
            "hand to exercise the mutating impact"
        ),
        evidence={"manual": True, "safe_curl": _edit_dns_safe_curl()},
    )


async def _maybe_edit_dns_record(consent: Consent) -> ProbeResult:
    """Attempt the gated DNS-write rung; report it as blocked when consent is absent.

    The gating happens inside :func:`cloudflare_gated_edit_dns`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the mutating step by hand.
    """
    try:
        return await cloudflare_gated_edit_dns(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="edit-dns-record",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _edit_dns_safe_curl(),
            },
        )
