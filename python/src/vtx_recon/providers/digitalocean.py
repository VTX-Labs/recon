"""DigitalOcean capability ladder — prove depth of access from a leaked token.

A TruffleHog ``DigitalOceanV2`` / ``DigitalOceanToken`` finding is a modern
DigitalOcean credential — a Personal Access Token or OAuth token shaped
``dop_v1_`` / ``doo_v1_`` / ``dor_v1_`` followed by 64 hex chars. Every rung
uses the same ``Authorization: Bearer {key}`` header against
``api.digitalocean.com``.

The ordered ladder (least -> most revealing, then impact):

#. ``account``        — SAFE. ``GET /v2/account`` is TruffleHog's own
   verification call. Returns the account email, uuid, status and resource
   limits: confirms the token authenticates and reveals the owning account.
   Read-only; decides VALID vs DENIED.
#. ``list-droplets``  — SAFE. ``GET /v2/droplets`` enumerates every droplet the
   token can reach (``droplet:read``): depth of access into compute, public
   IPs, regions. A read-only listing of owned resources.
#. ``create-droplet`` — GATED. ``POST /v2/droplets`` would provision a new
   *billable* droplet (a 202-Accepted, state-changing, crypto-mining/abuse
   vector). Routed through :func:`vtx_recon.safety.gated` so the SAFE tier can
   never reach it, AND — because creation needs a request body the engine
   cannot fill from ``{key}`` alone (name/region/size/image) — it never
   auto-fires even under full consent: it renders a safe curl only, so no
   billable droplet is ever created and the "no state changed" attestation
   holds.

Every rung is ordered (identity first, then depth), READ-ONLY by default, and
never raises across the public boundary: failures become a :class:`ProbeResult`
with ``success=False`` so one dead key cannot crash a batch run. The raw token
is held only transiently for the HTTP call and only non-secret fields ever land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["digitalocean_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

_API_BASE = "https://api.digitalocean.com"


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


def _create_droplet_curl() -> str:
    """Render the safe, copy-pasteable curl for the gated creation.

    The secret is kept as the ``$DO_TOKEN`` shell variable so it is never
    written into evidence. This is what the gated rung prints instead of
    provisioning anything.
    """
    return (
        'curl -sS -X POST "https://api.digitalocean.com/v2/droplets" '
        '-H "Authorization: Bearer $DO_TOKEN" -H "Content-Type: application/json" '
        '-d \'{"name":"authorized-probe","region":"nyc3",'
        '"size":"s-1vcpu-1gb","image":"ubuntu-22-04-x64"}\''
    )


@register("DigitalOceanV2", "DigitalOceanToken")
async def digitalocean_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """DigitalOcean ladder: SAFE account whoami -> SAFE droplet listing ->
    GATED (never-auto-fired) droplet creation.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # Rung 1 (SAFE): identity / whoami. Decides VALID vs DENIED.
    identity = await _do_account(key)
    rungs.append(identity)

    # Only climb deeper if the token actually authenticated (ordered ladder).
    if identity.success:
        # Rung 2 (SAFE): enumerate reachable droplets (depth of compute access).
        rungs.append(await _do_list_droplets(key))

        # Rung 3 (GATED): droplet creation. Reachable only with full consent;
        # even then it never fires a real POST (creation is billable and needs
        # a body the engine cannot fill) — the @gated wrapper raises
        # GatedProbeBlocked when consent is absent, otherwise we render a safe
        # curl. Either way we record a non-success rung so the "no state
        # changed" attestation holds.
        try:
            rungs.append(await _do_create_droplet(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="create-droplet",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "manual": True,
                        "reason": blocked.reason,
                        "safe_curl": _create_droplet_curl(),
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="digitalocean",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _do_account(key: str) -> ProbeResult:
    """SAFE: ``GET /v2/account`` — TruffleHog's verification call.

    Returns the account email, uuid, status and resource limits, proving the
    token is live and revealing the owning account. Read-only; no billable
    action. Success here is the difference between VALID and DENIED.
    """
    name = "account"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/v2/account",
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
    account = body.get("account") or {}

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {account.get('email', 'unknown')} "
            f"(status {account.get('status', '?')})"
        ),
        evidence={
            "status": resp.status_code,
            "email": account.get("email"),
            "uuid": account.get("uuid"),
            "account_status": account.get("status"),
            "droplet_limit": account.get("droplet_limit"),
            "email_verified": account.get("email_verified"),
        },
    )


async def _do_list_droplets(key: str) -> ProbeResult:
    """SAFE: ``GET /v2/droplets`` — enumerate every droplet the token can reach.

    Proves depth of access into compute (``droplet:read``): how many droplets,
    in which regions. Read-only listing of owned resources; only non-secret
    identifiers (ids, names, regions, counts) are recorded.
    """
    name = "list-droplets"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/v2/droplets",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list droplets (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    droplets = body.get("droplets")
    if not isinstance(droplets, list):
        droplets = []
    # Record only non-sensitive identifiers — never any droplet's contents.
    names = [d.get("name") for d in droplets if isinstance(d, dict) and d.get("name")]
    regions = sorted(
        {
            d["region"]["slug"]
            for d in droplets
            if isinstance(d, dict) and isinstance(d.get("region"), dict) and d["region"].get("slug")
        }
    )

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=len(droplets) > 0,
        detail=(
            f"{len(droplets)} droplet(s) reachable across {len(regions)} region(s)"
            if droplets
            else "no droplets reachable (token may still create new ones)"
        ),
        evidence={
            "status": resp.status_code,
            "droplet_count": len(droplets),
            "regions": regions,
            "droplet_names_sample": names[:25],
        },
    )


@gated
async def _do_create_droplet(consent: Consent, key: str) -> ProbeResult:
    """GATED: ``POST /v2/droplets`` would provision a new *billable* droplet.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and nothing is sent. Even WITH full
    consent we do not fire the POST — droplet creation is billable and
    irreversible, and the request body (name/region/size/image) is
    operator-supplied data the engine cannot fill from ``{key}``. So this rung
    is manual by design: it renders a safe curl and returns a non-success
    result, never creating a droplet (returns 202 on a real call).
    """
    # Consent WAS granted (the @gated boundary let this body run), so this is
    # not a `blocked` rung — it is a deliberate MANUAL no-op: the request body
    # (name/region/size/image) cannot be filled from ``{key}``, so we render a
    # safe curl instead of provisioning a billable droplet.
    return ProbeResult(
        name="create-droplet",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "gated billable action: droplet creation is never auto-run "
            "(state-changing, returns 202); run the safe curl by hand if authorized"
        ),
        evidence={
            "manual": True,
            "safe_curl": _create_droplet_curl(),
            "success_status": 202,
        },
    )
