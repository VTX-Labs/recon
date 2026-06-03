"""Mailgun capability ladder — prove depth of access for a leaked API key.

Handles TruffleHog ``Mailgun`` findings. A Mailgun key is either the legacy
``key-<32 hex/alnum>`` form or the newer ``<32 hex>-<8 hex>-<8 hex>`` form, and
authenticates as the password of HTTP Basic auth (username ``api``). Per the
provider spec the header is rendered as ``Authorization: Basic {key}``, where
the engine substitutes ``{key}`` with the live secret before the call.

Mailgun has NO whoami endpoint, so the domains list doubles as the identity
proof and the depth proof — it is also the family TruffleHog probes.

The ordered ladder (depth of access, least -> most revealing):

  1. ``list-domains``     ``GET /v4/domains?limit=10`` — confirms the key
     authenticates and reveals which sending domains it can reach (reachable
     resources you own). This is the identity/depth rung and decides VALID vs
     DENIED. Read-only, non-billable.
  2. ``list-domain-keys`` ``GET /v1/dkim/keys?limit=10`` — reads DKIM
     signing-key metadata across all domains, confirming account-wide read
     depth beyond a single domain. Read-only, non-billable.
  3. ``send-message``     ``POST /v3/{domain}/messages`` — GATED, billable and
     reputation-impacting (sends email on the victim's domain). Its URL needs a
     ``{domain}`` path segment (from ``list-domains``) the engine cannot fill,
     so this rung is rendered as a MANUAL safe-curl note: it is never auto-fired
     and prints a curl that keeps the secret as ``$KEY``.

Every rung is ordered (identity first, then depth), the live rungs are all
READ-ONLY GETs, and the ladder never raises across the public boundary:
failures become a :class:`ProbeResult` with ``success=False`` so one dead key
cannot crash a batch run. The raw key is held only transiently for the HTTP
call and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "mailgun_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Mailgun",)

API_BASE = "https://api.mailgun.net"

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


def _basic_auth(key: str) -> dict[str, str]:
    """Mailgun HTTP Basic header per the provider spec (``Basic {key}``)."""
    return {"Authorization": f"Basic {key}"}


@register("Mailgun")
async def mailgun_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Mailgun capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs ``list-domains`` first (Mailgun has no whoami) and only descends into
    the deeper SAFE rung if the key authenticated. The billable ``send-message``
    rung is GATED and, because its URL needs a ``{domain}`` segment the engine
    cannot fill, is emitted as a manual safe-curl note rather than a live call.
    Never raises across the public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: list-domains (SAFE) — identity/depth, decides live/dead -----
    identity = await _list_domains(key)
    rungs.append(identity)

    # Only climb deeper if the key authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-domain-keys (SAFE) ---------------------------------
        rungs.append(await _list_domain_keys(key))

        # --- Rung 3: send-message (GATED, manual safe-curl) ------------------
        # The URL embeds a {domain} segment the engine cannot fill, so this
        # never fires a live request: it is rendered as a manual note. The
        # @gated wrapper still enforces consent first, so without --prove +
        # --i-am-authorized the rung is recorded as blocked.
        rungs.append(await _maybe_send_message(consent))

    return LadderResult(
        finding=finding,
        provider="mailgun",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _list_domains(key: str) -> ProbeResult:
    """SAFE: ``GET /v4/domains?limit=10`` confirms the key and lists domains.

    Mailgun has no whoami; this list is the identity AND the depth proof.
    Records only non-secret domain names/counts, never message contents.
    """
    name = "list-domains"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/v4/domains",
                headers=_basic_auth(key),
                params={"limit": "10"},
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

    items = body.get("items") if isinstance(body.get("items"), list) else []
    # Record only non-secret identifiers (domain names), never message data.
    names = [d.get("name") for d in items if isinstance(d, dict) and d.get("name")]
    total = body.get("total_count")
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"key authenticates; {len(names)} domain(s) reachable: {', '.join(names[:5])}"
            if names
            else "key authenticates; no sending domains reachable"
        ),
        evidence={
            "status": resp.status_code,
            "domain_count": len(names),
            "domains_sample": names[:25],
            "total_count": total if isinstance(total, int) else None,
        },
    )


async def _list_domain_keys(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/dkim/keys?limit=10`` reads DKIM signing-key metadata.

    Reads DKIM signing-key metadata across all domains, confirming account-wide
    read depth beyond a single domain. Records only non-secret metadata
    (counts / signing domains), never private key material.
    """
    name = "list-domain-keys"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/v1/dkim/keys",
                headers=_basic_auth(key),
                params={"limit": "10"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not read DKIM keys (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    items = body.get("items") if isinstance(body.get("items"), list) else []
    # Record only the signing-domain names (non-secret), never key material.
    signing = [
        k.get("signing_domain") for k in items if isinstance(k, dict) and k.get("signing_domain")
    ]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"{len(items)} DKIM signing-key record(s) readable account-wide",
        evidence={
            "status": resp.status_code,
            "dkim_key_count": len(items),
            "signing_domains_sample": signing[:25],
        },
    )


# --- gated (manual) rung -----------------------------------------------------


def _send_message_safe_curl() -> str:
    """The safe curl printed for the manual gated send-message rung (secret as $KEY)."""
    return (
        "curl -X POST "
        f"'{API_BASE}/v3/DOMAIN/messages' "
        '-H "Authorization: Basic $KEY" '
        '-H "Content-Type: application/x-www-form-urlencoded" '
        "--data-urlencode 'from=probe@DOMAIN' "
        "--data-urlencode 'to=you@example.com' "
        "--data-urlencode 'subject=vtx-recon authorized probe' "
        "--data-urlencode 'text=authorized capability proof'"
    )


@gated
async def mailgun_gated_send_message(consent: Consent) -> ProbeResult:
    """GATED: ``POST /v3/{domain}/messages`` would send email on the domain.

    Billable and reputation-impacting impact (the action the program cares
    about). Decorated with :func:`vtx_recon.safety.gated`, so the safety
    boundary runs *before* this body and, without BOTH ``--prove`` and an
    authorized scope, raises :class:`GatedProbeBlocked` and nothing executes.
    Even with consent this rung is MANUAL: the URL needs a ``{domain}`` segment
    (from ``list-domains``) the engine cannot fill, so it never fires a live
    request — it only returns a safe curl (with the secret kept as ``$KEY``) for
    an operator to run by hand. The public ladder records it as a blocked/manual
    note either way.
    """
    name = "send-message"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: needs a {domain} from list-domains; run the safe curl "
            "by hand to exercise the billable send impact"
        ),
        evidence={"manual": True, "safe_curl": _send_message_safe_curl()},
    )


async def _maybe_send_message(consent: Consent) -> ProbeResult:
    """Attempt the gated send-message rung; report it as blocked when consent is absent.

    The gating happens inside :func:`mailgun_gated_send_message`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the billable step by hand.
    """
    try:
        return await mailgun_gated_send_message(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="send-message",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _send_message_safe_curl(),
            },
        )
