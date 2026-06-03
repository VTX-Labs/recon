"""Capability ladder for Netlify personal access / OAuth tokens.

A Netlify token is a 43-45 char ``[A-Za-z0-9_-]`` bearer credential. This
ladder climbs three rungs, identity first, never exercising a write:

* **user** (SAFE) — ``GET /api/v1/user`` is the whoami: it returns the
  owning user's id, email and full name, confirming the token authenticates
  and who it belongs to. Read-only.
* **list-sites** (SAFE) — ``GET /api/v1/sites`` enumerates every Netlify
  site the token can reach (names, custom domains, admin urls). This is also
  TruffleHog's verification call; it measures depth across deployments
  without changing anything.
* **read-site-env** (GATED) — ``GET /api/v1/accounts/{account_id}/env`` reads
  the account/site build environment variables: downstream API keys and
  secrets that enable lateral movement. It is GATED because it reads
  sensitive secret material, and because its URL needs an ``ACCOUNT_ID`` the
  engine cannot fill, it never auto-fires — it is emitted as a MANUAL
  safe-curl note (the secret rendered as ``$KEY``) only after the gated
  consent boundary is satisfied.

Every rung is ordered (identity first, then depth), READ-ONLY by default,
and never raises across the public boundary: failures become a
:class:`ProbeResult` with ``success=False`` so one dead key cannot crash a
batch run. The raw token is held only transiently for the HTTP call and only
non-secret values are ever placed in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["netlify_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# The exact safe curl an operator runs by hand for the gated env read. The
# live secret stays a ``$KEY`` placeholder and the unfillable ``ACCOUNT_ID`` is
# left for the operator to substitute (from ``GET /api/v1/accounts``).
_READ_SITE_ENV_CURL = (
    "curl -sS -X GET "
    "-H 'Authorization: Bearer $KEY' "
    "'https://api.netlify.com/api/v1/accounts/ACCOUNT_ID/env'"
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


@register("Netlify")
async def netlify_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Netlify ladder: SAFE whoami (/user) -> SAFE sites (/sites) -> GATED env.

    The env read is GATED and MANUAL: it needs an ``ACCOUNT_ID`` the engine
    cannot fill, so it never fires a live call even with consent.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _netlify_user(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _netlify_list_sites(key))

        # The env read is GATED. The @gated wrapper enforces consent BEFORE any
        # work; if consent is missing it raises GatedProbeBlocked, captured here
        # as a `blocked` rung. If consent IS granted the rung still does NOT
        # fire a live call — its URL needs an ACCOUNT_ID the engine cannot fill
        # — so it returns a MANUAL safe-curl note instead. The ladder never
        # raises across the public boundary.
        try:
            rungs.append(await _netlify_read_site_env(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="netlify.read-site-env",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated env read blocked: {blocked.reason}",
                    evidence={
                        "reason": blocked.reason,
                        "manual": True,
                        "safe_curl": _READ_SITE_ENV_CURL,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="netlify",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _netlify_user(key: str) -> ProbeResult:
    """SAFE: ``GET /api/v1/user`` is the whoami — confirms identity/ownership."""
    name = "netlify.user"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.netlify.com/api/v1/user",
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

    who = body.get("full_name") or body.get("email") or "unknown"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"authenticated as {who} (id {body.get('id')})",
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "email": body.get("email"),
            "full_name": body.get("full_name"),
        },
    )


async def _netlify_list_sites(key: str) -> ProbeResult:
    """SAFE: ``GET /api/v1/sites`` enumerates every reachable site.

    Depth across deployments (names, custom domains, admin urls) — also
    TruffleHog's verification call. Read-only listing of owned resources.
    """
    name = "netlify.list-sites"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.netlify.com/api/v1/sites",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list sites (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    sites = body if isinstance(body, list) else []
    # Summarise reach, do not dump: keep names/domains/account ids only.
    names = [s.get("name") for s in sites if isinstance(s, dict) and s.get("name")]
    custom_domains = [
        s.get("custom_domain") for s in sites if isinstance(s, dict) and s.get("custom_domain")
    ]
    account_ids = sorted(
        {s.get("account_id") for s in sites if isinstance(s, dict) and s.get("account_id")}
    )

    detail = f"token reaches {len(sites)} site(s)"
    if names:
        detail += ": " + ", ".join(str(n) for n in names[:10])
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=detail,
        evidence={
            "status": resp.status_code,
            "site_count": len(sites),
            "site_names": names[:25],
            "custom_domains": custom_domains[:25],
            "account_ids": account_ids,
        },
    )


@gated
async def _netlify_read_site_env(consent: Consent, key: str) -> ProbeResult:
    """GATED + MANUAL: read account/site build environment variables.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope
    it raises :class:`GatedProbeBlocked` and nothing happens. Even *with*
    consent this rung never fires a live request: its URL needs an
    ``ACCOUNT_ID`` the engine cannot fill, so it emits the copy-pasteable
    safe curl (secret as ``$KEY``) instead. This reads sensitive secret
    material (downstream API keys), which is exactly why it is gated.
    """
    return ProbeResult(
        name="netlify.read-site-env",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs an ACCOUNT_ID (from GET /api/v1/accounts) or site_id "
            f"scope; run this by hand once you have one: {_READ_SITE_ENV_CURL}"
        ),
        evidence={"manual": True, "safe_curl": _READ_SITE_ENV_CURL},
    )
