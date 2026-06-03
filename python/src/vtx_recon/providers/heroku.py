"""Heroku Platform API capability ladder — prove depth of access for a key.

A TruffleHog ``Heroku`` finding is a Platform API key (a UUID). The key is sent
as ``Authorization: Bearer <key>`` with
``Accept: application/vnd.heroku+json; version=3``. The ladder climbs from
identity to reach, then stops at a GATED rung that would dump an app's secret
config vars.

The ordered ladder (depth of access, least -> most revealing):

  1. ``account``           ``GET /account`` — SAFE. Identity / whoami: returns
     the account id, email, name and 2FA status. This is TruffleHog's own
     verification call; it decides VALID vs DENIED. Read-only.
  2. ``list-apps``         ``GET /apps`` — SAFE. Enumerates every app the key
     can administer (names, regions, owners) — reach across deployments beyond
     auth. Read-only.
  3. ``read-config-vars``  ``GET /apps/APP_ID/config-vars`` — GATED. Dumps an
     app's environment variables (``DATABASE_URL``, third-party API keys,
     secrets enabling lateral movement). Routed through
     :func:`vtx_recon.safety.gated` so the SAFE tier can never reach it; and
     because its URL needs an ``APP_ID`` (from ``list-apps``) the engine cannot
     substitute, even under full consent it never auto-fires — it renders a
     copy-pasteable safe curl (secret kept as ``$KEY``) for the operator to run
     by hand. It stays GATED because it reads sensitive secret material.

Every automated rung is a READ-ONLY ``GET``. The ladder never raises across its
public boundary: failures become a :class:`ProbeResult` with ``success=False``
so one dead key cannot crash a batch run. The raw key is held only transiently
for the HTTP call and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["heroku_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

_API_BASE = "https://api.heroku.com"

# The exact, copy-pasteable safe curl for the manual gated rung. The secret is
# NEVER interpolated: it stays the literal ``$KEY`` shell variable, and the
# ``APP_ID`` placeholder is left for the operator to fill from list-apps.
_READ_CONFIG_VARS_SAFE_CURL = (
    "curl -sS -X GET "
    "-H 'Authorization: Bearer $KEY' "
    "-H 'Accept: application/vnd.heroku+json; version=3' "
    "'https://api.heroku.com/apps/APP_ID/config-vars'"
)


def _headers(key: str) -> dict[str, str]:
    """Standard Heroku Platform API headers carrying the bearer key."""
    return {
        "Authorization": f"Bearer {key}",
        "Accept": "application/vnd.heroku+json; version=3",
    }


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


@register("Heroku")
async def heroku_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Heroku ladder: SAFE ``/account`` -> SAFE ``/apps`` -> GATED config dump.

    The two SAFE rungs are read-only (identity, then app reach). The config-var
    dump is GATED because it reveals downstream secrets; its URL needs an
    ``APP_ID`` the engine cannot fill, so it is rendered as a manual safe-curl
    rung that never auto-fires.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: identity (SAFE) ---
    identity = await _heroku_account(key)
    rungs.append(identity)

    # Only climb deeper if the key authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: reach across apps (SAFE) ---
        rungs.append(await _heroku_list_apps(key))

        # --- Rung 3: config-var dump (GATED, manual safe-curl) ---
        # The @gated wrapper enforces consent BEFORE the body runs; without BOTH
        # --prove and --i-am-authorized it raises GatedProbeBlocked, captured
        # here as a `blocked` rung so the ladder never raises across the public
        # boundary. When consent IS granted the body still makes no live call:
        # the URL needs an APP_ID the engine cannot fill, so it returns a manual
        # safe-curl rung.
        try:
            rungs.append(await _heroku_read_config_vars(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="read-config-vars",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "reason": blocked.reason,
                        "manual": True,
                        "safe_curl": _READ_CONFIG_VARS_SAFE_CURL,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="heroku",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _heroku_account(key: str) -> ProbeResult:
    """SAFE: ``GET /account`` confirms the key and returns account identity."""
    name = "account"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_API_BASE}/account", headers=_headers(key))
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

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"authenticated as {body.get('email') or body.get('id')} (id {body.get('id')})",
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "email": body.get("email"),
            "name": body.get("name"),
            "two_factor_authentication": body.get("two_factor_authentication"),
        },
    )


async def _heroku_list_apps(key: str) -> ProbeResult:
    """SAFE: ``GET /apps`` enumerates every app the key can administer (reach)."""
    name = "list-apps"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_API_BASE}/apps", headers=_headers(key))
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list apps (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        apps = resp.json()
    except ValueError:
        apps = []
    if not isinstance(apps, list):
        apps = []
    # Record only non-sensitive identifiers (app names), never app contents.
    names = [a.get("name") for a in apps if isinstance(a, dict) and a.get("name")]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=len(names) > 0,
        detail=(
            f"{len(names)} app(s) administrable: {', '.join(names)}"
            if names
            else "no apps administrable with this key"
        ),
        evidence={"status": resp.status_code, "app_count": len(names), "apps": names[:25]},
    )


@gated
async def _heroku_read_config_vars(consent: Consent, key: str) -> ProbeResult:
    """GATED + MANUAL: ``GET /apps/APP_ID/config-vars`` would dump app secrets.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary raises
    :class:`GatedProbeBlocked` *before* this body runs unless BOTH ``--prove``
    and ``--i-am-authorized`` were supplied. Even under full consent the body
    makes NO live call — the URL needs an ``APP_ID`` (a non-``{key}``
    placeholder, from ``list-apps``) the engine cannot fill — so it returns a
    manual safe-curl rung that keeps the secret as the literal ``$KEY`` shell
    variable for an operator to run by hand. Reading config vars dumps
    downstream secrets (``DATABASE_URL``, API keys) usable for lateral movement,
    which is exactly why it is gated.
    """
    return ProbeResult(
        name="read-config-vars",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs an APP_ID from list-apps; dumps app env vars "
            f"(DATABASE_URL, API secrets). Run this by hand: {_READ_CONFIG_VARS_SAFE_CURL}"
        ),
        evidence={"manual": True, "safe_curl": _READ_CONFIG_VARS_SAFE_CURL},
    )
