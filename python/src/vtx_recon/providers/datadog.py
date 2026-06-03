"""Datadog capability ladder — prove depth of access for a leaked API key.

Handles the TruffleHog ``DatadogToken`` finding: a 32-char hex Datadog **API
key** (``DD-API-KEY``). Datadog splits its credentials in two: the API key alone
is enough to *ingest* and to call ``GET /api/v1/validate``, but every read of
org / user / observability config additionally requires a paired **application
key** (``DD-APPLICATION-KEY``) — a second secret that is NOT present in the raw
API key. The engine can only fill the ``{key}`` placeholder, so any rung whose
headers embed ``{app_key}`` cannot be auto-fired.

The ordered ladder (identity/validity first, then depth):

  1. ``validate-api-key``  SAFE. ``GET /api/v1/validate`` with only
     ``DD-API-KEY`` confirms the key is live (returns ``{"valid": true}``).
     Read-only, idempotent, non-billable — this is the rung that decides VALID
     vs DENIED.
  2. ``list-current-user`` SAFE/MANUAL. ``GET /api/v2/current_user`` returns the
     user/org the keys map to (name, email, org) — whoami + depth. Requires BOTH
     ``DD-API-KEY`` and a paired ``DD-APPLICATION-KEY`` (second secret not in the
     raw key), so it is never auto-fired: it renders a safe curl that keeps the
     API key as ``$KEY`` and the app key as ``$APP_KEY``.
  3. ``list-monitors``     SAFE/MANUAL. ``GET /api/v1/monitor`` enumerates the
     org's own monitors (alert configs, query content), proving read access to
     observability config. Also needs the paired app key, so it is rendered as a
     manual safe-curl note rather than a live call.

Only the first rung makes a live request; the others are MANUAL because the
engine cannot supply the second secret. Every rung is ordered (validity first,
then depth), the live rung is a READ-ONLY GET, and the ladder never raises
across the public boundary: failures become a :class:`ProbeResult` with
``success=False`` so one dead key cannot crash a batch run. The raw key is held
only transiently for the HTTP call and never lands in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier
from . import register

__all__ = ["DETECTORS", "datadog_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("DatadogToken",)

API_BASE = "https://api.datadoghq.com"

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


# --------------------------------------------------------------------------- #
# safe-curl rendering (used only for the MANUAL app-key rungs)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(url: str) -> str:
    """Build a copy-pasteable curl for a Datadog read that needs BOTH keys.

    The API key is kept as the ``$KEY`` placeholder and the paired application
    key as ``$APP_KEY`` (the second secret is not in the raw finding), so the
    string never contains a live secret and is safe to print and to store.
    """
    parts = ["curl", "-sS", "-X", "GET"]
    parts.extend(["-H", _shquote("DD-API-KEY: $KEY")])
    parts.extend(["-H", _shquote("DD-APPLICATION-KEY: $APP_KEY")])
    parts.extend(["-H", _shquote("Accept: application/json")])
    parts.append(_shquote(url))
    return " ".join(parts)


@register("DatadogToken")
async def datadog_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Datadog capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs ``validate-api-key`` first (only ``DD-API-KEY`` is needed) and only
    descends into the deeper rungs if the key validated. Those deeper rungs each
    need a paired ``DD-APPLICATION-KEY`` (a second secret not in the raw key), so
    they are emitted as MANUAL safe-curl notes rather than live calls. Never
    raises across the public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: validate-api-key (SAFE) — validity, decides live/dead -------
    identity = await _validate_api_key(key)
    rungs.append(identity)

    # Only climb deeper if the key validated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-current-user (SAFE / MANUAL app-key rung) ----------
        # Needs a paired DD-APPLICATION-KEY the engine cannot supply, so it
        # never fires a live request: it is rendered as a manual safe-curl note.
        rungs.append(_list_current_user_manual())

        # --- Rung 3: list-monitors (SAFE / MANUAL app-key rung) --------------
        rungs.append(_list_monitors_manual())

    return LadderResult(
        finding=finding,
        provider="datadog",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _validate_api_key(key: str) -> ProbeResult:
    """SAFE: ``GET /api/v1/validate`` confirms the API key is live.

    Returns ``{"valid": true}`` for a live key. Needs only ``DD-API-KEY`` —
    read-only, idempotent, non-billable. This is the validity/identity rung that
    decides VALID vs DENIED. Records only the non-secret ``valid`` flag, never
    the key.
    """
    name = "validate-api-key"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/api/v1/validate",
                headers={"DD-API-KEY": key, "Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"API key rejected (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # Datadog returns 200 with {"valid": true} for a live key. Treat an explicit
    # non-true `valid` as a rejection so a soft-failure body is not a false VALID.
    if body.get("valid") is not True:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail="API key reported not valid",
            evidence={"status": resp.status_code, "valid": body.get("valid")},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail="API key is live (validate returned valid=true)",
        evidence={"status": resp.status_code, "valid": True},
    )


def _list_current_user_manual() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/v2/current_user`` returns the user/org the keys
    map to (name, email, org) — whoami + depth.

    Requires BOTH ``DD-API-KEY`` and a paired ``DD-APPLICATION-KEY`` (a second
    secret NOT present in the raw API key), so the engine cannot fill the
    ``{app_key}`` header — no live call is made. The operator is handed the exact
    safe curl (API key ``$KEY``, app key ``$APP_KEY``).
    """
    name = "list-current-user"
    url = f"{API_BASE}/api/v2/current_user"
    curl = _safe_curl(url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs a paired DD-APPLICATION-KEY (a second secret not in the "
            "raw API key); run this by hand to reveal the user/org the keys map to "
            f"(name, email, org): {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


def _list_monitors_manual() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/v1/monitor`` enumerates the org's own monitors
    (alert configs, query content), proving read access to observability config.

    Read-only, non-billable. Also needs the paired ``DD-APPLICATION-KEY`` (second
    secret not in the raw key), so no live call is made — the operator is handed
    the safe curl.
    """
    name = "list-monitors"
    url = f"{API_BASE}/api/v1/monitor"
    curl = _safe_curl(url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the paired DD-APPLICATION-KEY (second secret not in the "
            "raw key); run this by hand to enumerate the org's monitors (alert "
            "configs / query content) and prove read access to observability "
            f"config: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )
