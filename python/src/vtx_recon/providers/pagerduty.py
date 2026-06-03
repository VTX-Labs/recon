"""PagerDuty capability ladder — prove depth of access from a leaked API key.

Handles the TruffleHog ``PagerDutyApiKey`` finding: a REST API key used with the
``Authorization: Token token={key}`` header (works for both account-level and
user-scoped tokens). The key alone is enough to authenticate, so the read-only
rungs fire live; only the impactful write needs an out-of-band value.

Ordered ladder (identity / capability first, then depth, then impact):

#. ``abilities`` — SAFE. ``GET /abilities`` lists the account's enabled
   abilities/features — the cheapest validity + capability check. Works for
   account and user tokens alike. Read-only, idempotent, non-billable.
#. ``list-users`` — SAFE. ``GET /users?limit=1`` enumerates the account's own
   operator staff — proves ``users.read`` scope and full-account (vs scoped)
   reach. Read-only, non-billable.
#. ``create-incident`` — GATED / MANUAL. ``POST /incidents`` triggers a REAL
   incident: pages on-call responders and notifies third parties. This is the
   impact the program cares about — state-changing and human-notifying, so it
   never auto-fires. It is also MANUAL: the request needs a ``From:`` header (an
   account email) that is NOT present in the raw key, so the engine cannot fill
   it. Routed through :func:`vtx_recon.safety.gated` so it is structurally
   unreachable without BOTH ``--prove`` and ``--i-am-authorized "<scope>"``; even
   with consent it only renders a safe curl (secret kept as ``$KEY``).

The ladder never raises across its public boundary: every failure becomes a
:class:`ProbeResult`. Secrets are held only transiently for the live HTTP calls
and never land in :attr:`ProbeResult.evidence`; only non-secret values (ids,
names, scopes, counts) are recorded.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["pagerduty_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# PagerDuty REST API requires this versioned Accept header.
_ACCEPT = "application/vnd.pagerduty+json;version=2"


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

    NOTE: the only GATED rung here is MANUAL (it never fires a live call, so it
    is never ``success=True``), meaning a clean run tops out at VALID — proving
    live impact requires the operator to run the rendered curl by hand.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# safe-curl rendering (for the MANUAL gated rung — no live call is made there)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _create_incident_curl() -> str:
    """Build a copy-pasteable curl for the gated ``POST /incidents`` call.

    The token is kept as a ``$KEY`` placeholder and the required ``From:``
    account email as ``$FROM_EMAIL``; the JSON body is left as a ``$BODY``
    placeholder. The string never contains a live secret, so it is safe to print
    and to store.
    """
    parts = ["curl", "-sS", "-X", "POST"]
    parts.extend(["-H", _shquote("Authorization: Token token=$KEY")])
    parts.extend(["-H", _shquote(f"Accept: {_ACCEPT}")])
    parts.extend(["-H", _shquote("Content-Type: application/json")])
    parts.extend(["-H", _shquote("From: $FROM_EMAIL")])
    parts.extend(["-d", _shquote("$BODY")])
    parts.append(_shquote("https://api.pagerduty.com/incidents"))
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# rung 1 — SAFE: abilities (validity + account capability)
# --------------------------------------------------------------------------- #


async def _pagerduty_abilities(key: str) -> ProbeResult:
    """SAFE: ``GET /abilities`` lists the account's enabled abilities/features.

    The cheapest validity check that also reveals capability, and it works for
    both account and user tokens. Read-only, idempotent, non-billable.
    """
    name = "abilities"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.pagerduty.com/abilities",
                headers={"Authorization": f"Token token={key}", "Accept": _ACCEPT},
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

    abilities = body.get("abilities") if isinstance(body.get("abilities"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"key authenticates; account has {len(abilities)} enabled abilities",
        evidence={
            "status": resp.status_code,
            "ability_count": len(abilities),
            # A small, bounded sample of NON-secret feature names proves
            # capability without dumping the whole list.
            "abilities_sample": abilities[:10],
        },
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE: list-users (reachable-data depth / scope)
# --------------------------------------------------------------------------- #


async def _pagerduty_list_users(key: str) -> ProbeResult:
    """SAFE: ``GET /users?limit=1`` enumerates the account's own operator staff.

    Proves ``users.read`` scope and whether the token has full-account (vs
    scoped) reach. First-party staff data, read-only, non-billable. We record
    only counts and non-secret identifiers — never email/PII bodies.
    """
    name = "list-users"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.pagerduty.com/users?limit=1",
                headers={"Authorization": f"Token token={key}", "Accept": _ACCEPT},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not enumerate users (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    users = body.get("users") if isinstance(body.get("users"), list) else []
    first = users[0] if users else {}
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            "enumerated account users (users.read confirmed; "
            f"more={body.get('more') is True}, page total={len(users)})"
        ),
        evidence={
            "status": resp.status_code,
            "returned": len(users),
            "more": body.get("more"),
            # Non-secret identifiers from the first record only; no emails/PII.
            "first_user_id": first.get("id"),
            "first_user_role": first.get("role"),
        },
    )


# --------------------------------------------------------------------------- #
# rung 3 — GATED / MANUAL: create-incident (real-world impact)
# --------------------------------------------------------------------------- #


@gated
async def _pagerduty_create_incident(consent: Consent) -> ProbeResult:
    """GATED / MANUAL: ``POST /incidents`` triggers a REAL incident.

    Pages on-call responders and notifies third parties. This is the impact the
    program cares about: state-changing and human-notifying, so it must NEVER
    auto-fire. Decorated with :func:`vtx_recon.safety.gated`: the safety boundary
    runs *before* this body, so without BOTH ``--prove`` and an authorized scope
    it raises :class:`GatedProbeBlocked` and nothing is rendered as runnable.
    Even WITH consent it is MANUAL — the request needs a ``From:`` account-email
    header that is not in the raw key, so the engine cannot fill it. It therefore
    returns the safe curl for the operator rather than firing.
    """
    name = "create-incident"
    curl = _create_incident_curl()
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would trigger a REAL incident (pages on-call responders, "
            "notifies third parties). Needs a From: account-email header not in the "
            f"raw key; run by hand only when authorized: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [201]},
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("PagerDutyApiKey")
async def pagerduty_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered PagerDuty capability ladder for one finding.

    Refuses to ladder without an authorized scope. The two SAFE rungs fire live
    (identity/capability first, then read depth) and only climb if the key
    authenticated. The GATED ``create-incident`` rung is reached only through the
    safety boundary: when consent is missing it is recorded as a blocked rung;
    when consent is present it still only renders a safe curl (MANUAL — the From
    email is not in the key). Never raises across this boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # Rung 1 (SAFE): validity + capability. Identity rung — only climb deeper if
    # the key authenticated at all (ordered ladder).
    identity = await _pagerduty_abilities(key)
    rungs.append(identity)

    if identity.success:
        # Rung 2 (SAFE): reachable-data depth / scope.
        rungs.append(await _pagerduty_list_users(key))

        # Rung 3 (GATED/MANUAL): real-world impact. Reachable only via the
        # @gated wrapper; without full consent it raises GatedProbeBlocked,
        # recorded as a blocked rung (the safe curl is still surfaced as
        # evidence). The ladder never raises across its public boundary.
        incident_curl = _create_incident_curl()
        try:
            rungs.append(await _pagerduty_create_incident(consent))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="create-incident",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "reason": blocked.reason,
                        "manual": True,
                        "billable": False,
                        "safe_curl": incident_curl,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="pagerduty",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
