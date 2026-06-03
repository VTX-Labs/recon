"""Capability ladder for Square access tokens.

Square OAuth / personal access tokens (``EAAA...``) authenticate via an
``Authorization: Bearer <token>`` header against ``connect.squareup.com``.
TruffleHog surfaces them under the ``Square`` detector. Every request is pinned
to a fixed API version (``Square-Version: 2024-01-18``) so the parsed shapes are
stable. The ladder climbs:

* **``list-locations``** (SAFE) — ``GET /v2/locations`` confirms the token
  authenticates and reaches the seller account, returning the seller's own
  business locations (names, addresses, status). Read-only, idempotent, and no
  third-party PII — this is the whoami / ground-truth that the key is live.
* **``retrieve-merchant-me``** (SAFE) — ``GET /v2/merchants/me`` resolves the
  merchant the token is scoped to (merchant_id, business_name, country,
  currency). Identity depth; requires ``MERCHANT_PROFILE_READ``.
* **``list-team-members``** (SAFE) — ``POST /v2/team-members/search`` lists the
  seller's own team members (employees), proving ``EMPLOYEES_READ``. A POST, but
  a read-only search: no state change, no billing. The PII is first-party (the
  operator's own staff), so it stays SAFE.
* **``create-payment``** (GATED) — ``POST /v2/payments`` charges money via the
  seller's Square account (``PAYMENTS_WRITE``). Billable and state-changing — the
  real impact. It is GATED *and* rendered MANUAL: a live charge needs a
  ``source_id``, ``amount_money``, and ``idempotency_key`` that the engine cannot
  synthesise, so the rung never fires — even with consent it only hands back a
  safe curl that keeps the secret as ``$KEY``.

Every rung is ordered (identity first, then depth), READ-ONLY by default, and
never raises across the public boundary: failures become a :class:`ProbeResult`
with ``success=False`` so one dead key cannot crash a batch run. The raw token is
held only transiently for the HTTP call and never lands in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import json

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["square_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# Every Square request is pinned to one API version so parsed shapes are stable.
_SQUARE_VERSION = "2024-01-18"


def _square_headers(key: str) -> dict[str, str]:
    """Headers every Square rung sends: Bearer auth + pinned API version."""
    return {
        "Authorization": f"Bearer {key}",
        "Square-Version": _SQUARE_VERSION,
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


def _safe_curl(method: str, url: str, headers: dict[str, str], body: str | None = None) -> str:
    """A ``\\``-joined, shell-safe curl that keeps the live secret as ``$KEY``."""
    parts = [f"curl -X {method} {json.dumps(url)}"]
    for name, value in headers.items():
        parts.append(f"-H {json.dumps(f'{name}: {value}')}")
    if body is not None:
        parts.append(f"-d {json.dumps(body)}")
    return " \\\n  ".join(parts)


def _create_payment_safe_curl() -> str:
    """The safe curl printed for the manual gated payment rung (secret as ``$KEY``)."""
    return _safe_curl(
        "POST",
        "https://connect.squareup.com/v2/payments",
        {
            "Authorization": "Bearer $KEY",
            "Square-Version": _SQUARE_VERSION,
            "Content-Type": "application/json",
        },
        '{"source_id":"<card-nonce>","idempotency_key":"<uuid>",'
        '"amount_money":{"amount":<cents>,"currency":"<CUR>"}}',
    )


@register("Square")
async def square_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Square ladder: SAFE locations (``/v2/locations``) -> SAFE merchant identity
    (``/v2/merchants/me``) -> SAFE team enumeration
    (``/v2/team-members/search``) -> GATED+MANUAL payment charge
    (``/v2/payments``).

    The three SAFE rungs only prove the token authenticates and size the
    account's reach. The payment rung is GATED because it charges money; it is
    also MANUAL (the engine cannot build a real charge body), so it never fires —
    it only renders a safe curl, and only after BOTH ``--prove`` and an
    authorized scope.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _square_list_locations(key)
    rungs.append(identity)
    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _square_retrieve_merchant_me(key))
        rungs.append(await _square_list_team_members(key))

        # Ordered: only attempt the gated payment rung once the token
        # authenticates. The @gated wrapper enforces consent BEFORE any work; if
        # consent is missing it raises GatedProbeBlocked, captured here as a
        # `blocked` rung so the ladder never raises across the boundary. Even
        # with consent the rung is MANUAL and never fires a real charge.
        try:
            rungs.append(await _square_create_payment(consent))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="create-payment",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "safe_curl": _create_payment_safe_curl(),
                        "reason": blocked.reason,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="square",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _square_list_locations(key: str) -> ProbeResult:
    """SAFE: ``GET /v2/locations`` confirms the token authenticates and reaches
    the seller account, returning the seller's own business locations (names,
    addresses, status). Read-only, idempotent, no third-party PII — the
    ground-truth that the key is live.
    """
    name = "list-locations"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://connect.squareup.com/v2/locations",
                headers=_square_headers(key),
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

    # Locations arrive under `locations`; summarise names + count to size the
    # seller's footprint without dumping the whole payload.
    locations = body.get("locations") if isinstance(body.get("locations"), list) else []
    names = [
        n
        for loc in locations
        if isinstance(loc, dict)
        and isinstance(
            (n := loc["name"] if loc.get("name") is not None else loc.get("id")),
            str,
        )
    ]
    suffix = f" ({', '.join(names)})" if names else ""

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"authenticates: {len(locations)} business location(s){suffix}",
        evidence={
            "status": resp.status_code,
            "location_count": len(locations),
            "location_names": names,
        },
    )


async def _square_retrieve_merchant_me(key: str) -> ProbeResult:
    """SAFE: ``GET /v2/merchants/me`` resolves the merchant the token is scoped
    to (merchant_id, business_name, country, currency) — identity depth.

    Requires ``MERCHANT_PROFILE_READ``. Own-business metadata, not third-party
    PII.
    """
    name = "retrieve-merchant-me"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://connect.squareup.com/v2/merchants/me",
                headers=_square_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not resolve merchant (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # The merchant is nested under `merchant`; surface only the non-secret whoami
    # fields.
    merchant = body.get("merchant") or {}
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"merchant {merchant.get('id')} — "
            f"{merchant.get('business_name') or 'unknown'} "
            f"({merchant.get('country') or '??'}, {merchant.get('currency') or '??'})"
        ),
        evidence={
            "status": resp.status_code,
            "merchant_id": merchant.get("id"),
            "business_name": merchant.get("business_name"),
            "country": merchant.get("country"),
            "currency": merchant.get("currency"),
        },
    )


async def _square_list_team_members(key: str) -> ProbeResult:
    """SAFE: ``POST /v2/team-members/search`` lists the seller's own team members,
    proving ``EMPLOYEES_READ``.

    A POST, but a read-only search — no state change, no billing. The PII is
    first-party (the operator's own staff), so it stays SAFE. An empty body
    returns the workspace's team members.
    """
    name = "list-team-members"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                "https://connect.squareup.com/v2/team-members/search",
                headers={**_square_headers(key), "Content-Type": "application/json"},
                json={},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not search team members (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # Team members arrive under `team_members`; count them and note how many are
    # active to size first-party staff exposure, never their personal values.
    members = body.get("team_members") if isinstance(body.get("team_members"), list) else []
    active_count = sum(1 for m in members if isinstance(m, dict) and m.get("status") == "ACTIVE")

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"EMPLOYEES_READ: {len(members)} team member(s), {active_count} active",
        evidence={
            "status": resp.status_code,
            "team_member_count": len(members),
            "active_count": active_count,
        },
    )


@gated
async def _square_create_payment(consent: Consent) -> ProbeResult:
    """GATED/MANUAL: ``POST /v2/payments`` charges money via the seller's Square
    account (``PAYMENTS_WRITE``). Billable and state-changing — the action the
    program actually cares about, and the one that must never auto-run.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and nothing is rendered as runnable. Even
    *with* consent it is MANUAL — a real charge needs a ``source_id``,
    ``amount_money``, and ``idempotency_key`` that the engine cannot synthesise —
    so it never fires; it only hands back the safe curl (secret kept as ``$KEY``).
    """
    name = "create-payment"
    curl = _create_payment_safe_curl()
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would charge money via the seller's Square account "
            "(PAYMENTS_WRITE) — billable and state-changing. Needs a real "
            "source_id, amount_money, and idempotency_key the engine cannot "
            f"synthesise; run by hand only when authorized: {curl}"
        ),
        evidence={"manual": True, "billable": True, "safe_curl": curl, "success_status": [200]},
    )
