"""Stripe capability ladder — prove depth of access for a leaked API key.

Handles TruffleHog ``StripeAccessToken`` and ``Stripe`` findings. A Stripe
secret/restricted key (``sk_...`` / ``rk_...``) authenticates with
``Authorization: Bearer <key>``.

The ordered ladder (depth of access, least -> most revealing):

  1. ``stripe.auth_check``           ``GET /v1/balance`` — cheap, non-PII probe
     that only proves the key authenticates. Decides VALID vs DENIED.
  2. ``stripe.products.list``        ``GET /v1/products?limit=1`` — SAFE scope
     probe. A restricted key may be denied here (403) yet still be live; both
     200 and 403 are recorded as a successful reachability/scope signal.
  3. ``stripe.balance_transactions`` ``GET /v1/balance_transactions?limit=1`` —
     SAFE depth: confirms ledger read access. We keep only whether it was
     reachable and the count, never amounts.
  4. ``stripe.account.read``         ``GET /v1/account`` — GATED. Returns live
     business PII (legal name, support email, payout hints).
  5. ``stripe.charges.list``         ``GET /v1/charges?limit=1`` — GATED.
     Returns customer PII (names, emails, card metadata).

The two GATED rungs run only if the operator supplied BOTH ``--prove`` and an
authorized scope; otherwise they are recorded as ``blocked`` and no request is
issued. Every live rung is READ-ONLY, the ladder never raises across the public
boundary, and the raw key never lands in evidence (only :func:`redact`ed).

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..redact import redact
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "stripe_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("StripeAccessToken", "Stripe")

API_BASE = "https://api.stripe.com/v1"

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
    """Standard Stripe bearer header for a secret/restricted key."""
    return {"Authorization": f"Bearer {key}"}


@register("StripeAccessToken", "Stripe")
async def stripe_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Stripe ladder: SAFE auth check -> SAFE depth probes -> GATED PII reads.

    The SAFE rungs only prove the key authenticates and map its read reach. The
    account read and charges read are GATED because they return live PII; they
    run only if the operator supplied BOTH ``--prove`` and an authorized scope.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    token = finding.raw

    # --- Rung 1: auth_check (SAFE) — decides live/dead -----------------------
    auth = await _stripe_auth_check(token)
    rungs.append(auth)

    # Only climb deeper if the key authenticates (ordered ladder). The @gated
    # wrappers enforce consent BEFORE any network call; if consent is missing
    # they raise GatedProbeBlocked, captured here as a `blocked` rung so the
    # ladder never raises across the public boundary.
    if auth.success:
        # --- Rung 2: products.list (SAFE scope probe) ------------------------
        rungs.append(await _stripe_products_list(token))

        # --- Rung 3: balance_transactions (SAFE depth) -----------------------
        rungs.append(await _stripe_balance_transactions(token))

        # --- Rung 4: account.read (GATED PII) --------------------------------
        try:
            rungs.append(await _stripe_account_read(consent, token))
        except GatedProbeBlocked as blocked:
            rungs.append(_gated_blocked("stripe.account.read", blocked))

        # --- Rung 5: charges.list (GATED PII) --------------------------------
        try:
            rungs.append(await _stripe_charges_list(consent, token))
        except GatedProbeBlocked as blocked:
            rungs.append(_gated_blocked("stripe.charges.list", blocked))

    return LadderResult(
        finding=finding,
        provider="stripe",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


def _gated_blocked(name: str, blocked: GatedProbeBlocked) -> ProbeResult:
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=True,
        detail=f"gated PII read blocked: {blocked.reason}",
        evidence={"reason": blocked.reason},
    )


# --- SAFE rungs --------------------------------------------------------------


async def _stripe_auth_check(token: str) -> ProbeResult:
    """SAFE: hit read-only ``/v1/balance`` purely to confirm the key works.

    Balance is account-level money data but not third-party PII; we keep no
    figures from it — only whether the key authenticated.
    """
    name = "stripe.auth_check"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{API_BASE}/balance", headers=_bearer(token))
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

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail="key authenticates (live secret/restricted key)",
        evidence={"status": resp.status_code, "key_prefix": redact(token)},
    )


async def _stripe_products_list(token: str) -> ProbeResult:
    """SAFE: ``GET /v1/products?limit=1`` maps read scope.

    A restricted key may be forbidden here (403) yet still be a live key; we
    treat both 200 (read access) and 403 (live key, scope withheld) as a
    successful reachability signal.
    """
    name = "stripe.products.list"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/products", headers=_bearer(token), params={"limit": "1"}
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code == 403:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=True,
            detail="products read forbidden (restricted key, scope withheld)",
            evidence={"status": resp.status_code, "readable": False},
        )

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"products probe failed (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    data = body.get("data") if isinstance(body.get("data"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"products readable ({len(data)} sampled)",
        evidence={"status": resp.status_code, "readable": True, "sample_count": len(data)},
    )


async def _stripe_balance_transactions(token: str) -> ProbeResult:
    """SAFE: ``GET /v1/balance_transactions?limit=1`` confirms ledger read depth.

    We keep only the reachability and a sample count — never amounts.
    """
    name = "stripe.balance_transactions"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/balance_transactions",
                headers=_bearer(token),
                params={"limit": "1"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code == 403:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=True,
            detail="balance transactions forbidden (restricted key, scope withheld)",
            evidence={"status": resp.status_code, "readable": False},
        )

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"balance transactions probe failed (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    data = body.get("data") if isinstance(body.get("data"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"balance ledger readable ({len(data)} sampled)",
        evidence={"status": resp.status_code, "readable": True, "sample_count": len(data)},
    )


# --- GATED rungs -------------------------------------------------------------


@gated
async def _stripe_account_read(consent: Consent, token: str) -> ProbeResult:
    """GATED: ``GET /v1/account`` returns live business PII.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and no request is ever sent. The public
    ladder catches that and records a ``blocked`` rung.
    """
    name = "stripe.account.read"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{API_BASE}/account", headers=_bearer(token))
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"account read refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    # PII is summarised, not dumped: prove access without hoarding the data.
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=(
            f"read live account {body.get('id')} "
            f"({body.get('business_type', 'unknown')} in {body.get('country', '??')})"
        ),
        evidence={
            "status": resp.status_code,
            "account_id": body.get("id"),
            "country": body.get("country"),
            "business_type": body.get("business_type"),
            "charges_enabled": body.get("charges_enabled"),
            "pii_fields_present": sorted(k for k in ("email", "business_profile") if k in body),
        },
    )


@gated
async def _stripe_charges_list(consent: Consent, token: str) -> ProbeResult:
    """GATED: ``GET /v1/charges?limit=1`` returns customer PII.

    Without consent it raises :class:`GatedProbeBlocked` before any request. We
    summarise (count + which PII fields were present), never dump card/customer
    data.
    """
    name = "stripe.charges.list"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/charges", headers=_bearer(token), params={"limit": "1"}
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"charges read refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    data = body.get("data") if isinstance(body.get("data"), list) else []
    first = data[0] if data and isinstance(data[0], dict) else {}
    pii_fields = sorted(k for k in ("billing_details", "receipt_email", "customer") if k in first)
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=f"read live charges ({len(data)} sampled, customer PII reachable)",
        evidence={
            "status": resp.status_code,
            "charge_count": len(data),
            "pii_fields_present": pii_fields,
        },
    )
