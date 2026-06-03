"""Shopify capability ladder — prove depth of access from a leaked Admin API token.

Handles the TruffleHog ``ShopifyToken`` finding: a ``shpat_…`` Admin API access
token used with the header ``X-Shopify-Access-Token: <token>``. The token
authenticates fine on its own, but EVERY Admin REST endpoint is hosted at
``https://{shop}.myshopify.com/...`` — and the shop domain is **not present in
the raw token**. The engine can fill the ``{key}`` header, but it cannot invent
the ``{shop}`` host, so per the manual-rung rule that makes **every rung
MANUAL**: no rung issues a live call. Each rung instead emits a copy-pasteable,
safe ``curl`` an operator can run by hand once they know the shop domain, with
the secret kept as a ``$KEY`` placeholder and ``{shop}`` left for the operator to
substitute — nothing sensitive is ever stored.

Ordered ladder (identity / scopes first, then depth):

#. ``access-scopes`` — SAFE/MANUAL. ``GET /admin/oauth/access_scopes.json``
   returns the exact access scopes granted to the token (e.g. ``read_products``,
   ``write_orders``, ``read_customers``) — the depth of access without
   exercising any of it. Read-only, idempotent, non-billable.
#. ``shop-info`` — SAFE/MANUAL. ``GET /admin/api/2024-01/shop.json`` returns the
   store's own profile (shop name, owner email, plan, domain, currency) —
   identity / whoami over first-party store data. Read-only, non-billable.
#. ``list-customers`` — GATED/MANUAL. ``GET /admin/api/2024-01/customers.json``
   reads third-party customer PII (names, emails, addresses, order history) —
   the data exposure the program cares about. Read-only but GATED because it
   reads customer PII. Routed through :func:`vtx_recon.safety.gated` so it is
   structurally unreachable without BOTH ``--prove`` and
   ``--i-am-authorized "<scope>"``; even when consent is granted it never
   auto-fires (the ``{shop}`` host cannot be filled) — it renders the safe curl
   for the operator.

The ladder never raises across its public boundary: every failure becomes a
:class:`ProbeResult`. Secrets are never persisted; only non-secret values land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["shopify_ladder"]


# --------------------------------------------------------------------------- #
# safe-curl rendering (no live call is ever made by this provider)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(method: str, url: str) -> str:
    """Build a copy-pasteable curl for a Shopify Admin API call.

    The token is kept as a ``$KEY`` placeholder in the ``X-Shopify-Access-Token``
    header; the shop is left as the ``{shop}`` placeholder the operator must
    substitute. The string never contains a live secret, so it is safe to print
    and to store.
    """
    parts = ["curl", "-sS", "-X", method]
    parts.extend(["-H", _shquote("X-Shopify-Access-Token: $KEY")])
    parts.extend(["-H", _shquote("Accept: application/json")])
    parts.append(_shquote(url))
    return " ".join(parts)


# The list-customers URL (embeds the {shop} placeholder the engine cannot fill).
_LIST_CUSTOMERS_URL = "https://{shop}.myshopify.com/admin/api/2024-01/customers.json?limit=1"


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID.
    * Nothing succeeded -> DENIED.

    NOTE: every Shopify rung is manual and never makes a live call, so no rung is
    ever ``success=True``. The verdict is therefore always DENIED — the ladder
    cannot prove live access without the out-of-band ``{shop}`` domain.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# rung 1 — SAFE / MANUAL: access-scopes (depth of access)
# --------------------------------------------------------------------------- #


def _shopify_access_scopes() -> ProbeResult:
    """SAFE/MANUAL: ``GET /admin/oauth/access_scopes.json`` returns the exact
    access scopes granted to the token (e.g. ``read_products``, ``write_orders``,
    ``read_customers``) — depth of access without exercising any of it.

    Read-only, idempotent, non-billable. MANUAL because the URL needs the
    ``{shop}`` host (the shop domain is not in the raw token), so no live call is
    made — the operator is handed the exact safe curl.
    """
    name = "access-scopes"
    url = "https://{shop}.myshopify.com/admin/oauth/access_scopes.json"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {shop} host (the shop domain is not in the raw "
            "token); run this by hand to list the exact access scopes granted to "
            f"the token: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE / MANUAL: shop-info (identity / whoami)
# --------------------------------------------------------------------------- #


def _shopify_shop_info() -> ProbeResult:
    """SAFE/MANUAL: ``GET /admin/api/2024-01/shop.json`` returns the store's own
    profile (shop name, owner email, plan, domain, currency) — identity / whoami
    over first-party store data.

    Read-only, non-billable. MANUAL (needs the ``{shop}`` host); no live call is
    made — the operator is handed the safe curl.
    """
    name = "shop-info"
    url = "https://{shop}.myshopify.com/admin/api/2024-01/shop.json"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {shop} host (not in the raw token); run this by "
            "hand to read the store's own profile (name, owner email, plan, "
            f"domain, currency): {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 3 — GATED / MANUAL: list-customers (customer PII read)
# --------------------------------------------------------------------------- #


@gated
async def _shopify_list_customers(consent: Consent) -> ProbeResult:
    """GATED/MANUAL: ``GET /admin/api/2024-01/customers.json`` reads third-party
    customer PII (names, emails, addresses, order history) — the data exposure
    the program cares about.

    Read-only but GATED because it reads customer PII. Decorated with
    :func:`vtx_recon.safety.gated`: the safety boundary runs *before* this body,
    so without BOTH ``--prove`` and an authorized scope it raises
    :class:`GatedProbeBlocked` and nothing is rendered as runnable. Even with
    consent it is MANUAL — the engine cannot fill the ``{shop}`` host, so it
    returns the safe curl rather than firing.
    """
    name = "list-customers"
    curl = _safe_curl("GET", _LIST_CUSTOMERS_URL)
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: would read third-party customer PII (names, emails, "
            "addresses, order history). Needs the {shop} host (not in the raw "
            f"token); run by hand only when authorized: {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("ShopifyToken", "Shopify")
async def shopify_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Shopify capability ladder for one finding.

    Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
    call): the SAFE rungs always render their safe curl; the GATED rung is
    reached only through the safety boundary — when consent is missing it is
    recorded as a blocked rung, when consent is present it still only renders a
    safe curl.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE/MANUAL): depth of access (granted scopes). Manual rungs always
    # render, so subsequent rungs are not gated on a (never-true) success — the
    # operator gets the full hand-run plan.
    rungs.append(_shopify_access_scopes())
    # Rung 2 (SAFE/MANUAL): identity / first-party store profile.
    rungs.append(_shopify_shop_info())

    # Rung 3 (GATED/MANUAL): customer-PII read. Reachable only via the @gated
    # wrapper; without full consent it raises GatedProbeBlocked, recorded as a
    # blocked rung (the safe curl is still surfaced as evidence). The ladder
    # never raises across its public boundary.
    customers_curl = _safe_curl("GET", _LIST_CUSTOMERS_URL)
    try:
        rungs.append(await _shopify_list_customers(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="list-customers",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={
                    "reason": blocked.reason,
                    "manual": True,
                    "billable": False,
                    "safe_curl": customers_curl,
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="shopify",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
