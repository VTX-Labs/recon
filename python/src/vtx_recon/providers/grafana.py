"""Grafana capability ladder — prove depth of access from a leaked service-account token.

Handles the TruffleHog ``Grafana`` finding: a service-account token of the form
``glsa_<32 base62>_<8 hex>``. Every Grafana HTTP API call is made against the
tenant's own instance host — a self-hosted server or a Grafana Cloud stack URL
(``{host}`` / ``https://<stack>.grafana.net``). That host is **not** present in
the raw token: the token authenticates *to* an instance but does not name it.

Because every rung's URL embeds ``{host}`` and the engine cannot fill that
placeholder, the manual-rung rule applies: **every rung is MANUAL**. No rung
issues a live call. Each rung instead emits a copy-pasteable, safe ``curl`` an
operator can run by hand once they know the instance host, with the token kept
as a ``$KEY`` placeholder so nothing sensitive is ever stored.

Ordered ladder (identity first, then depth):

#. ``current-user`` — SAFE/MANUAL. ``GET /api/user`` — whoami: returns the
   identity backing the token (login, email, org). Read-only, idempotent,
   non-billable.
#. ``user-permissions`` — SAFE/MANUAL. ``GET /api/access-control/user/permissions``
   — list-scopes: the exact RBAC permissions granted to the token
   (e.g. ``dashboards:read``, ``datasources:write``, ``org.users:read``).
   Read-only.
#. ``list-datasources`` — SAFE/MANUAL. ``GET /api/datasources`` — reachable-data
   depth: enumerates configured data sources (types, URLs, names), proving read
   access to backend wiring. Read-only.

The ladder never raises across its public boundary: every failure becomes a
:class:`ProbeResult`. Secrets are never persisted; only non-secret values land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier
from . import register

__all__ = ["grafana_ladder"]


# --------------------------------------------------------------------------- #
# safe-curl rendering (no live call is ever made by this provider)
# --------------------------------------------------------------------------- #


def _shquote(value: str) -> str:
    """Minimal POSIX single-quote shell quoting for a curl argument."""
    inner = value.replace("'", "'\\''")
    return f"'{inner}'"


def _safe_curl(method: str, url: str) -> str:
    """Build a copy-pasteable curl for a Grafana bearer-auth call.

    The token is kept as a ``$KEY`` placeholder; the instance host is left as the
    ``{host}`` placeholder the operator must substitute. The string never contains
    a live secret, so it is safe to print and to store.
    """
    parts = ["curl", "-sS", "-X", method]
    parts.extend(["-H", _shquote("Authorization: Bearer $KEY")])
    parts.extend(["-H", _shquote("Accept: application/json")])
    parts.append(_shquote(url))
    return " ".join(parts)


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID.
    * Nothing succeeded -> DENIED.

    NOTE: every Grafana rung is manual and never makes a live call, so no rung is
    ever ``success=True``. The verdict is therefore always DENIED — the ladder
    cannot prove live access without the out-of-band instance host.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


# --------------------------------------------------------------------------- #
# rung 1 — SAFE / MANUAL: current-user (identity / whoami)
# --------------------------------------------------------------------------- #


def _grafana_current_user() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/user`` — whoami.

    Returns the identity backing the service-account token (login, email, org).
    Read-only, idempotent, non-billable. MANUAL because it needs the ``{host}``
    instance URL (not in the raw token), so no live call is made — the operator is
    handed the exact safe curl.
    """
    name = "current-user"
    url = "https://{host}/api/user"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {host} Grafana instance URL (not in the raw token); "
            "run this by hand to confirm the identity backing the token "
            f"(login/email/org): {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE / MANUAL: user-permissions (token RBAC scopes / depth)
# --------------------------------------------------------------------------- #


def _grafana_user_permissions() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/access-control/user/permissions`` — list-scopes.

    Returns the exact RBAC permissions granted to the token (e.g.
    ``dashboards:read``, ``datasources:write``, ``org.users:read``) — depth of
    access without exercising any of it. Read-only, non-billable. MANUAL (needs
    ``{host}``); no live call is made — the operator is handed the safe curl.
    """
    name = "user-permissions"
    url = "https://{host}/api/access-control/user/permissions"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {host} Grafana instance URL; run this by hand to read "
            f"the token's exact RBAC permissions (depth of access): {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# rung 3 — SAFE / MANUAL: list-datasources (reachable backend wiring)
# --------------------------------------------------------------------------- #


def _grafana_list_datasources() -> ProbeResult:
    """SAFE/MANUAL: ``GET /api/datasources`` — reachable-data depth.

    Enumerates the configured data sources (types, URLs, names), proving read
    access to the backend wiring the instance can reach. Read-only, idempotent,
    non-billable. MANUAL (needs ``{host}``); no live call is made — the operator
    is handed the safe curl.
    """
    name = "list-datasources"
    url = "https://{host}/api/datasources"
    curl = _safe_curl("GET", url)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs the {host} Grafana instance URL; run this by hand to "
            "enumerate configured data sources (types/URLs/names — reachable backend "
            f"wiring): {curl}"
        ),
        evidence={"manual": True, "billable": False, "safe_curl": curl, "success_status": [200]},
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


@register("Grafana")
async def grafana_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Grafana capability ladder for one finding.

    Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
    call): each SAFE rung always renders its safe curl. Because manual rungs never
    succeed, subsequent rungs are not gated on a (never-true) success — the
    operator gets the full hand-run plan. The ladder never raises across its
    public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE/MANUAL): identity / whoami.
    rungs.append(_grafana_current_user())
    # Rung 2 (SAFE/MANUAL): token RBAC permissions (depth of access).
    rungs.append(_grafana_user_permissions())
    # Rung 3 (SAFE/MANUAL): reachable data sources (backend wiring).
    rungs.append(_grafana_list_datasources())

    return LadderResult(
        finding=finding,
        provider="grafana",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
