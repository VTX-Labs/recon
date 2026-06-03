"""Capability ladder for New Relic personal API keys (``NRAK-...``).

New Relic personal API keys (User keys) authenticate to the NerdGraph GraphQL
API at ``https://api.newrelic.com/graphql`` via an ``Api-Key: <key>`` header.
Every rung is a single ``POST`` carrying a read-only GraphQL query — the POST
verb is an artifact of GraphQL, not a mutation: each query is idempotent and
non-billable. TruffleHog surfaces these under ``NewRelicPersonalApiKey``. The
ladder climbs:

* **``viewer-identity``** (SAFE) — ``{ actor { user { id name email } } }`` is
  the NerdGraph whoami: it returns the key owner's identity, confirming the key
  is live and revealing who it belongs to. Decides VALID vs DENIED.
* **``list-accounts``** (SAFE) — ``{ actor { accounts { id name } } }``
  enumerates every New Relic account the key can reach, proving the scope /
  blast radius of access (which accounts' telemetry, dashboards and config the
  key can read).

Both rungs are read-only GraphQL queries: NerdGraph returns HTTP 200 even on a
GraphQL-level error, so each rung treats a populated ``errors`` array as a
failure. Every rung is ordered (identity first, then depth), READ-ONLY, and
never raises across the public boundary: failures become a :class:`ProbeResult`
with ``success=False`` so one dead key cannot crash a batch run. The raw key is
held only transiently for the HTTP call and never lands in evidence.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier
from . import register

__all__ = ["newrelic_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# The single NerdGraph GraphQL endpoint every rung POSTs to.
_NERDGRAPH_URL = "https://api.newrelic.com/graphql"


def _newrelic_headers(key: str) -> dict[str, str]:
    """``Api-Key`` auth plus JSON content-type completes every rung's headers."""
    return {"Api-Key": key, "Content-Type": "application/json"}


def _network_failure(name: str, tier: ProbeTier, exc: Exception) -> ProbeResult:
    """Turn an httpx/transport error into a non-success rung (never raise)."""
    return ProbeResult(
        name=name,
        tier=tier,
        success=False,
        detail=f"probe could not complete: {type(exc).__name__}",
        evidence={"error": type(exc).__name__},
    )


def _graphql_error_messages(body: object) -> list[str]:
    """Collect GraphQL ``errors[].message`` strings (NerdGraph 200s on error).

    Defensive: a hostile / malformed response may make ``body`` or any
    ``errors`` element a non-dict, so every access is guarded — this helper must
    never raise (it runs after JSON parsing, outside the network try/except).
    """
    errors = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errors, list):
        return []
    return [
        e["message"] for e in errors if isinstance(e, dict) and isinstance(e.get("message"), str)
    ]


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


@register("NewRelicPersonalApiKey")
async def newrelic_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """New Relic ladder: SAFE viewer identity -> SAFE account enumeration.

    Both rungs are read-only NerdGraph queries. The first is whoami; the second
    sizes the blast radius by listing every account the key can reach. There is
    no GATED rung — neither query mutates or returns third-party PII beyond the
    key owner's own identity and the accounts they already administer.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _newrelic_viewer_identity(key)
    rungs.append(identity)
    # Only climb deeper if the key authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _newrelic_list_accounts(key))

    return LadderResult(
        finding=finding,
        provider="newrelic",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _newrelic_viewer_identity(key: str) -> ProbeResult:
    """SAFE: ``{ actor { user { id name email } } }`` is the NerdGraph whoami.

    It confirms the key is live and returns the owner's identity (who the key
    belongs to). POST but a read-only, idempotent, non-billable GraphQL query.
    """
    name = "viewer-identity"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _NERDGRAPH_URL,
                headers=_newrelic_headers(key),
                json={"query": "{ actor { user { id name email } } }"},
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

    # NerdGraph returns HTTP 200 even when the key is bad: a populated `errors`
    # array (or a null user) means the key did not authenticate.
    errors = _graphql_error_messages(body)
    if errors:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"key rejected: {errors[0]}",
            evidence={"status": resp.status_code, "errors": errors[:3]},
        )

    data = body.get("data") if isinstance(body, dict) else None
    data = data if isinstance(data, dict) else {}
    actor = data.get("actor") if isinstance(data.get("actor"), dict) else {}
    user = actor.get("user") if isinstance(actor.get("user"), dict) else None
    if not user:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail="key did not resolve a viewer identity",
            evidence={"status": resp.status_code},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {user.get('name') or user.get('email') or user.get('id')} "
            f"(id {user.get('id') or 'unknown'})"
        ),
        evidence={
            "status": resp.status_code,
            "user_id": user.get("id"),
            "user_name": user.get("name"),
            "user_email": user.get("email"),
        },
    )


async def _newrelic_list_accounts(key: str) -> ProbeResult:
    """SAFE: ``{ actor { accounts { id name } } }`` enumerates reachable accounts.

    Listing every account the key can reach proves the scope of access (blast
    radius) — which accounts' telemetry, dashboards and config the key can read.
    Read-only GraphQL.
    """
    name = "list-accounts"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _NERDGRAPH_URL,
                headers=_newrelic_headers(key),
                json={"query": "{ actor { accounts { id name } } }"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list accounts (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    errors = _graphql_error_messages(body)
    if errors:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list accounts: {errors[0]}",
            evidence={"status": resp.status_code, "errors": errors[:3]},
        )

    # Accounts arrive under data.actor.accounts; summarise ids/names to size the
    # blast radius without dumping the whole payload. Every access is guarded so a
    # malformed payload can never raise across the ladder boundary.
    data = body.get("data") if isinstance(body, dict) else None
    data = data if isinstance(data, dict) else {}
    actor = data.get("actor") if isinstance(data.get("actor"), dict) else {}
    accounts = actor.get("accounts") if isinstance(actor.get("accounts"), list) else []
    names = [
        str(a.get("name") if a.get("name") is not None else a.get("id"))
        for a in accounts
        if isinstance(a, dict) and (a.get("name") is not None or a.get("id") is not None)
    ]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"key can reach {len(accounts)} account(s): "
            f"{', '.join(names[:5]) if names else '(none)'}"
        ),
        evidence={
            "status": resp.status_code,
            "account_count": len(accounts),
            "account_ids": [
                a.get("id") for a in accounts if isinstance(a, dict) and a.get("id") is not None
            ][:25],
            "names_sample": names[:25],
        },
    )
