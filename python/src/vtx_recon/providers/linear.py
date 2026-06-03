"""Capability ladder for Linear API keys.

Linear personal API keys are shaped ``lin_api_<40 chars>`` and authenticate
against the single GraphQL endpoint ``https://api.linear.app/graphql``. Unlike
almost every other provider, Linear expects the raw key in the
``Authorization`` header WITHOUT a ``Bearer `` prefix; the value is the key
verbatim. Every rung is a ``POST`` carrying a GraphQL query, but each one is
read-only and idempotent. TruffleHog surfaces these under the ``LinearAPI``
detector. The ladder climbs:

* **``viewer-identity``** (SAFE) — ``query { viewer { id name email } }`` is
  whoami: it returns the key owner, confirming the key is live and revealing
  who it belongs to. POST, but read-only GraphQL, idempotent, non-billable.
  Decides VALID vs DENIED.
* **``organization``** (SAFE) — ``query { organization { id name urlKey
  userCount } }`` reveals the org the key can reach and its size — the
  reachable-data depth beyond the bare identity. Read-only GraphQL.
* **``list-org-users``** (GATED) — ``query { users { nodes { name email } } }``
  enumerates every org member's name and email — third-party PII exposure.
  Read-only, but GATED because it reads member PII; it runs only if the
  operator supplied BOTH ``--prove`` and an authorized scope, otherwise it is
  recorded as a ``blocked`` rung.

Every rung is ordered (identity first, then depth), READ-ONLY by default, and
never raises across the public boundary: failures become a :class:`ProbeResult`
with ``success=False`` so one dead key cannot crash a batch run. The raw key is
held only transiently for the HTTP call and only non-secret fields ever land in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["linear_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# The one GraphQL endpoint every rung POSTs to.
_GRAPHQL_URL = "https://api.linear.app/graphql"


def _linear_headers(key: str) -> dict[str, str]:
    """Linear auth: the raw key with NO ``Bearer`` prefix, plus a JSON body type."""
    return {
        "Authorization": key,
        "Content-Type": "application/json",
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


def _graphql_errors(body: dict) -> str | None:
    """Return the first GraphQL error message, if any.

    Linear returns HTTP 200 with a top-level ``errors`` array for an invalid key
    or a denied field, so a non-empty ``errors`` is an application-level failure
    even on a 200.
    """
    errors = body.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0] if isinstance(errors[0], dict) else {}
        message = first.get("message")
        return message if isinstance(message, str) else "unknown"
    return None


@register("LinearAPI")
async def linear_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Linear ladder: SAFE viewer identity (``viewer``) -> SAFE org reach
    (``organization``) -> GATED member-PII enumeration (``users``).

    The two SAFE rungs only prove the key authenticates and size the org. The
    user enumeration is GATED because it returns third-party member PII (names,
    emails); it runs only if the operator supplied BOTH ``--prove`` and an
    authorized scope.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _linear_viewer_identity(key)
    rungs.append(identity)
    # Only climb deeper if the key authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _linear_organization(key))

        # Ordered: only attempt the gated PII enumeration if the key
        # authenticates. The @gated wrapper enforces consent BEFORE any network
        # call; if consent is missing it raises GatedProbeBlocked, which we
        # capture here as a `blocked` rung so the ladder never raises across the
        # public boundary.
        try:
            rungs.append(await _linear_list_org_users(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="list-org-users",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated member-PII read blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="linear",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _linear_viewer_identity(key: str) -> ProbeResult:
    """SAFE: ``query { viewer { id name email } }`` confirms the key and returns
    the key owner — whoami.

    POST, but read-only GraphQL, idempotent, non-billable.
    """
    name = "viewer-identity"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _GRAPHQL_URL,
                headers=_linear_headers(key),
                json={"query": "query { viewer { id name email } }"},
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

    # Linear returns HTTP 200 with a top-level `errors` array for an invalid key;
    # treat that as a rejected rung rather than a successful identity.
    gql_error = _graphql_errors(body)
    if gql_error is not None:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"key rejected: {gql_error}",
            evidence={"status": resp.status_code, "error": gql_error},
        )

    viewer = (body.get("data") or {}).get("viewer") or {}
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            "authenticated as "
            f"{viewer.get('name') or viewer.get('email') or viewer.get('id') or 'unknown'}"
        ),
        evidence={
            "status": resp.status_code,
            "viewer_id": viewer.get("id"),
            "name": viewer.get("name"),
            "email": viewer.get("email"),
        },
    )


async def _linear_organization(key: str) -> ProbeResult:
    """SAFE: ``query { organization { id name urlKey userCount } }`` reveals the
    org the key can reach and its size.

    Reachable-data depth beyond bare identity. Read-only GraphQL.
    """
    name = "organization"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _GRAPHQL_URL,
                headers=_linear_headers(key),
                json={"query": "query { organization { id name urlKey userCount } }"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not read organization (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    gql_error = _graphql_errors(body)
    if gql_error is not None:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not read organization: {gql_error}",
            evidence={"status": resp.status_code, "error": gql_error},
        )

    org = (body.get("data") or {}).get("organization") or {}
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"reachable org {org.get('name') or org.get('urlKey') or org.get('id') or 'unknown'} "
            f"({org.get('userCount', '?')} users)"
        ),
        evidence={
            "status": resp.status_code,
            "org_id": org.get("id"),
            "name": org.get("name"),
            "url_key": org.get("urlKey"),
            "user_count": org.get("userCount"),
        },
    )


@gated
async def _linear_list_org_users(consent: Consent, key: str) -> ProbeResult:
    """GATED: ``query { users { nodes { name email } } }`` enumerates every org
    member's name and email — third-party PII exposure.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and no request is ever sent. The public
    ladder catches that and records a ``blocked`` rung. Names/emails are
    summarised (a small sample plus a count), never the full directory dump.
    """
    name = "list-org-users"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _GRAPHQL_URL,
                headers=_linear_headers(key),
                json={"query": "query { users { nodes { name email } } }"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"user enumeration refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    gql_error = _graphql_errors(body)
    if gql_error is not None:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"user enumeration refused: {gql_error}",
            evidence={"status": resp.status_code, "error": gql_error},
        )

    # PII is summarised, not dumped: prove the read without hoarding the full
    # member directory. We keep a small sample of names plus the total count.
    nodes = ((body.get("data") or {}).get("users") or {}).get("nodes")
    nodes = nodes if isinstance(nodes, list) else []
    names = [
        u.get("name") or u.get("email")
        for u in nodes
        if isinstance(u.get("name") or u.get("email"), str)
    ]

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=(
            f"enumerated {len(nodes)} org member(s): "
            f"{', '.join(names[:5]) if names else '(none)'} — third-party PII"
        ),
        evidence={
            "status": resp.status_code,
            "user_count": len(nodes),
            "names_sample": names[:25],
        },
    )
