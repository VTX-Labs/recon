"""Capability ladder for Notion integration tokens.

Notion internal/OAuth integration tokens are shaped ``secret_<43+ chars>`` or
the newer ``ntn_<43+ chars>`` and authenticate via an
``Authorization: Bearer <token>`` header. Every request is pinned to the
``Notion-Version: 2022-06-28`` API version so the parsed shapes stay stable.
TruffleHog surfaces these under the ``Notion`` detector. The ladder climbs:

* **``bot-user``** (SAFE) — ``GET /v1/users/me`` returns the bot user tied to
  the integration token, including ``bot.owner`` (workspace vs user install)
  and the workspace name. This is whoami: it confirms the token is live and
  reveals the scope of the integration. Read-only, non-billable, exposes no
  third-party PII (only the integration's own bot). Decides VALID vs DENIED.
* **``list-users``** (GATED) — ``GET /v1/users`` enumerates every member of the
  workspace, and each ``person`` user object carries that member's email —
  third-party PII exposure. Read-only, but GATED because it reads member PII;
  it runs only if the operator supplied BOTH ``--prove`` and an authorized
  scope, otherwise it is recorded as a ``blocked`` rung. Names are summarised
  (a small sample plus counts), never the full directory dump, and emails never
  land in evidence.
* **``search-shared-content``** (GATED) — ``POST /v1/search`` returns the
  actual pages and databases shared with the integration — potentially
  sensitive workspace content. Read-only, but GATED because it surfaces real
  document data; it runs only if the operator supplied BOTH ``--prove`` and an
  authorized scope, otherwise it is recorded as a ``blocked`` rung. The body is
  capped (``page_size: 5``) so an empty body never dumps everything shared.

Every rung is ordered (identity first, then depth), READ-ONLY by default, and
never raises across the public boundary: failures become a :class:`ProbeResult`
with ``success=False`` so one dead key cannot crash a batch run. The raw token
is held only transiently for the HTTP call and only non-secret fields ever land
in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["notion_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)


def _notion_headers(key: str) -> dict[str, str]:
    """Bearer auth pinned to a fixed Notion API version (stable parsed shapes)."""
    return {
        "Authorization": f"Bearer {key}",
        "Notion-Version": "2022-06-28",
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


@register("Notion")
async def notion_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Notion ladder: SAFE bot identity (``/users/me``) -> GATED workspace
    member-PII enumeration (``/users``) -> GATED shared-content read
    (``/search``).

    The one SAFE rung only proves the token authenticates and sizes the bot's
    scope. Member enumeration is GATED because it returns third-party PII
    (member emails) and the search read is GATED because it returns real shared
    document data; both run only if the operator supplied BOTH ``--prove`` and
    an authorized scope.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _notion_bot_user(key)
    rungs.append(identity)
    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # Ordered: only attempt the gated member-PII enumeration if the token
        # authenticates. The @gated wrapper enforces consent BEFORE any network
        # call; if consent is missing it raises GatedProbeBlocked, which we
        # capture here as a `blocked` rung so the ladder never raises across the
        # public boundary.
        try:
            rungs.append(await _notion_list_users(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="list-users",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated member-PII read blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

        # Ordered: only attempt the gated content read if the token
        # authenticates.
        try:
            rungs.append(await _notion_search_shared_content(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="search-shared-content",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated content read blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="notion",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _notion_bot_user(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/users/me`` confirms the token and returns the bot user.

    Returns whoami plus ``bot.owner`` (workspace vs user) and the workspace
    name, which together map the scope of the integration. Read-only,
    non-billable, and exposes no third-party PII (only the integration's own
    bot).
    """
    name = "bot-user"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.notion.com/v1/users/me",
                headers=_notion_headers(key),
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

    # The bot object is embedded under `bot`; `bot.owner.type` is "workspace" or
    # "user". Summarise it so we prove the integration's scope without dumping
    # the whole payload.
    bot = body.get("bot") or {}
    owner = bot.get("owner") or {}
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as bot {body.get('name') or body.get('id')} "
            f"(owner type {owner.get('type', 'unknown')}, "
            f"workspace {bot.get('workspace_name', 'unknown')})"
        ),
        evidence={
            "status": resp.status_code,
            "bot_id": body.get("id"),
            "bot_name": body.get("name"),
            "type": body.get("type"),
            "owner_type": owner.get("type"),
            "workspace_name": bot.get("workspace_name"),
        },
    )


@gated
async def _notion_list_users(consent: Consent, key: str) -> ProbeResult:
    """GATED: ``GET /v1/users`` enumerates every member of the workspace; each
    ``person`` user object carries that member's email — third-party PII.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and no request is ever sent. The public
    ladder catches that and records a ``blocked`` rung. Names are summarised (a
    small sample plus counts), never the full directory dump, and emails never
    land in evidence.
    """
    name = "list-users"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.notion.com/v1/users",
                headers=_notion_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"could not list users (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    # PII is summarised, not dumped: prove the read without hoarding the full
    # member directory. We keep a small sample of names plus counts; member
    # emails are never recorded.
    users = body.get("results") if isinstance(body.get("results"), list) else []
    names = [
        u.get("name") or u.get("id") for u in users if isinstance(u.get("name") or u.get("id"), str)
    ]
    person_count = sum(1 for u in users if u.get("type") == "person")

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=(
            f"enumerated {len(users)} workspace member(s) ({person_count} person): "
            f"{', '.join(names[:5]) if names else '(none)'} — third-party PII"
        ),
        evidence={
            "status": resp.status_code,
            "user_count": len(users),
            "person_count": person_count,
            "names_sample": names[:25],
        },
    )


@gated
async def _notion_search_shared_content(consent: Consent, key: str) -> ProbeResult:
    """GATED: ``POST /v1/search`` returns the pages and databases shared with the
    integration — potentially sensitive workspace content.

    Read-only, but GATED because it surfaces real document data. Decorated with
    :func:`vtx_recon.safety.gated`, so the safety boundary runs *before* this
    body and, without BOTH ``--prove`` and an authorized scope, raises
    :class:`GatedProbeBlocked` and no request is ever sent. The public ladder
    catches that and records a ``blocked`` rung. The body caps ``page_size`` to
    5 so an empty body never returns everything shared.
    """
    name = "search-shared-content"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                "https://api.notion.com/v1/search",
                headers={**_notion_headers(key), "Content-Type": "application/json"},
                json={"page_size": 5},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"search refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    # Content is summarised, not dumped: prove the read without hoarding shared
    # document data. We only count objects and note object types / whether more
    # pages exist, never page titles or body content.
    results = body.get("results") if isinstance(body.get("results"), list) else []
    object_types = sorted({r.get("object") for r in results if isinstance(r.get("object"), str)})
    has_more = bool(body.get("has_more"))

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=(
            f"read {len(results)} shared object(s)"
            f"{' (more available)' if has_more else ''} — live workspace content"
        ),
        evidence={
            "status": resp.status_code,
            "sample_count": len(results),
            "object_types": object_types,
            "has_more": has_more,
        },
    )
