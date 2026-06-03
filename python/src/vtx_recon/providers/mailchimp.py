"""Mailchimp Marketing API capability ladder — prove depth of access for a
leaked API key.

Handles TruffleHog ``Mailchimp`` findings. A Mailchimp Marketing key is 32 hex
characters followed by a datacenter suffix, e.g. ``…-us21``. The datacenter
(``{dc}``) is *not* a free placeholder: it is encoded in the key itself (the
segment after the final dash) and is required to address every Marketing API
endpoint (``https://{dc}.api.mailchimp.com/3.0/…``). The key authenticates with
HTTP Basic auth (``Authorization: Basic <key>``), per the provider spec.

The ordered ladder (depth of access, least -> most revealing):

  1. ``api-root``        ``GET /3.0/`` — the whoami for a Mailchimp key. Confirms
     the key authenticates and returns account identity (account id, login
     email, contact, total subscribers). Read-only, idempotent. This is the rung
     that decides VALID vs DENIED.
  2. ``list-audiences``  ``GET /3.0/lists?count=10`` — enumerates the audiences /
     lists the key can reach (names, member counts) — reachable resources,
     deeper than identity. Read-only enumeration.
  3. ``add-list-member`` ``POST /3.0/lists/{list_id}/members`` — GATED, mutating.
     Writes a subscriber into an audience; state-changing and injects into a
     marketing pipeline that emails third parties. Its URL needs a ``{list_id}``
     from ``list-audiences`` that the engine cannot fill, so this rung is
     rendered as a MANUAL safe-curl note: it is never auto-fired and prints a
     curl that keeps the secret as ``$KEY``.

Every rung is ordered (identity first, then depth), the live rungs are all
READ-ONLY GETs, and the ladder never raises across the public boundary:
failures become a :class:`ProbeResult` with ``success=False`` so one dead key
cannot crash a batch run. The raw key is held only transiently for the HTTP
call and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "mailchimp_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Mailchimp",)

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


def _basic(key: str) -> dict[str, str]:
    """Standard Mailchimp HTTP Basic header (the key is the credential, per spec)."""
    return {"Authorization": f"Basic {key}"}


def _datacenter_of(key: str) -> str | None:
    """Derive the datacenter (``{dc}``) from the key: the segment after the final
    dash (e.g. ``us21``).

    Returns ``None`` for a key that has no such suffix, in which case no Marketing
    endpoint can be addressed and the ladder reports DENIED.
    """
    dash = key.rfind("-")
    if dash < 0 or dash == len(key) - 1:
        return None
    return key[dash + 1 :]


@register("Mailchimp")
async def mailchimp_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Mailchimp capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs ``api-root`` first and only descends into the deeper SAFE rung if the
    key authenticated. The mutating ``add-list-member`` rung is GATED and,
    because its URL needs a ``{list_id}`` the engine cannot fill, is emitted as a
    manual safe-curl note rather than a live call. Never raises across the public
    boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw
    dc = _datacenter_of(key)

    # --- Rung 1: api-root (SAFE) — decides live/dead -------------------------
    identity = await _api_root(key, dc)
    rungs.append(identity)

    # Only climb deeper if the key authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-audiences (SAFE) -----------------------------------
        rungs.append(await _list_audiences(key, dc))

        # --- Rung 3: add-list-member (GATED, manual safe-curl) ---------------
        # The URL embeds a {list_id} the engine cannot fill, so this never fires
        # a live request: it is rendered as a manual note. The @gated wrapper
        # still enforces consent first, so without --prove + --i-am-authorized
        # the rung is recorded as blocked.
        rungs.append(await _maybe_add_list_member(consent, dc))

    return LadderResult(
        finding=finding,
        provider="mailchimp",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _api_root(key: str, dc: str | None) -> ProbeResult:
    """SAFE: ``GET /3.0/`` is the whoami for a Mailchimp key.

    Returns account identity (account id, login email, contact, total
    subscribers) and is the rung that decides VALID vs DENIED.
    """
    name = "api-root"
    if dc is None:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail="key has no datacenter suffix (expected <32hex>-us<NN>); cannot address the API",
            evidence={"datacenter": None},
        )

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"https://{dc}.api.mailchimp.com/3.0/",
                headers=_basic(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"key rejected (HTTP {resp.status_code})",
            evidence={"status": resp.status_code, "datacenter": dc},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"key authenticates as {body.get('login_id') or body.get('account_id') or '?'} "
            f"({body.get('account_name') or body.get('email') or 'account'})"
        ),
        evidence={
            "status": resp.status_code,
            "datacenter": dc,
            "account_id": body.get("account_id"),
            "account_name": body.get("account_name"),
            "login_id": body.get("login_id"),
            "email": body.get("email"),
            "total_subscribers": body.get("total_subscribers"),
        },
    )


async def _list_audiences(key: str, dc: str | None) -> ProbeResult:
    """SAFE: ``GET /3.0/lists?count=10`` enumerates the audiences/lists the key
    can reach (names, member counts) — reachable resources, deeper than identity.
    """
    name = "list-audiences"
    if dc is None:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail="key has no datacenter suffix; cannot address the API",
            evidence={"datacenter": None},
        )

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"https://{dc}.api.mailchimp.com/3.0/lists",
                headers=_basic(key),
                params={"count": "10"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list audiences (HTTP {resp.status_code})",
            evidence={"status": resp.status_code, "datacenter": dc},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    lists = body.get("lists") if isinstance(body.get("lists"), list) else []
    # Record only non-secret identifiers (audience names), never member PII.
    names = [item.get("name") for item in lists if isinstance(item, dict) and item.get("name")]
    total_items = (
        body.get("total_items") if isinstance(body.get("total_items"), int) else len(names)
    )
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"{total_items} audience(s); reachable: {', '.join(names[:5])}"
            if names
            else "no audiences reachable"
        ),
        evidence={
            "status": resp.status_code,
            "datacenter": dc,
            "total_items": total_items,
            "audiences_sample": names[:25],
        },
    )


# --- gated (manual) rung -----------------------------------------------------


def _add_member_safe_curl(dc: str | None) -> str:
    """The safe curl printed for the manual gated add-member rung (secret as $KEY)."""
    host = dc or "DC"
    return (
        "curl -X POST "
        f"'https://{host}.api.mailchimp.com/3.0/lists/LIST_ID/members' "
        '-H "Authorization: Basic $KEY" '
        '-H "Content-Type: application/json" '
        '--data \'{"email_address":"probe@example.com","status":"subscribed"}\''
    )


@gated
async def mailchimp_gated_add_member(consent: Consent, dc: str | None) -> ProbeResult:
    """GATED: ``POST /3.0/lists/{list_id}/members`` would write a subscriber.

    State-changing and it injects into a marketing pipeline that emails third
    parties. Decorated with :func:`vtx_recon.safety.gated`, so the safety
    boundary runs *before* this body and, without BOTH ``--prove`` and an
    authorized scope, raises :class:`GatedProbeBlocked` and nothing executes.
    Even with consent this rung is MANUAL: the URL needs a ``{list_id}`` (from
    ``list-audiences``) the engine cannot fill, so it never fires a live
    request — it only returns a safe curl (with the secret kept as ``$KEY``) for
    an operator to run by hand. The public ladder records it as a blocked/manual
    note either way.
    """
    name = "add-list-member"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: needs a list_id from list-audiences; run the safe curl "
            "by hand to exercise the mutating impact"
        ),
        evidence={"manual": True, "safe_curl": _add_member_safe_curl(dc)},
    )


async def _maybe_add_list_member(consent: Consent, dc: str | None) -> ProbeResult:
    """Attempt the gated add-member rung; report it blocked when consent is absent.

    The gating happens inside :func:`mailchimp_gated_add_member`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the mutating step by hand.
    """
    try:
        return await mailchimp_gated_add_member(consent, dc)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="add-list-member",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _add_member_safe_curl(dc),
            },
        )
