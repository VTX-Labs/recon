"""Sentry capability ladder — prove depth of access for a leaked auth token.

Handles TruffleHog ``SentryToken`` (modern user auth tokens,
``sntryu_<64 hex>``) and ``SentryOrgToken`` (org tokens,
``sntrys_eyJ<base64>``). Both authenticate the same way:
``Authorization: Bearer <token>`` against ``https://sentry.io/api/0``.

The ordered ladder (depth of access, least -> most revealing):

  1. ``list-organizations``  ``GET /organizations/`` — TruffleHog's ACTUAL
     verification endpoint for both user and org tokens. 200 = live token,
     403 = valid token lacking org scope, 401 = revoked. Read-only; this is
     the rung that decides VALID vs DENIED and maps blast radius (which orgs
     the token can reach). The unverified ``/auth/validate/`` rung was dropped:
     it is not TruffleHog's path and was ``endpoint_verified:false``.
  2. ``list-org-projects``   ``GET /organizations/{organization_slug}/projects/``
     — lists the projects (metadata, DSNs) within a reachable org, proving
     depth into the monitoring config without touching event data. Read-only,
     BUT its URL needs an ``{organization_slug}`` the engine cannot fill, so it
     is rendered as a MANUAL safe-curl note (no live call) with the secret kept
     as ``$KEY``.
  3. ``read-project-issues`` ``GET /projects/{organization_slug}/{project_slug}/issues/``
     — GATED. Reads captured issues/error events; error payloads routinely
     contain third-party PII, request bodies, headers, tokens and stack traces,
     so reading them exposes customer data. Its URL needs two slugs the engine
     cannot fill, so even with consent it is a MANUAL safe-curl note: never
     auto-fired, always rendered as a blocked/manual rung.

Every rung is ordered (identity first, then depth), the live rung is a
READ-ONLY GET, and the ladder never raises across the public boundary:
failures become a :class:`ProbeResult` with ``success=False`` so one dead key
cannot crash a batch run. The raw token is held only transiently for the HTTP
call and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "sentry_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("SentryToken", "SentryOrgToken")

API_BASE = "https://sentry.io/api/0"

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
    """Standard Sentry bearer header for a user/org auth token."""
    return {"Authorization": f"Bearer {key}"}


@register("SentryToken", "SentryOrgToken")
async def sentry_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Sentry capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs ``list-organizations`` first (TruffleHog's verification endpoint)
    and only descends if the token authenticated. The deeper rungs both embed
    slugs the engine cannot fill, so they are emitted as manual safe-curl notes
    rather than live calls. The ``read-project-issues`` rung is additionally
    GATED. Never raises across the public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: list-organizations (SAFE) — decides live/dead ---------------
    identity = await _list_organizations(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: list-org-projects (SAFE, manual safe-curl) --------------
        # The URL embeds an {organization_slug} the engine cannot fill, so this
        # never fires a live request: it is rendered as a manual note.
        rungs.append(_list_org_projects_manual())

        # --- Rung 3: read-project-issues (GATED, manual safe-curl) -----------
        # The URL embeds two slugs the engine cannot fill, so this never fires
        # a live request. The @gated wrapper still enforces consent first, so
        # without --prove + --i-am-authorized the rung is recorded as blocked.
        rungs.append(await _maybe_read_project_issues(consent))

    return LadderResult(
        finding=finding,
        provider="sentry",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- individual rungs --------------------------------------------------------


async def _list_organizations(key: str) -> ProbeResult:
    """SAFE: ``GET /organizations/`` — TruffleHog's verification endpoint.

    200 = live token (lists the orgs it can reach, mapping blast radius);
    403 = a valid token that lacks org scope; 401 = revoked. Read-only.
    """
    name = "list-organizations"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE}/organizations/",
                headers=_bearer(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"token rejected or lacking org scope (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # Sentry returns a bare JSON array of organization objects.
    orgs = body if isinstance(body, list) else []
    # Record only non-secret identifiers (org slugs), never raw payloads.
    slugs = [o.get("slug") for o in orgs if isinstance(o, dict) and o.get("slug")]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"{len(slugs)} organization(s) reachable: {', '.join(slugs[:5])}"
            if slugs
            else "token authenticates but reaches no organizations"
        ),
        evidence={
            "status": resp.status_code,
            "organization_count": len(slugs),
            "organization_slugs_sample": slugs[:25],
        },
    )


def _list_org_projects_safe_curl() -> str:
    """The safe curl printed for the manual list-org-projects rung (secret as $KEY)."""
    return (
        "curl "
        f"'{API_BASE}/organizations/ORGANIZATION_SLUG/projects/' "
        '-H "Authorization: Bearer $KEY"'
    )


def _list_org_projects_manual() -> ProbeResult:
    """SAFE (manual): ``GET /organizations/{organization_slug}/projects/``.

    Lists the projects (metadata, DSNs) within a reachable org. Read-only, but
    the URL needs an ``{organization_slug}`` from list-organizations that the
    engine cannot fill, so this never fires a live request — it only returns a
    safe curl (with the secret kept as ``$KEY``) for an operator to run by hand.
    """
    return ProbeResult(
        name="list-org-projects",
        tier=ProbeTier.SAFE,
        success=False,
        detail=(
            "manual rung: needs an {organization_slug} from list-organizations; "
            "run the safe curl by hand to enumerate projects/DSNs"
        ),
        evidence={"manual": True, "safe_curl": _list_org_projects_safe_curl()},
    )


# --- gated (manual) rung -----------------------------------------------------


def _read_issues_safe_curl() -> str:
    """The safe curl printed for the manual gated read-project-issues rung (secret as $KEY)."""
    return (
        "curl "
        f"'{API_BASE}/projects/ORGANIZATION_SLUG/PROJECT_SLUG/issues/' "
        '-H "Authorization: Bearer $KEY"'
    )


@gated
async def sentry_gated_read_issues(consent: Consent) -> ProbeResult:
    """GATED: ``GET /projects/{organization_slug}/{project_slug}/issues/``.

    Reads captured issues/error events. Error payloads routinely contain
    third-party PII (request bodies, headers, tokens, stack traces), so reading
    them exposes customer data — hence GATED. Decorated with
    :func:`vtx_recon.safety.gated`, so the safety boundary runs *before* this
    body and, without BOTH ``--prove`` and an authorized scope, raises
    :class:`GatedProbeBlocked` and nothing executes. Even with consent this rung
    is MANUAL: the URL needs two slugs the engine cannot fill, so it never fires
    a live request — it only returns a safe curl (with the secret kept as
    ``$KEY``) for an operator to run by hand. The public ladder records it as a
    blocked/manual note either way.
    """
    name = "read-project-issues"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: needs {organization_slug}/{project_slug} from "
            "list-org-projects; run the safe curl by hand to read third-party PII"
        ),
        evidence={"manual": True, "safe_curl": _read_issues_safe_curl()},
    )


async def _maybe_read_project_issues(consent: Consent) -> ProbeResult:
    """Attempt the gated issues-read rung; report it as blocked when consent is absent.

    The gating happens inside :func:`sentry_gated_read_issues`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the PII-reading step by hand.
    """
    try:
        return await sentry_gated_read_issues(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="read-project-issues",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _read_issues_safe_curl(),
            },
        )
