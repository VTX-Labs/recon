"""Capability ladder for CircleCI personal API tokens (``CCIPAT_...``).

CircleCI tokens authenticate via the ``Circle-Token`` header against the v2
REST API. TruffleHog surfaces them under the ``Circle`` / ``CircleCI``
detectors (modern tokens carry the ``CCIPAT_`` prefix; legacy v1 tokens are
bare 40-char hex, which the key regex deliberately does not cover). The ladder
climbs:

* **``whoami``** (SAFE) — ``GET /api/v2/me`` confirms the token authenticates
  and returns the current user's id / login / name. This is exactly the
  endpoint TruffleHog hits to verify the credential, so a success here is the
  ground truth that the key is live.
* **``list-collaborations``** (SAFE) — ``GET /api/v2/me/collaborations`` lists
  every VCS org / collaboration the token can reach, proving the blast radius
  of accessible projects without changing anything.
* **``trigger-pipeline``** (GATED) — ``POST /api/v2/project/{project-slug}/pipeline``
  would start a new pipeline, consuming compute credits (billable) and
  executing CI — i.e. arbitrary code execution in the build environment. Its
  URL needs a ``{project-slug}`` the engine cannot supply, so it is never
  auto-fired: it is rendered as a MANUAL gated rung with a safe curl that
  keeps the secret as ``$KEY``.

Every rung is ordered (identity first, then depth), READ-ONLY by default, and
never raises across the public boundary: failures become a
:class:`ProbeResult` with ``success=False`` so one dead key cannot crash a
batch run. The raw token is held only transiently for the HTTP call and never
lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier
from . import register

__all__ = ["circleci_ladder"]

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


@register("Circle", "CircleCI")
async def circleci_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """CircleCI ladder: SAFE identity (``/me``) -> SAFE reachable orgs
    (``/me/collaborations``) -> MANUAL gated ``trigger-pipeline``.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _circleci_whoami(key)
    rungs.append(identity)
    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _circleci_collaborations(key))
        # trigger-pipeline is GATED *and* needs a {project-slug} the engine
        # cannot fill, so it is never auto-fired: emit a MANUAL gated note with
        # a safe curl (secret stays $KEY).
        rungs.append(_circleci_trigger_pipeline_manual())

    return LadderResult(
        finding=finding,
        provider="circleci",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _circleci_whoami(key: str) -> ProbeResult:
    """SAFE: ``GET /api/v2/me`` confirms the token and returns id/login/name.

    This is the exact endpoint TruffleHog verifies against.
    """
    name = "circleci.whoami"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://circleci.com/api/v2/me",
                headers={"Circle-Token": key, "Accept": "application/json"},
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

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"authenticated as {body.get('login')} (id {body.get('id')})",
        evidence={
            "status": resp.status_code,
            "id": body.get("id"),
            "login": body.get("login"),
            "name": body.get("name"),
        },
    )


async def _circleci_collaborations(key: str) -> ProbeResult:
    """SAFE: ``GET /api/v2/me/collaborations`` lists reachable VCS orgs.

    Proves the blast radius of accessible projects (which orgs the token can
    reach) without changing anything.
    """
    name = "circleci.list-collaborations"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://circleci.com/api/v2/me/collaborations",
                headers={"Circle-Token": key, "Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list collaborations (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    collaborations = body if isinstance(body, list) else []
    # Summarise the reachable orgs without dumping the whole payload: the VCS
    # slugs are enough to size the blast radius.
    slugs = [
        slug
        for c in collaborations
        if isinstance(c, dict)
        and isinstance((slug := c.get("slug") or c.get("name") or c.get("vcs_type")), str)
    ]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"token reaches {len(collaborations)} collaboration(s): "
            f"{', '.join(slugs) if slugs else '(none)'}"
        ),
        evidence={
            "status": resp.status_code,
            "collaboration_count": len(collaborations),
            "slugs": slugs,
        },
    )


def _circleci_trigger_pipeline_manual() -> ProbeResult:
    """MANUAL (GATED-tier): ``POST /api/v2/project/{project-slug}/pipeline``.

    Triggering a pipeline consumes compute credits (billable) and executes CI
    — arbitrary code execution in the build environment. The URL needs a
    ``{project-slug}`` the engine cannot fill, so this rung is NEVER
    auto-fired. It is recorded as a manual, blocked GATED note carrying a
    copy-pasteable curl whose secret stays ``$KEY`` and whose project slug
    stays a placeholder for the operator to fill in deliberately.
    """
    name = "circleci.trigger-pipeline"
    safe_curl = (
        'curl -sS -X POST -H "Circle-Token: $KEY" -H "Content-Type: application/json" '
        '"https://circleci.com/api/v2/project/{project-slug}/pipeline"'
    )
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=True,
        detail=(
            "MANUAL gated rung: triggering a pipeline is billable and executes "
            "CI (arbitrary code execution). The {project-slug} cannot be "
            "auto-filled, so this is never auto-fired; run it by hand only when "
            f"authorized: {safe_curl}"
        ),
        evidence={"manual": True, "billable": True, "safe_curl": safe_curl},
    )
