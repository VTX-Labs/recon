"""Capability ladder for Travis CI API access tokens.

Travis tokens authenticate via the ``Authorization: token {key}`` header (with
``Travis-API-Version: 3``) against the v3 REST API at ``api.travis-ci.com``.
TruffleHog surfaces them under the ``TravisCI`` detector. The token has no
self-identifying standalone shape, so routing relies on the detector rather
than a key regex. The ladder climbs:

* **``whoami``** (SAFE) — ``GET /user`` confirms the token authenticates and
  returns the current user's login / id / account info. This is exactly the
  endpoint TruffleHog hits to verify the credential, so a success here is the
  ground truth that the key is live.
* **``list-repos``** (SAFE) — ``GET /repos`` lists every repository the token
  can administer / build (the reachable resource set), proving depth beyond
  bare identity without changing anything.
* **``trigger-build``** (GATED) — ``POST /repo/{repository.id}/requests`` would
  queue a build request on a reachable repo, executing CI (arbitrary code in
  the build environment) and consuming build minutes — state-changing and
  billable, the real impact of a leaked Travis token. Its URL needs a
  ``{repository.id}`` the engine cannot supply, so it is never auto-fired: it
  is rendered as a MANUAL gated rung with a safe curl that keeps the secret as
  ``$KEY``.

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

__all__ = ["travisci_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# Travis v3 requires these headers on every request; the API version pins the
# response schema and the explicit User-Agent is required by the API gateway.
_TRAVIS_API_VERSION = "3"
_USER_AGENT = "vtx-recon"


def _auth_headers(key: str) -> dict[str, str]:
    return {
        "Authorization": f"token {key}",
        "Travis-API-Version": _TRAVIS_API_VERSION,
        "User-Agent": _USER_AGENT,
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


@register("TravisCI")
async def travisci_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Travis CI ladder: SAFE identity (``/user``) -> SAFE reachable repos
    (``/repos``) -> MANUAL gated ``trigger-build``.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _travisci_whoami(key)
    rungs.append(identity)
    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _travisci_list_repos(key))
        # trigger-build is GATED *and* needs a {repository.id} the engine
        # cannot fill, so it is never auto-fired: emit a MANUAL gated note with
        # a safe curl (secret stays $KEY).
        rungs.append(_travisci_trigger_build_manual())

    return LadderResult(
        finding=finding,
        provider="travisci",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _travisci_whoami(key: str) -> ProbeResult:
    """SAFE: ``GET /user`` confirms the token and returns id/login/name.

    This is the exact endpoint TruffleHog verifies against.
    """
    name = "travisci.whoami"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.travis-ci.com/user",
                headers=_auth_headers(key),
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


async def _travisci_list_repos(key: str) -> ProbeResult:
    """SAFE: ``GET /repos`` lists repositories the token can administer/build.

    Proves the blast radius of accessible projects (which repos the token can
    reach) without changing anything.
    """
    name = "travisci.list-repos"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.travis-ci.com/repos",
                headers=_auth_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list repos (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # Travis v3 wraps the collection: {"repositories": [...]}.
    repositories = body.get("repositories") if isinstance(body, dict) else None
    repositories = repositories if isinstance(repositories, list) else []
    # Summarise the reachable repos without dumping the whole payload: the slugs
    # are enough to size the blast radius.
    slugs = [
        slug
        for r in repositories
        if isinstance(r, dict) and isinstance((slug := r.get("slug") or r.get("name")), str)
    ]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"token reaches {len(repositories)} repo(s): {', '.join(slugs) if slugs else '(none)'}"
        ),
        evidence={
            "status": resp.status_code,
            "repo_count": len(repositories),
            "slugs": slugs,
        },
    )


def _travisci_trigger_build_manual() -> ProbeResult:
    """MANUAL (GATED-tier): ``POST /repo/{repository.id}/requests``.

    Triggering a build queues a build request that executes CI (arbitrary code
    execution in the build environment) and consumes build minutes (billable).
    The URL needs a ``{repository.id}`` the engine cannot fill, so this rung is
    NEVER auto-fired. It is recorded as a manual, blocked GATED note carrying a
    copy-pasteable curl whose secret stays ``$KEY`` and whose repository id
    stays a placeholder for the operator to fill in deliberately.
    """
    name = "travisci.trigger-build"
    safe_curl = (
        'curl -sS -X POST -H "Authorization: token $KEY" -H "Travis-API-Version: 3" '
        '-H "Content-Type: application/json" '
        '"https://api.travis-ci.com/repo/{repository.id}/requests"'
    )
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        blocked=True,
        detail=(
            "MANUAL gated rung: triggering a build is billable and executes CI "
            "(arbitrary code execution). The {repository.id} cannot be "
            "auto-filled, so this is never auto-fired; run it by hand only when "
            f"authorized: {safe_curl}"
        ),
        evidence={"manual": True, "billable": True, "safe_curl": safe_curl},
    )
