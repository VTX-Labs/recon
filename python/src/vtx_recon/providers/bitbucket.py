"""Bitbucket capability ladder — prove depth of access for a leaked app password.

Handles TruffleHog ``BitbucketAppPassword`` findings. A Bitbucket Cloud app
password matches ``ATBB[A-Za-z0-9_=.-]+``, but — and this is the crux — it is
**not usable on its own**. Bitbucket's REST API authenticates with HTTP Basic
auth as ``username:app_password``, so the ``Authorization: Basic {key}`` header
needs ``{key}`` to be the base64 of ``"<username>:ATBB..."``. The raw finding is
only the bare ``ATBB...`` secret; the paired username is *not* present in it.

Because the engine cannot synthesise the ``<username>`` half of the credential,
**every rung here is a MANUAL safe-curl note** — none can be auto-fired. Each
rung renders a curl that keeps the secret as ``$KEY`` (and a ``USERNAME``
placeholder for the operator to supply) so an authorized operator can run it by
hand. Nothing on this ladder ever issues a live request.

The ordered ladder (depth of access, least -> most revealing):

  1. ``whoami`` ``GET /2.0/user`` — TruffleHog's own verification call. With
     Basic auth (base64 of ``username:app_password``) it returns the account
     (uuid, username, display name). HTTP 200 confirms identity; 403 still
     confirms a live credential whose scope merely excludes ``account`` (a live
     finding either way). MANUAL: needs the paired username. SAFE tier.
  2. ``list-workspace-repo-permissions``
     ``GET /2.0/user/permissions/repositories`` — lists every repository the
     credential can reach and the permission level (read/write/admin) on each,
     mapping the blast radius. Read-only. MANUAL: needs the paired username.
     SAFE tier.
  3. ``create-repository``
     ``POST /2.0/repositories/{workspace}/{repo_slug}`` — creates a new repo in
     a writable workspace: resource-creating, state-changing write impact.
     GATED; and its URL needs ``{workspace}`` / ``{repo_slug}`` the engine
     cannot fill, so it is rendered as a MANUAL blocked safe-curl note (never
     auto-fired).

Every rung is ordered (identity first, then depth) and the ladder never raises
across the public boundary: failures become a :class:`ProbeResult` with
``success=False`` so one half-credential cannot crash a batch run. The raw
secret is held only transiently and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "bitbucket_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("BitbucketAppPassword",)

API_BASE = "https://api.bitbucket.org/2.0"


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.

    For Bitbucket every rung is manual (the engine lacks the paired username),
    so no rung reports ``success=True`` and the verdict is DENIED unless an
    operator runs the safe curls by hand — the honest result for a
    half-credential.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("BitbucketAppPassword")
async def bitbucket_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered Bitbucket capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Every rung is a manual safe-curl note because the ``Authorization: Basic``
    header requires base64 of ``username:app_password`` and the username is not
    present in the raw finding. The mutating ``create-repository`` rung is
    additionally GATED and routed through the safety boundary so it is recorded
    as blocked without the full ``--prove`` + ``--i-am-authorized`` consent.
    Never raises across the public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # --- Rung 1: whoami (SAFE, manual) — identity / verification -------------
    rungs.append(_whoami_manual())

    # --- Rung 2: list-workspace-repo-permissions (SAFE, manual) — blast radius
    rungs.append(_list_repo_permissions_manual())

    # --- Rung 3: create-repository (GATED, manual safe-curl) -----------------
    # Resource-creating write. The @gated wrapper enforces consent first, so
    # without --prove + --i-am-authorized the rung is recorded as blocked. Even
    # with consent it stays MANUAL (URL needs {workspace}/{repo_slug} and the
    # header needs the paired username), so it never fires a live request.
    rungs.append(await _maybe_create_repository(consent))

    return LadderResult(
        finding=finding,
        provider="bitbucket",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- manual SAFE rungs -------------------------------------------------------


def _whoami_safe_curl() -> str:
    """Safe curl for the manual ``whoami`` rung (secret kept as $KEY)."""
    return f'curl -s \'{API_BASE}/user\' -H "Accept: application/json" -u "USERNAME:$KEY"'


def _whoami_manual() -> ProbeResult:
    """SAFE (manual): ``GET /2.0/user`` confirms the account behind the credential.

    This is TruffleHog's verification call. With Basic auth (base64 of
    ``username:app_password``) a 200 returns the account uuid/username/display
    name and confirms identity; a 403 still confirms a live credential whose
    scope excludes ``account``. We cannot fire it automatically — the header
    needs the paired username that is absent from the raw key — so we emit a
    safe curl.
    """
    name = "whoami"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        detail=(
            "manual rung: Basic auth needs base64 of 'username:$KEY'; the paired "
            "username is not in the raw finding. Run the safe curl by hand — 200 "
            "returns the account (uuid/username); 403 still confirms a live "
            "credential lacking the 'account' scope"
        ),
        evidence={
            "manual": True,
            "success_status": [200, 403],
            "safe_curl": _whoami_safe_curl(),
        },
    )


def _list_repo_permissions_safe_curl() -> str:
    """Safe curl for the manual repo-permissions rung (secret kept as $KEY)."""
    return (
        f"curl -s '{API_BASE}/user/permissions/repositories' "
        '-H "Accept: application/json" '
        '-u "USERNAME:$KEY"'
    )


def _list_repo_permissions_manual() -> ProbeResult:
    """SAFE (manual): ``GET /2.0/user/permissions/repositories`` maps the blast radius.

    Lists every repository the credential can access and the permission level
    (read/write/admin) on each — read-only enumeration of the leaked app
    password's reach. MANUAL for the same reason: the Basic header needs the
    paired username that is not in the raw key.
    """
    name = "list-workspace-repo-permissions"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        detail=(
            "manual rung: lists each reachable repository and the permission level "
            "(read/write/admin) — the credential's blast radius. Needs the paired "
            "username for Basic auth, so run the safe curl by hand"
        ),
        evidence={
            "manual": True,
            "success_status": [200],
            "safe_curl": _list_repo_permissions_safe_curl(),
        },
    )


# --- gated (manual) rung -----------------------------------------------------


def _create_repository_safe_curl() -> str:
    """Safe curl for the manual gated create-repository rung (secret kept as $KEY)."""
    return (
        "curl -X POST "
        f"'{API_BASE}/repositories/WORKSPACE/REPO_SLUG' "
        '-H "Content-Type: application/json" '
        '-u "USERNAME:$KEY" '
        '--data \'{"scm":"git","is_private":true}\''
    )


@gated
async def bitbucket_gated_create_repository(consent: Consent) -> ProbeResult:
    """GATED (manual): ``POST /2.0/repositories/{workspace}/{repo_slug}`` creates a repo.

    Creating a new repository in a writable workspace is resource-creating,
    state-changing write impact. Decorated with :func:`vtx_recon.safety.gated`,
    so the safety boundary runs *before* this body and, without BOTH ``--prove``
    and an authorized scope, raises :class:`GatedProbeBlocked` and nothing
    executes. Even with consent this rung is MANUAL: the URL needs
    ``{workspace}`` / ``{repo_slug}`` the engine cannot fill (and the Basic
    header needs the paired username), so it never fires a live request — it
    only returns a safe curl (secret kept as ``$KEY``) for an operator to run by
    hand. The public ladder records it as a blocked/manual note either way.
    """
    name = "create-repository"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: needs a writable {workspace}/{repo_slug} and the paired "
            "username; run the safe curl by hand to exercise the resource-creating "
            "write impact"
        ),
        evidence={
            "manual": True,
            "success_status": [200, 201],
            "safe_curl": _create_repository_safe_curl(),
        },
    )


async def _maybe_create_repository(consent: Consent) -> ProbeResult:
    """Attempt the gated create-repository rung; report it as blocked when consent is absent.

    The gating happens inside :func:`bitbucket_gated_create_repository`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the mutating step by hand.
    """
    try:
        return await bitbucket_gated_create_repository(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="create-repository",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _create_repository_safe_curl(),
            },
        )
