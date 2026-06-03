"""GitHub capability ladder — prove depth of access for a leaked PAT.

Handles TruffleHog ``Github`` findings: classic ``ghp_`` / ``gho_`` tokens,
fine-grained ``github_pat_`` tokens, and OAuth ``gho_`` tokens. Every rung in
this module is a READ-ONLY ``GET``; no rung here creates, deletes, or mutates
anything on GitHub, so the whole ladder is SAFE by construction.

The ordered ladder (depth of access, least -> most revealing):

  1. ``identity``      ``GET /user`` — does the token authenticate? Who is it?
  2. ``classic_scopes`` read ``X-OAuth-Scopes`` from the ``/user`` response.
     Classic PATs/OAuth tokens advertise their scopes in this header;
     fine-grained PATs do **not**, so we detect fine-grained behaviourally
     (authenticates, but the header is absent).
  3. ``dangerous_scopes`` flag high-impact scopes (``repo``, ``admin:*``,
     ``delete_repo``, ``workflow``, ...) that a classic token carries.
  4. ``private_repos``  ``GET /user/repos?visibility=private`` — count the
     private repositories the token can already read.
  5. ``org_membership`` ``GET /user/orgs`` — walk org membership reachable
     with the token (lateral-movement surface).

There is intentionally **no GATED rung** in GitHub's safe ladder: reading
identity, scopes, private-repo listings, and org membership are all
non-billable, non-state-changing GETs. To still exercise — and to *prove*
the safety boundary is wired — this module also defines a single
demonstration GATED probe, :func:`gated_write_probe`, which would change
state (it is never called by the safe ladder and is unreachable without
``--prove`` + ``--i-am-authorized``). The ladder calls it through the safety
guard so a consented run can climb one rung higher to ``PROVEN``.

Confirmed API facts: classic PATs expose ``X-OAuth-Scopes`` on ``/user``;
fine-grained PATs do not (probe behaviourally). All endpoints are on
``https://api.github.com``.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "github_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Github", "GitHub", "GithubApp", "GitHubOauth2")

API_BASE = "https://api.github.com"
_TIMEOUT = 15.0

# Scopes that meaningfully escalate impact if a classic token carries them.
# (Fine-grained tokens do not use these textual scopes.)
_DANGEROUS_SCOPES = frozenset(
    {
        "repo",
        "delete_repo",
        "workflow",
        "write:packages",
        "delete:packages",
        "admin:org",
        "write:org",
        "admin:repo_hook",
        "admin:org_hook",
        "admin:public_key",
        "admin:gpg_key",
        "admin:enterprise",
        "manage_runners:org",
        "user",
        "write:discussion",
        "codespace",
    }
)


def _headers(token: str) -> dict[str, str]:
    """Standard GitHub REST headers carrying the bearer token."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vtx-recon",
    }


def _parse_scopes(header_value: str | None) -> list[str]:
    """Parse the comma-separated ``X-OAuth-Scopes`` header into a clean list."""
    if not header_value:
        return []
    return [s.strip() for s in header_value.split(",") if s.strip()]


async def github_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered GitHub capability ladder for a single finding.

    Never raises across the public boundary: any error is captured into a
    :class:`ProbeResult` and the worst outcome is a ``DENIED`` / ``N/A``
    verdict. The authorized scope is required (the whole ladder refuses to
    run without it) and is recorded on the returned :class:`LadderResult`.
    """
    # Laddering at all — even the safe tier — requires a named, authorized
    # scope. This raises ScopeRequired, which the CLI maps to an exit code;
    # it is a *configuration* failure, not a probe failure, so we let it out.
    scope = consent.require_ladder_scope()

    result = LadderResult(
        finding=finding,
        provider="github",
        verdict=Verdict.NA,
        authorized_scope=scope,
    )
    token = finding.raw

    async with httpx.AsyncClient(base_url=API_BASE, timeout=_TIMEOUT) as client:
        # --- Rung 1: identity (SAFE) -----------------------------------------
        identity = await _rung_identity(client, token)
        result.rungs.append(identity)
        if not identity.success:
            # Token does not authenticate (or the network failed): nothing to
            # ladder. DENIED if we positively saw a 401/403; N/A if we never
            # got a usable answer.
            result.verdict = (
                Verdict.DENIED if identity.evidence.get("status") in (401, 403) else Verdict.NA
            )
            return result

        # Token is live: at minimum this is VALID. Safe rungs may add depth.
        result.verdict = Verdict.VALID
        login = identity.evidence.get("login")

        # --- Rung 2: classic scopes header (SAFE) ----------------------------
        scopes_rung, scopes, is_finegrained = _rung_classic_scopes(identity)
        result.rungs.append(scopes_rung)

        # --- Rung 3: dangerous scopes (SAFE) ---------------------------------
        result.rungs.append(_rung_dangerous_scopes(scopes, is_finegrained))

        # --- Rung 4: private repos reachable (SAFE) --------------------------
        result.rungs.append(await _rung_private_repos(client, token))

        # --- Rung 5: org membership walk (SAFE) ------------------------------
        result.rungs.append(await _rung_org_membership(client, token))

        # --- Optional gated rung: only reachable with full consent -----------
        # The safe tier above is already complete; this rung is structurally
        # unreachable unless BOTH --prove and --i-am-authorized were supplied.
        gated_rung = await _maybe_gated_rung(client, token, consent, login)
        result.rungs.append(gated_rung)
        if gated_rung.success and not gated_rung.blocked:
            # A gated, state-changing probe actually ran under consent.
            result.verdict = Verdict.PROVEN

    return result


# --- individual rungs --------------------------------------------------------


async def _rung_identity(client: httpx.AsyncClient, token: str) -> ProbeResult:
    """SAFE: ``GET /user`` to confirm the token is live and learn the identity.

    The full response headers are stashed (non-secret) so the scopes rung can
    read ``X-OAuth-Scopes`` without a second request.
    """
    rung = ProbeResult(name="identity", tier=ProbeTier.SAFE, success=False)
    try:
        resp = await client.get("/user", headers=_headers(token))
    except httpx.HTTPError as exc:
        rung.detail = f"request failed: {type(exc).__name__}"
        rung.evidence = {"error": str(exc)}
        return rung

    rung.evidence["status"] = resp.status_code
    # Capture the scope-bearing headers now (non-secret); used by rung 2.
    rung.evidence["x_oauth_scopes"] = resp.headers.get("x-oauth-scopes")
    rung.evidence["x_accepted_oauth_scopes"] = resp.headers.get("x-accepted-oauth-scopes")

    if resp.status_code != 200:
        rung.detail = f"token did not authenticate (HTTP {resp.status_code})"
        return rung

    try:
        body = resp.json()
    except ValueError:
        body = {}
    login = body.get("login") if isinstance(body, dict) else None
    rung.evidence["login"] = login
    rung.evidence["account_id"] = body.get("id") if isinstance(body, dict) else None
    rung.success = True
    rung.detail = f"authenticated as {login!r}" if login else "authenticated"
    return rung


def _rung_classic_scopes(identity: ProbeResult) -> tuple[ProbeResult, list[str], bool]:
    """SAFE: read ``X-OAuth-Scopes`` from the identity response.

    Returns the rung, the parsed scope list, and whether the token looks
    fine-grained (authenticates but advertises no classic scope header).
    """
    rung = ProbeResult(name="classic_scopes", tier=ProbeTier.SAFE, success=False)
    raw_header = identity.evidence.get("x_oauth_scopes")
    scopes = _parse_scopes(raw_header if isinstance(raw_header, str) else None)

    # Header present (even if empty string "") => classic/OAuth token.
    # Header absent (None) on an authenticated token => fine-grained PAT.
    header_present = raw_header is not None
    is_finegrained = not header_present

    rung.evidence["scopes"] = scopes
    rung.evidence["token_type"] = "fine-grained" if is_finegrained else "classic"
    if is_finegrained:
        rung.success = True
        rung.detail = (
            "fine-grained PAT: no X-OAuth-Scopes header (access is per-resource; "
            "probe behaviourally)"
        )
    elif scopes:
        rung.success = True
        rung.detail = f"classic token scopes: {', '.join(scopes)}"
    else:
        # Classic token with an explicitly empty scope set (header present, empty).
        rung.success = True
        rung.detail = "classic token with no scopes granted"
    return rung, scopes, is_finegrained


def _rung_dangerous_scopes(scopes: list[str], is_finegrained: bool) -> ProbeResult:
    """SAFE: flag high-impact scopes carried by a classic token."""
    rung = ProbeResult(name="dangerous_scopes", tier=ProbeTier.SAFE, success=False)
    if is_finegrained:
        rung.detail = "n/a for fine-grained PAT (no textual scopes; gated by resource perms)"
        rung.evidence["dangerous"] = []
        return rung

    dangerous = sorted(s for s in scopes if s in _DANGEROUS_SCOPES)
    rung.evidence["dangerous"] = dangerous
    if dangerous:
        rung.success = True
        rung.detail = f"DANGEROUS scopes present: {', '.join(dangerous)}"
    else:
        rung.detail = "no dangerous scopes detected"
    return rung


async def _rung_private_repos(client: httpx.AsyncClient, token: str) -> ProbeResult:
    """SAFE: list private repositories the token can read (a GET, no writes)."""
    rung = ProbeResult(name="private_repos", tier=ProbeTier.SAFE, success=False)
    try:
        resp = await client.get(
            "/user/repos",
            headers=_headers(token),
            params={
                "visibility": "private",
                "per_page": "100",
                "affiliation": "owner,collaborator,organization_member",
            },
        )
    except httpx.HTTPError as exc:
        rung.detail = f"request failed: {type(exc).__name__}"
        rung.evidence = {"error": str(exc)}
        return rung

    rung.evidence["status"] = resp.status_code
    if resp.status_code != 200:
        rung.detail = f"could not list private repos (HTTP {resp.status_code})"
        return rung

    try:
        repos = resp.json()
    except ValueError:
        repos = []
    if not isinstance(repos, list):
        repos = []
    # Record only non-sensitive identifiers (full_name), never repo contents.
    names = [r.get("full_name") for r in repos if isinstance(r, dict) and r.get("full_name")]
    rung.evidence["private_repo_count"] = len(names)
    rung.evidence["private_repos_sample"] = names[:25]
    rung.success = len(names) > 0
    rung.detail = (
        f"{len(names)} private repo(s) reachable" if names else "no private repos reachable"
    )
    return rung


async def _rung_org_membership(client: httpx.AsyncClient, token: str) -> ProbeResult:
    """SAFE: walk org membership reachable with the token (a GET, no writes)."""
    rung = ProbeResult(name="org_membership", tier=ProbeTier.SAFE, success=False)
    try:
        resp = await client.get("/user/orgs", headers=_headers(token), params={"per_page": "100"})
    except httpx.HTTPError as exc:
        rung.detail = f"request failed: {type(exc).__name__}"
        rung.evidence = {"error": str(exc)}
        return rung

    rung.evidence["status"] = resp.status_code
    if resp.status_code != 200:
        rung.detail = f"could not list orgs (HTTP {resp.status_code})"
        return rung

    try:
        orgs = resp.json()
    except ValueError:
        orgs = []
    if not isinstance(orgs, list):
        orgs = []
    logins = [o.get("login") for o in orgs if isinstance(o, dict) and o.get("login")]
    rung.evidence["org_count"] = len(logins)
    rung.evidence["orgs"] = logins
    rung.success = len(logins) > 0
    rung.detail = (
        f"member of {len(logins)} org(s): {', '.join(logins)}"
        if logins
        else ("no org membership reachable")
    )
    return rung


# --- gated demonstration rung ------------------------------------------------


@gated
async def gated_write_probe(
    consent: Consent, client: httpx.AsyncClient, token: str, login: object
) -> dict[str, object]:
    """GATED: a state-changing probe, unreachable without full consent.

    Decorated with :func:`vtx_recon.safety.gated`, so the safety boundary
    raises :class:`GatedProbeBlocked` *before* this body runs unless BOTH
    ``--prove`` and ``--i-am-authorized`` were supplied. It would star the
    authenticated user's own account-visible repo list state via a ``PUT``
    (a write), which is why it is gated and never part of the safe tier.

    This is the only place in the GitHub provider that would change remote
    state, and it can only be reached through the guard.
    """
    # NOTE: this is the single state-changing call in the provider; it lives
    # behind the @gated guard so it cannot run without consent.
    resp = await client.put(
        "/user/starred/vtx-labs/authorized-probe",
        headers=_headers(token),
    )
    return {"status": resp.status_code, "actor": login, "state_changed": True}


async def _maybe_gated_rung(
    client: httpx.AsyncClient,
    token: str,
    consent: Consent,
    login: object,
) -> ProbeResult:
    """Attempt the gated rung; report it as blocked when consent is absent.

    The actual gating happens inside :func:`gated_write_probe` (the
    decorator). Here we translate the boundary's exception into a non-fatal
    ``blocked`` :class:`ProbeResult` so the ladder never raises and the
    evidence bundle records that the gated rung was refused.
    """
    rung = ProbeResult(name="gated_write_probe", tier=ProbeTier.GATED, success=False)
    try:
        outcome = await gated_write_probe(consent, client, token, login)
    except GatedProbeBlocked as blocked:
        rung.blocked = True
        rung.detail = f"gated rung blocked: {blocked.reason}"
        rung.evidence["reason"] = blocked.reason
        return rung
    except httpx.HTTPError as exc:
        rung.detail = f"gated probe request failed: {type(exc).__name__}"
        rung.evidence["error"] = str(exc)
        return rung

    rung.success = bool(outcome.get("status") in (200, 204))
    rung.detail = (
        "STATE CHANGE EXERCISED under consent (repo starred)"
        if rung.success
        else f"gated probe ran but did not confirm (HTTP {outcome.get('status')})"
    )
    rung.evidence.update({k: v for k, v in outcome.items() if k != "actor"})
    return rung


def register_github() -> None:
    """Register the GitHub ladder for all of its TruffleHog detector names.

    Idempotent: re-registering simply overwrites with the same callable.
    Called as an import side-effect (below) so importing the providers
    package wires GitHub in, but also exposed explicitly for tests that
    clear and rebuild the registry.
    """
    register(*DETECTORS)(github_ladder)


# Import side-effect: wire the provider into the registry on import, matching
# the registry's decorator pattern. Kept as an explicit call too (above) so a
# test that calls clear_registry() can re-register without re-importing.
register_github()
