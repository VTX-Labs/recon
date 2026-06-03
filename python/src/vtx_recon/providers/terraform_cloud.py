"""Capability ladder for HCP Terraform / Terraform Cloud personal tokens.

A TruffleHog ``TerraformCloudPersonalToken`` finding has the shape
``<14>.atlasv1.<67>`` (trigger keyword ``.atlasv1.``). The token authenticates
via ``Authorization: Bearer <token>`` against the JSON:API at
``https://app.terraform.io/api/v2`` (media type ``application/vnd.api+json``).

A leaked HCP Terraform token is catastrophic: it drives the *state* of real
cloud infrastructure. The ladder proves that blast radius, least -> most:

SAFE rungs (run by default, read-only, non-billable, idempotent):

* ``account-details``     ``GET /account/details`` — identity / whoami.
  Confirms the token is live and names the principal (username, email, 2FA
  status). This is TruffleHog's own verification endpoint; it decides VALID vs
  DENIED.
* ``list-organizations``  ``GET /organizations`` — enumerates the HCP Terraform
  organizations the token can reach: the set of infra-managing orgs in blast
  radius. Read-only.

GATED rung (UNREACHABLE without BOTH ``--prove`` and ``--i-am-authorized``):

* ``create-run``          ``POST /runs`` — queues a Terraform run (a plan, and
  with apply a mutation of real cloud infrastructure). State-changing and
  effectively billable (it provisions / destroys cloud resources) — the
  catastrophic impact of the leaked token. The JSON:API body must reference a
  workspace id (from a workspace the operator chooses) that the engine cannot
  fill, so this rung is rendered as a MANUAL, gated safe-curl note: it never
  auto-fires. The note is emitted only behind the safety boundary (consent
  fully granted); without consent it is recorded as ``blocked``.

The public entry point is :func:`terraform_cloud_ladder`; it never raises across
its boundary — every failure becomes a :class:`ProbeResult` with
``success=False`` so one dead key cannot crash a batch run. Secrets are held
only transiently for the HTTP call and never land in evidence; the manual curl
keeps the secret as ``$KEY``.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["terraform_cloud_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

_API_BASE = "https://app.terraform.io/api/v2"

# A copy/paste-safe curl the operator runs by hand once they have chosen a
# target WORKSPACE_ID (from ``GET /organizations/<org>/workspaces``). The secret
# stays a shell variable (``$KEY``); the engine never substitutes it and no
# state-changing request is fired automatically.
_SAFE_CURL_CREATE_RUN = (
    "curl -sS -X POST "
    '-H "Authorization: Bearer $KEY" '
    '-H "Content-Type: application/vnd.api+json" '
    '-d \'{"data":{"type":"runs","relationships":{"workspace":'
    '{"data":{"type":"workspaces","id":"WORKSPACE_ID"}}}}}\' '
    '"https://app.terraform.io/api/v2/runs"'
)


def _headers(key: str) -> dict[str, str]:
    """Standard HCP Terraform JSON:API headers carrying the bearer token."""
    return {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/vnd.api+json",
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
    * The token authenticated nowhere -> DENIED.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("TerraformCloudPersonalToken")
async def terraform_cloud_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered HCP Terraform capability ladder for a single finding.

    Identity first (account whoami); org enumeration only if the token
    authenticated. The gated ``create-run`` is a manual safe-curl note: its
    JSON:API body needs a workspace id the engine cannot fill (and the action is
    state-changing / billable), so it never fires a live request. Even the note
    is gated — without full consent it is recorded as ``blocked``.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: identity / whoami (SAFE) ---
    identity = await _terraform_cloud_account_details(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: enumerate reachable organizations (SAFE) ---
        rungs.append(await _terraform_cloud_list_organizations(key))

        # --- Rung 3: queue a Terraform run (GATED, MANUAL) ---
        # The JSON:API body must reference a workspace id the engine cannot
        # fill, and the action mutates real infra (state-changing / billable),
        # so this never makes a live call. The @gated wrapper still enforces
        # consent BEFORE the body runs: without --prove + scope it raises
        # GatedProbeBlocked, captured here as a `blocked` rung so the ladder
        # never raises across the boundary.
        try:
            rungs.append(await _terraform_cloud_create_run(consent))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="create-run",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "manual": True,
                        "safe_curl": _SAFE_CURL_CREATE_RUN,
                        "reason": blocked.reason,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="terraform-cloud",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _terraform_cloud_account_details(key: str) -> ProbeResult:
    """SAFE: ``GET /account/details`` confirms identity (TruffleHog verify)."""
    name = "account-details"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/account/details",
                headers=_headers(key),
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

    # JSON:API: { data: { id, type: "users", attributes: { username, email } } }
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
    two_factor = attrs.get("two-factor") if isinstance(attrs.get("two-factor"), dict) else {}

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {attrs.get('username') or attrs.get('email') or 'unknown'} "
            f"(id {data.get('id') or '?'})"
        ),
        evidence={
            "status": resp.status_code,
            "id": data.get("id"),
            "username": attrs.get("username"),
            "email": attrs.get("email"),
            "two_factor": two_factor.get("enabled"),
            "is_service_account": attrs.get("is-service-account"),
        },
    )


async def _terraform_cloud_list_organizations(key: str) -> ProbeResult:
    """SAFE: ``GET /organizations`` enumerates reachable orgs (blast radius)."""
    name = "list-organizations"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/organizations",
                headers=_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list organizations (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # JSON:API: { data: [ { id: "<org-name>", type: "organizations" }, ... ] }
    raw_data = body.get("data")
    data = raw_data if isinstance(raw_data, list) else []
    # The JSON:API `id` of an organization IS its name (a non-secret slug).
    orgs = [o["id"] for o in data if isinstance(o, dict) and o.get("id")]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=bool(orgs),
        detail=(
            f"{len(orgs)} organization(s) reachable: {', '.join(orgs[:10])}"
            if orgs
            else "no organizations reachable"
        ),
        evidence={
            "status": resp.status_code,
            "organization_count": len(orgs),
            "organizations_sample": orgs[:25],
        },
    )


@gated
async def _terraform_cloud_create_run(consent: Consent) -> ProbeResult:
    """GATED + MANUAL: ``POST /runs`` queues a Terraform run on a workspace.

    A run executes a plan (and, with apply, mutates real cloud infrastructure):
    state-changing and effectively billable (it provisions / destroys cloud
    resources). The JSON:API request body must reference a ``WORKSPACE_ID`` the
    engine cannot fill, so this rung NEVER makes a live call — it emits a manual
    safe-curl note instead. It is still decorated with
    :func:`vtx_recon.safety.gated`: the boundary runs BEFORE this body, so
    without BOTH ``--prove`` and an authorized scope it raises
    :class:`GatedProbeBlocked` and even the note is withheld (the public ladder
    records a ``blocked`` rung).
    """
    return ProbeResult(
        name="create-run",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "MANUAL gated rung: needs a WORKSPACE_ID and would queue a Terraform "
            "run (state-changing / billable infra mutation), so no live call is "
            "made. Run the safe curl by hand under consent to queue a run on a "
            "chosen workspace."
        ),
        evidence={"manual": True, "safe_curl": _SAFE_CURL_CREATE_RUN},
    )
