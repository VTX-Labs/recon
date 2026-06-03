"""Capability ladder for HubSpot private-app / OAuth access tokens.

HubSpot tokens (``pat-na...`` / ``pat-eu...`` private-app tokens, plus OAuth
access tokens) authenticate against ``api.hubapi.com``. TruffleHog surfaces
them under the ``HubSpot`` detector. The ladder climbs:

* **``token-info``** (SAFE) — ``GET /oauth/v1/access-tokens/{token}`` is
  HubSpot's path-based token introspection: it returns ``hub_id``, ``user``,
  ``hub_domain``, ``app_id`` and the granted scopes. This is whoami +
  list-scopes in one call. It works for OAuth access tokens; private-app
  ``pat-`` tokens return 400 here, which is why the next rung exists as a
  fallback. The token is embedded in the URL path, so the request URL itself
  is a secret and is NEVER stored in evidence. Read-only, idempotent,
  non-billable.
* **``account-info``** (SAFE) — ``GET /account-info/v3/details`` is the whoami
  fallback for private-app ``pat-`` tokens (which cannot use the introspection
  endpoint): it returns ``portalId``, account type, time zone, and the
  data-hosting region via a read-only ``Authorization: Bearer`` call.
* **``list-contacts``** (GATED) — ``GET /crm/v3/objects/contacts?limit=1``
  reads CRM contact records (names, emails, phone numbers) — third-party
  customer PII, the data exposure the program cares about. Read-only, but
  GATED because it reads customer PII. It runs only if the operator supplied
  BOTH ``--prove`` and an authorized scope; otherwise it is recorded as a
  ``blocked`` rung.

Every rung is ordered (identity first, then depth), READ-ONLY by default,
and never raises across the public boundary: failures become a
:class:`ProbeResult` with ``success=False`` so one dead key cannot crash a
batch run. The raw token is held only transiently for the HTTP call and never
lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["hubspot_ladder"]

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


@register("HubSpot")
async def hubspot_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """HubSpot ladder: SAFE token introspection
    (``/oauth/v1/access-tokens/{token}``) -> SAFE account whoami fallback
    (``/account-info/v3/details``) -> GATED CRM contact PII read
    (``/crm/v3/objects/contacts``).

    The two SAFE rungs only prove the token authenticates and reveal its hub /
    scopes. The contacts read is GATED because it returns live customer PII; it
    runs only if the operator supplied BOTH ``--prove`` and an authorized scope.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # Two whoami rungs: token-info works for OAuth tokens, account-info is the
    # fallback for private-app `pat-` tokens. Either one authenticating is
    # enough to prove the token is live, so we run both and treat success as
    # "authed".
    token_info = await _hubspot_token_info(key)
    rungs.append(token_info)
    account_info = await _hubspot_account_info(key)
    rungs.append(account_info)

    # Only climb to the gated PII read if the token authenticated somewhere.
    if token_info.success or account_info.success:
        # Ordered: only attempt the gated PII read if the token authenticates.
        # The @gated wrapper enforces consent BEFORE any network call; if
        # consent is missing it raises GatedProbeBlocked, which we capture here
        # as a `blocked` rung so the ladder never raises across the boundary.
        try:
            rungs.append(await _hubspot_list_contacts(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="hubspot.list-contacts",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated PII read blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="hubspot",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _hubspot_token_info(key: str) -> ProbeResult:
    """SAFE: ``GET /oauth/v1/access-tokens/{token}`` introspects the token —
    whoami + list-scopes in one call.

    Returns ``hub_id``, ``user``, ``hub_domain``, ``app_id`` and the granted
    scopes. Works for OAuth access tokens; private-app ``pat-`` tokens return
    400 here (the ``account-info`` rung is the fallback for those). The token
    is embedded in the URL path, so the request URL is itself secret — it is
    NEVER placed into evidence; only the parsed non-secret fields are.
    """
    name = "hubspot.token-info"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"https://api.hubapi.com/oauth/v1/access-tokens/{quote(key, safe='')}",
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=(
                f"token introspection rejected (HTTP {resp.status_code}) "
                "— likely a private-app pat- token; see account-info"
            ),
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # Scopes prove depth of access without exercising any of them.
    scopes = body.get("scopes") if isinstance(body.get("scopes"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {body.get('user') or 'unknown'} on hub "
            f"{body.get('hub_id') or '?'} ({body.get('hub_domain') or '?'}); "
            f"{len(scopes)} scope(s)"
        ),
        evidence={
            "status": resp.status_code,
            "hub_id": body.get("hub_id"),
            "hub_domain": body.get("hub_domain"),
            "user": body.get("user"),
            "user_id": body.get("user_id"),
            "app_id": body.get("app_id"),
            "token_type": body.get("token_type"),
            "scopes": scopes,
        },
    )


async def _hubspot_account_info(key: str) -> ProbeResult:
    """SAFE: ``GET /account-info/v3/details`` is the whoami fallback for
    private-app ``pat-`` tokens (which cannot use the introspection endpoint).

    Returns ``portalId``, account type, time zone, and the data-hosting region
    via a read-only ``Authorization: Bearer`` call.
    """
    name = "hubspot.account-info"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.hubapi.com/account-info/v3/details",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"account-info rejected (HTTP {resp.status_code})",
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
        detail=(
            f"authenticated on portal {body.get('portalId') or '?'} "
            f"({body.get('accountType') or '?'}, region "
            f"{body.get('dataHostingLocation') or '?'})"
        ),
        evidence={
            "status": resp.status_code,
            "portal_id": body.get("portalId"),
            "account_type": body.get("accountType"),
            "time_zone": body.get("timeZone"),
            "data_hosting_location": body.get("dataHostingLocation"),
            "ui_domain": body.get("uiDomain"),
        },
    )


@gated
async def _hubspot_list_contacts(consent: Consent, key: str) -> ProbeResult:
    """GATED: ``GET /crm/v3/objects/contacts?limit=1`` reads CRM contact records
    (names, emails, phone numbers) — third-party customer PII, the data exposure
    the program cares about.

    This is the real impact: read-only, but gated because it reads customer
    PII. Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and no request is ever sent. The public
    ladder catches that and records a ``blocked`` rung.
    """
    name = "hubspot.list-contacts"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.hubapi.com/crm/v3/objects/contacts?limit=1",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"contacts read refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    # PII is summarised, not dumped: prove the read without hoarding customer
    # data. We only note which PII fields are present on a record, never their
    # values.
    contacts = body.get("results") if isinstance(body.get("results"), list) else []
    first = contacts[0] if contacts and isinstance(contacts[0], dict) else {}
    props = first.get("properties") if isinstance(first.get("properties"), dict) else {}
    pii_fields = sorted(k for k in ("firstname", "lastname", "email", "phone") if k in props)

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=(f"read {len(contacts)} CRM contact record(s) — live third-party customer PII"),
        evidence={
            "status": resp.status_code,
            "sample_count": len(contacts),
            "pii_fields_present": pii_fields,
        },
    )
