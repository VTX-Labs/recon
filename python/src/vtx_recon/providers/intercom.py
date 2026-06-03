"""Capability ladder for Intercom access tokens.

Intercom OAuth / personal access tokens authenticate via an
``Authorization: Bearer <token>`` header against ``api.intercom.io``.
TruffleHog surfaces them under the ``Intercom`` detector. Every request is
pinned to a fixed API version (``Intercom-Version: 2.11``) so the parsed
shapes are stable. The ladder climbs:

* **``me``** (SAFE) — ``GET /me`` returns the authorized admin plus the
  embedded workspace / app object. This is whoami: it confirms the token is
  live and reveals *which workspace* the token controls.
* **``list-admins``** (SAFE) — ``GET /admins`` lists every teammate / admin
  in the workspace, enumerating the org the token can reach. This is own-org
  metadata (teammates), not customer PII, so it stays SAFE.
* **``list-contacts``** (GATED) — ``GET /contacts?per_page=5`` reads customer
  contact records (names, emails, phone, location) — third-party PII. This is
  the real impact: read-only, but GATED because it exfiltrates customer data.
  It runs only if the operator supplied BOTH ``--prove`` and an authorized
  scope; otherwise it is recorded as a ``blocked`` rung.

Every rung is ordered (identity first, then depth), READ-ONLY by default,
and never raises across the public boundary: failures become a
:class:`ProbeResult` with ``success=False`` so one dead key cannot crash a
batch run. The raw token is held only transiently for the HTTP call and never
lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["intercom_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)


def _intercom_headers(key: str) -> dict[str, str]:
    """Headers every Intercom rung sends: Bearer auth + pinned API version."""
    return {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "Intercom-Version": "2.11",
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


@register("Intercom")
async def intercom_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Intercom ladder: SAFE identity (``/me``) -> SAFE teammate enumeration
    (``/admins``) -> GATED customer PII read (``/contacts``).

    The two SAFE rungs only prove the token authenticates and size the org.
    The contacts read is GATED because it returns live customer PII; it runs
    only if the operator supplied BOTH ``--prove`` and an authorized scope.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _intercom_me(key)
    rungs.append(identity)
    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _intercom_list_admins(key))

        # Ordered: only attempt the gated PII read if the token authenticates.
        # The @gated wrapper enforces consent BEFORE any network call; if
        # consent is missing it raises GatedProbeBlocked, which we capture here
        # as a `blocked` rung so the ladder never raises across the boundary.
        try:
            rungs.append(await _intercom_list_contacts(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="intercom.list-contacts",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated PII read blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="intercom",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _intercom_me(key: str) -> ProbeResult:
    """SAFE: ``GET /me`` confirms the token and returns the authorized admin
    plus the embedded workspace / app object — whoami and which workspace the
    token controls.
    """
    name = "intercom.me"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.intercom.io/me",
                headers=_intercom_headers(key),
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

    # The workspace/app object is embedded under `app`; summarise it so we prove
    # which workspace the token controls without dumping the whole payload.
    app = body.get("app") or {}
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as {body.get('email') or body.get('name')} "
            f"(admin {body.get('id')}) on workspace "
            f"{app.get('name') or app.get('id_code') or 'unknown'}"
        ),
        evidence={
            "status": resp.status_code,
            "admin_id": body.get("id"),
            "email": body.get("email"),
            "name": body.get("name"),
            "app_id_code": app.get("id_code"),
            "app_name": app.get("name"),
        },
    )


async def _intercom_list_admins(key: str) -> ProbeResult:
    """SAFE: ``GET /admins`` lists every teammate / admin in the workspace.

    Enumerates the org the token can reach (own-org metadata, not customer
    PII) without changing anything.
    """
    name = "intercom.list-admins"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.intercom.io/admins",
                headers=_intercom_headers(key),
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list admins (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    # Admins arrive under `admins`; summarise the teammate emails to size the
    # org without dumping the whole payload.
    admins = body.get("admins") if isinstance(body.get("admins"), list) else []
    emails = [
        email
        for a in admins
        if isinstance(a, dict) and isinstance((email := a.get("email") or a.get("name")), str)
    ]

    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"workspace has {len(admins)} teammate(s): {', '.join(emails) if emails else '(none)'}"
        ),
        evidence={
            "status": resp.status_code,
            "admin_count": len(admins),
            "emails": emails,
        },
    )


@gated
async def _intercom_list_contacts(consent: Consent, key: str) -> ProbeResult:
    """GATED: ``GET /contacts?per_page=5`` reads customer contact records
    (names, emails, phone, location) — third-party PII.

    This is the real impact: read-only, but gated because it exfiltrates
    customer data. Decorated with :func:`vtx_recon.safety.gated`: the safety
    boundary runs *before* this body, so without BOTH ``--prove`` and an
    authorized scope it raises :class:`GatedProbeBlocked` and no request is
    ever sent. The public ladder catches that and records a ``blocked`` rung.
    """
    name = "intercom.list-contacts"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.intercom.io/contacts?per_page=5",
                headers=_intercom_headers(key),
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
    # data. `total_count` sizes the exposure; we only note which PII fields are
    # present on a record, never their values.
    contacts = body.get("data") if isinstance(body.get("data"), list) else []
    first = contacts[0] if contacts and isinstance(contacts[0], dict) else {}
    pii_fields = sorted(k for k in ("name", "email", "phone", "location") if k in first)
    total_count = body.get("total_count")
    if not isinstance(total_count, int):
        total_count = len(contacts)

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail=(
            f"read {len(contacts)} of {total_count} customer contact(s) — live third-party PII"
        ),
        evidence={
            "status": resp.status_code,
            "total_count": total_count,
            "sample_count": len(contacts),
            "pii_fields_present": pii_fields,
        },
    )
