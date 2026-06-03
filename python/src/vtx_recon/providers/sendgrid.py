"""SendGrid capability ladder — prove depth of access for a leaked API key.

A TruffleHog ``SendGrid`` finding is an API key (``SG.<id>.<secret>``). The
ladder proves what the key can reach, then gates the obvious abuse:

  1. ``scopes``    SAFE. ``GET /v3/scopes`` — the key authenticates and returns
     the exact scopes granted to it (read-only). This proves both validity and
     depth-of-access (e.g. ``mail.send``). Decides VALID vs DENIED.
  2. ``send-mail`` GATED. ``POST /v3/mail/send`` — actually sending email is
     state-changing and reputation-/billing-impacting. Wrapped with ``@gated``:
     the boundary runs *before* any network call, so without BOTH ``--prove``
     and an authorized scope it raises ``GatedProbeBlocked`` and nothing is sent.

The ladder never raises across its public boundary — every failure becomes a
:class:`ProbeResult`. The raw key is held only transiently and never written
into evidence.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..redact import redact
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "sendgrid_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("SendGrid", "Sendgrid")

_API_BASE = "https://api.sendgrid.com"
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
    """Derive the impact tier from the rungs that ran."""
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("SendGrid", "Sendgrid")
async def sendgrid_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """SendGrid ladder: SAFE ``scopes`` -> GATED ``send-mail``."""
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    scopes = await _sendgrid_scopes(key)
    rungs.append(scopes)

    if scopes.success:
        try:
            rungs.append(await _sendgrid_send_mail(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="sendgrid.send_mail",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated mail send blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="sendgrid",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _sendgrid_scopes(key: str) -> ProbeResult:
    """SAFE: ``GET /v3/scopes`` confirms the key and reveals granted scopes."""
    name = "sendgrid.scopes"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/v3/scopes",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"key rejected (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    raw_scopes = body.get("scopes") if isinstance(body, dict) else None
    scopes = raw_scopes if isinstance(raw_scopes, list) else []
    can_send = "mail.send" in scopes
    detail = f"key authenticates; {len(scopes)} scopes granted"
    if can_send:
        detail += " (including mail.send)"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=detail,
        evidence={
            "status": resp.status_code,
            "key_prefix": redact(key),
            "scope_count": len(scopes),
            "can_send_mail": can_send,
            "sample_scopes": scopes[:10],
        },
    )


@gated("sendgrid.send_mail")
async def _sendgrid_send_mail(_consent: Consent, key: str) -> ProbeResult:
    """GATED: ``POST /v3/mail/send`` — actually sends an email.

    Decorated with ``@gated``: the boundary runs before this body, so without
    BOTH ``--prove`` and an authorized scope it raises ``GatedProbeBlocked`` and
    no mail is ever sent.
    """
    name = "sendgrid.send_mail"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_API_BASE}/v3/mail/send",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "personalizations": [{"to": [{"email": "recon@example.com"}]}],
                    "from": {"email": "recon@example.com"},
                    "subject": "vtx-recon authorized capability probe",
                    "content": [{"type": "text/plain", "value": "probe"}],
                },
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    # SendGrid returns 202 Accepted for a queued send.
    if resp.status_code != 202:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"mail send refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail="mail send accepted (state-changing: an email was queued)",
        evidence={"status": resp.status_code, "state_changed": True},
    )
