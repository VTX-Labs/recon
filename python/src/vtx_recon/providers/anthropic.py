"""Anthropic capability ladder — prove depth of access for a leaked API key.

A TruffleHog ``Anthropic`` finding is a secret API key (``sk-ant-...``). The
ladder mirrors OpenAI's shape — one safe read-only identity rung, one billable
gated rung:

  1. ``list-models``    SAFE. ``GET /v1/models`` — the key authenticates and can
     list the models available to it (read-only, idempotent, non-billable).
     Decides VALID vs DENIED.
  2. ``create-message`` GATED. ``POST /v1/messages`` — a real message costs the
     target money. Wrapped with ``@gated``: the safety boundary runs *before*
     any network call, so without BOTH ``--prove`` and an authorized scope it
     raises ``GatedProbeBlocked`` and nothing is sent.

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

__all__ = ["DETECTORS", "anthropic_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Anthropic",)

_API_BASE = "https://api.anthropic.com"
_API_VERSION = "2023-06-01"
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


@register("Anthropic")
async def anthropic_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Anthropic ladder: SAFE ``list-models`` -> GATED ``create-message``."""
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    models = await _anthropic_list_models(key)
    rungs.append(models)

    if models.success:
        try:
            rungs.append(await _anthropic_create_message(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="anthropic.create_message",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated billable message blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="anthropic",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _anthropic_list_models(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/models`` confirms the key and lists reachable models."""
    name = "anthropic.list_models"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/v1/models",
                headers={"x-api-key": key, "anthropic-version": _API_VERSION},
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

    data = body.get("data") if isinstance(body, dict) else None
    models = data if isinstance(data, list) else []
    ids = [m.get("id") for m in models if isinstance(m, dict) and isinstance(m.get("id"), str)]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=f"key authenticates; {len(ids)} models reachable",
        evidence={
            "status": resp.status_code,
            "key_prefix": redact(key),
            "model_count": len(ids),
            "sample_models": ids[:5],
        },
    )


@gated("anthropic.create_message")
async def _anthropic_create_message(_consent: Consent, key: str) -> ProbeResult:
    """GATED: ``POST /v1/messages`` — a billable message.

    Decorated with ``@gated``: the boundary runs before this body, so without
    BOTH ``--prove`` and an authorized scope it raises ``GatedProbeBlocked`` and
    no billable request is ever sent. A minimal ``max_tokens`` keeps any
    (consented) spend to the smallest possible amount.
    """
    name = "anthropic.create_message"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_API_BASE}/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": _API_VERSION,
                    "Content-Type": "application/json",
                },
                json={
                    "model": "claude-3-5-haiku-latest",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "1"}],
                },
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.GATED, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"billable message refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail="billable message creation succeeded (spent the target's credits)",
        evidence={"status": resp.status_code, "billable": True},
    )
