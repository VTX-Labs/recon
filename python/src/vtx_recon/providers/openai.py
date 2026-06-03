"""OpenAI capability ladder — prove depth of access for a leaked API key.

A TruffleHog ``OpenAI`` finding is a secret API key (``sk-...`` or the project
form ``sk-proj-...``). The ladder is deliberately short because OpenAI exposes
exactly one safe, read-only identity surface and one obviously billable action:

  1. ``list-models``     SAFE. ``GET /v1/models`` — the key authenticates and can
     list the models available to it (read-only, idempotent, non-billable). This
     is the rung that decides VALID vs DENIED.
  2. ``chat-completion`` GATED. ``POST /v1/chat/completions`` — a real completion
     costs the target money. Wrapped with ``@gated``: the safety boundary runs
     *before* any network call, so without BOTH ``--prove`` and an authorized
     scope it raises ``GatedProbeBlocked`` and nothing is sent.

The ladder never raises across its public boundary — every failure becomes a
:class:`ProbeResult`. The raw key is held only transiently for the HTTP call and
is never written into evidence.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..redact import redact
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "openai_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("OpenAI",)

_API_BASE = "https://api.openai.com"
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


@register("OpenAI")
async def openai_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """OpenAI ladder: SAFE ``list-models`` -> GATED ``chat-completion``."""
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    models = await _openai_list_models(key)
    rungs.append(models)

    # Ordered: only attempt the gated billable rung if the key authenticated.
    if models.success:
        try:
            rungs.append(await _openai_chat_completion(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="openai.chat_completion",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated billable completion blocked: {blocked.reason}",
                    evidence={"reason": blocked.reason},
                )
            )

    return LadderResult(
        finding=finding,
        provider="openai",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _openai_list_models(key: str) -> ProbeResult:
    """SAFE: ``GET /v1/models`` confirms the key and lists reachable models."""
    name = "openai.list_models"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_BASE}/v1/models",
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


@gated("openai.chat_completion")
async def _openai_chat_completion(_consent: Consent, key: str) -> ProbeResult:
    """GATED: ``POST /v1/chat/completions`` — a billable completion.

    Decorated with ``@gated``: the boundary runs before this body, so without
    BOTH ``--prove`` and an authorized scope it raises ``GatedProbeBlocked`` and
    no billable request is ever sent. A minimal ``max_tokens`` keeps any
    (consented) spend to the smallest possible amount.
    """
    name = "openai.chat_completion"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_API_BASE}/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": "gpt-4o-mini",
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
            detail=f"billable completion refused (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=True,
        detail="billable chat completion succeeded (spent the target's credits)",
        evidence={"status": resp.status_code, "billable": True},
    )
