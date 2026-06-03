"""Postmark Server API capability ladder — prove depth of access for a token.

A TruffleHog ``Postmark`` finding is a Postmark **server token** (a UUID). It
authenticates every call through the ``X-Postmark-Server-Token`` header and is
scoped to a single Postmark server. The ladder climbs from identity to read
depth, then stops at a GATED rung that would actually send mail.

The ordered ladder (depth of access, least -> most revealing):

  1. ``get-server``     ``GET /server`` — SAFE. Identity / whoami: returns the
     server this token controls (name, id, settings). Read-only.
  2. ``delivery-stats`` ``GET /deliverystats`` — SAFE. Reads send / bounce
     statistics, confirming read depth into delivery data. This is the endpoint
     TruffleHog probes to verify the token. Read-only.
  3. ``send-email``     ``POST /email`` — GATED. Sends transactional email from
     the victim's server: billable, with deliverability / reputation impact. It
     needs a To/From/Subject message body the engine must never fabricate
     (sending live mail from someone else's server is exactly the action the
     program cares about), so even under consent it is rendered as a MANUAL
     blocked safe-curl note and never auto-fired.

Every automated rung is a READ-ONLY ``GET``. The ladder never raises across its
public boundary: failures become a :class:`ProbeResult` with ``success=False``
so one dead key cannot crash a batch run. The raw token is held only
transiently for the HTTP call and never lands in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["postmark_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

_API_BASE = "https://api.postmarkapp.com"

# Safe curl for the manual gated send-email rung (token kept as ``$KEY``).
_SEND_EMAIL_SAFE_CURL = (
    "curl -X POST "
    f"'{_API_BASE}/email' "
    '-H "X-Postmark-Server-Token: $KEY" '
    '-H "Accept: application/json" '
    '-H "Content-Type: application/json" '
    '--data \'{"From":"FROM_ADDRESS","To":"TO_ADDRESS","Subject":"SUBJECT","TextBody":"BODY"}\''
)


def _headers(key: str) -> dict[str, str]:
    """Standard Postmark Server API headers carrying the server token."""
    return {
        "X-Postmark-Server-Token": key,
        "Accept": "application/json",
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


@register("Postmark")
async def postmark_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Postmark ladder: SAFE ``/server`` -> SAFE ``/deliverystats`` -> GATED send.

    The two SAFE rungs are read-only (identity, then read depth into delivery
    data). The send-email rung is GATED because it sends billable mail; even
    under consent it stays MANUAL (it needs a message body the engine must never
    fabricate), so it is rendered as a blocked safe-curl rung that never fires.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    # --- Rung 1: identity (SAFE) ---
    identity = await _postmark_get_server(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        # --- Rung 2: read depth into delivery data (SAFE) ---
        rungs.append(await _postmark_delivery_stats(key))

        # --- Rung 3: send-email (GATED, MANUAL safe-curl) ---
        # Sending mail is billable and damages deliverability/reputation. The
        # @gated wrapper enforces consent BEFORE the body runs; without BOTH
        # --prove and --i-am-authorized it raises GatedProbeBlocked, captured
        # here as a `blocked` rung so the ladder never raises across the public
        # boundary. Even WITH consent the body makes no live call: it would need
        # a To/From/Subject message the engine must never fabricate, so it
        # returns a manual safe-curl rung.
        try:
            rungs.append(await _postmark_send_email(consent))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="send-email",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated rung blocked: {blocked.reason}",
                    evidence={
                        "reason": blocked.reason,
                        "manual": True,
                        "safe_curl": _SEND_EMAIL_SAFE_CURL,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="postmark",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _postmark_get_server(key: str) -> ProbeResult:
    """SAFE: ``GET /server`` confirms the token and returns the server it controls.

    Identity / whoami for a Postmark server token: the response names the server,
    its id, and its settings (only non-secret identifiers are kept in evidence).
    """
    name = "get-server"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_API_BASE}/server", headers=_headers(key))
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
        detail=f"controls Postmark server {body.get('Name') or '(unnamed)'} (id {body.get('ID')})",
        evidence={
            "status": resp.status_code,
            "id": body.get("ID"),
            "name": body.get("Name"),
            "color": body.get("Color"),
            "smtp_api_activated": body.get("SmtpApiActivated"),
            "delivery_type": body.get("DeliveryType"),
        },
    )


async def _postmark_delivery_stats(key: str) -> ProbeResult:
    """SAFE: ``GET /deliverystats`` reads send / bounce statistics for the server.

    Confirms read depth into delivery data — the inactive-mail count and the
    per-type bounce breakdown. This is the endpoint TruffleHog probes to verify
    the token. Read-only; only aggregate counts are kept in evidence.
    """
    name = "delivery-stats"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_API_BASE}/deliverystats", headers=_headers(key))
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not read delivery stats (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    bounces = body.get("Bounces") if isinstance(body.get("Bounces"), list) else []
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"read delivery stats: {body.get('InactiveMails', 0)} inactive, "
            f"{len(bounces)} bounce type(s)"
        ),
        evidence={
            "status": resp.status_code,
            "inactive_mails": body.get("InactiveMails"),
            "bounce_type_count": len(bounces),
        },
    )


@gated
async def _postmark_send_email(consent: Consent) -> ProbeResult:
    """GATED (MANUAL): ``POST /email`` sends transactional email from the server.

    Sending mail is billable and damages deliverability / reputation. Decorated
    with :func:`vtx_recon.safety.gated`: the safety boundary runs *before* this
    body, so without BOTH ``--prove`` and an authorized scope it raises
    :class:`GatedProbeBlocked` and nothing executes. Even with full consent the
    rung stays MANUAL: actually sending mail requires a To/From/Subject message
    the engine must never fabricate (live mail from someone else's server is the
    impact, not a probe), so it never fires a live request — it only returns a
    safe curl (token kept as ``$KEY``) for an authorized operator to run by hand.
    """
    return ProbeResult(
        name="send-email",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: sends billable transactional email from the victim's server "
            "(deliverability/reputation impact); needs a From/To/Subject message the engine "
            "will not fabricate. Run the safe curl by hand under consent to exercise the impact"
        ),
        evidence={
            "manual": True,
            "success_status": [200],
            "safe_curl": _SEND_EMAIL_SAFE_CURL,
        },
    )
