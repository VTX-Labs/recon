"""Twilio capability ladder — map impact for a leaked Twilio Account SID.

Handles TruffleHog ``Twilio`` findings. The raw secret here is the Account SID
(``AC...``), which is only *half* of Twilio's HTTP-basic credential: every
authenticated request is ``curl -u <AccountSid>:<AuthToken>``, and the paired
AuthToken is NOT present in the finding. The engine therefore cannot fire a
single authenticated request — there is nothing to verify against.

Consequently EVERY rung is a MANUAL safe-curl note. Each prints a ready-to-run
curl with the SID inlined and the AuthToken kept as ``$TWILIO_AUTH_TOKEN``, for
an authorized operator who holds the paired token to run by hand:

  1. ``twilio.account.fetch``  ``GET /Accounts/{Sid}.json`` — confirm the SID and
     read account status/name. (MANUAL — identity, but still needs the token.)
  2. ``twilio.phone_numbers``  ``GET /Accounts/{Sid}/IncomingPhoneNumbers.json``
     — enumerate owned phone numbers (reach / cost surface). MANUAL.
  3. ``twilio.balance``        ``GET /Accounts/{Sid}/Balance.json`` — read the
     account balance (billing impact surface). GATED + MANUAL.

The first two are SAFE-tier manual notes (read-only, but unrunnable without the
token). The balance read is GATED (billing/PII surface) and also manual. The
ladder never raises across the public boundary and the SID is the only secret
material here — it is a public-ish identifier, not the AuthToken.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "twilio_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("Twilio",)

API_BASE = "https://api.twilio.com/2010-04-01"


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.

    Twilio rungs are all manual, so none reports ``success=True``; a finding
    with only manual notes lands on DENIED (nothing was actually exercised).
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("Twilio")
async def twilio_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the Twilio capability ladder for one finding.

    Because the finding carries only the Account SID (not the paired AuthToken),
    NO authenticated request can be issued: every rung is a manual safe-curl
    note. Refuses to ladder without an authorized scope. Never raises across the
    boundary.
    """
    scope = consent.require_ladder_scope()
    sid = finding.raw
    rungs: list[ProbeResult] = [
        # --- Rung 1: account.fetch (SAFE, manual) ----------------------------
        _manual_note("twilio.account.fetch", ProbeTier.SAFE, _account_fetch_safe_curl(sid)),
        # --- Rung 2: phone_numbers (SAFE, manual) ----------------------------
        _manual_note("twilio.phone_numbers", ProbeTier.SAFE, _phone_numbers_safe_curl(sid)),
        # --- Rung 3: balance (GATED, manual) ---------------------------------
        await _maybe_balance(consent, sid),
    ]

    return LadderResult(
        finding=finding,
        provider="twilio",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


def _manual_note(name: str, tier: ProbeTier, safe_curl: str) -> ProbeResult:
    """A SAFE manual rung: read-only but unrunnable without the paired AuthToken."""
    return ProbeResult(
        name=name,
        tier=tier,
        success=False,
        detail=(
            "manual rung: needs the paired AuthToken (not in this finding); run "
            "the safe curl by hand with -u <AccountSid>:<AuthToken>"
        ),
        evidence={"manual": True, "safe_curl": safe_curl},
    )


# --- safe curls (SID inlined, AuthToken kept as a shell variable) ------------


def _account_fetch_safe_curl(sid: str) -> str:
    return f"curl -X GET '{API_BASE}/Accounts/{sid}.json' -u '{sid}:$TWILIO_AUTH_TOKEN'"


def _phone_numbers_safe_curl(sid: str) -> str:
    return (
        "curl -X GET "
        f"'{API_BASE}/Accounts/{sid}/IncomingPhoneNumbers.json' "
        f"-u '{sid}:$TWILIO_AUTH_TOKEN'"
    )


def _balance_safe_curl(sid: str) -> str:
    return f"curl -X GET '{API_BASE}/Accounts/{sid}/Balance.json' -u '{sid}:$TWILIO_AUTH_TOKEN'"


# --- gated (manual) rung -----------------------------------------------------


@gated
async def twilio_gated_balance(consent: Consent, sid: str) -> ProbeResult:
    """GATED: reading the account balance is a billing/financial surface.

    Decorated with :func:`vtx_recon.safety.gated`, so the safety boundary runs
    *before* this body; without consent it raises :class:`GatedProbeBlocked`.
    Even with consent it is MANUAL: there is no AuthToken to authenticate with,
    so it never fires a live request — it only returns a safe curl.
    """
    return ProbeResult(
        name="twilio.balance",
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: reads account balance (billing surface); needs the "
            "paired AuthToken; run the safe curl by hand"
        ),
        evidence={"manual": True, "safe_curl": _balance_safe_curl(sid)},
    )


async def _maybe_balance(consent: Consent, sid: str) -> ProbeResult:
    """Attempt the gated balance rung; report it as blocked when consent absent."""
    try:
        return await twilio_gated_balance(consent, sid)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="twilio.balance",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _balance_safe_curl(sid),
            },
        )
