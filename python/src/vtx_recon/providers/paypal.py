"""PayPal capability ladder — render the blast radius of a leaked PayPal app
credential (TruffleHog ``PaypalOauth``).

Unlike most providers, a PayPal credential is NOT a single standalone secret:
it is a ``client_id`` + ``client_secret`` pair, and every live API call needs a
bearer access token first **minted** from that pair via the OAuth2
client-credentials grant. The engine only ever holds one opaque ``finding.raw``
value, so it can fill neither the ``Basic <base64(client_id:client_secret)>``
token-exchange header nor the downstream ``Bearer <access_token>`` header. As a
result EVERY rung here is MANUAL: nothing is fired live; each rung emits a safe
curl (with the secret kept as ``$KEY``) for an authorized operator to run by
hand. See https://developer.paypal.com/api/rest/authentication/ .

The ordered ladder (depth of access, least -> most impactful):

  1. ``oauth2-token``  ``POST /v1/oauth2/token`` — SAFE, manual. Exchanges the
     ``client_id:client_secret`` (HTTP Basic) for an access token via
     ``grant_type=client_credentials``. Success would prove the creds are live
     and the app exists (validity/identity). Read-only/idempotent. Requires
     BOTH halves of the credential, so manual.
  2. ``userinfo``      ``GET /v1/identity/oauth2/userinfo`` — SAFE, manual.
     Returns the OpenID Connect profile (payer_id, account email, verified
     status) — a whoami. Read-only. Needs a bearer token first obtained from
     the manual token rung, so also manual.
  3. ``create-payout`` ``POST /v1/payments/payouts`` — GATED, manual. Sends
     money out of the account via a batch payout: billable and state-changing,
     the action the program cares about. Needs the minted bearer token; never
     auto-run.

The ladder is ordered (identity first, then depth), never raises across the
public boundary (failures become a :class:`ProbeResult` with ``success=False``
so one dead key cannot crash a batch run), and never persists the raw secret:
only the ``$KEY``-placeholder curls land in :attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import json

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["DETECTORS", "paypal_ladder"]

# TruffleHog DetectorName values routed to this ladder (matched case-insensitively).
DETECTORS = ("PaypalOauth",)

TOKEN_URL = "https://api-m.paypal.com/v1/oauth2/token"
USERINFO_URL = "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1"
PAYOUTS_URL = "https://api-m.paypal.com/v1/payments/payouts"

# NOTE: every rung in this ladder is MANUAL — the credential is a
# ``client_id:client_secret`` pair and each live call needs a bearer token the
# engine cannot mint from a single secret. No rung issues an HTTP request, so
# there is intentionally no shared timeout / network-failure helper here (unlike
# the live-call providers); a rung never touches the network and so never fails
# on it.


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.

    For PayPal every rung is manual (``success=False``), so a single-secret
    finding resolves to DENIED — the engine cannot mint the token to prove more.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("PaypalOauth")
async def paypal_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Run the ordered PayPal capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Every rung is manual: the credential is a ``client_id:client_secret`` pair
    and each live call needs a minted bearer token, neither of which the engine
    can fill from a single secret. The SAFE rungs are emitted as manual
    safe-curl notes; the mutating ``create-payout`` rung is GATED and also
    manual. Never raises across the public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # --- Rung 1: oauth2-token (SAFE, manual) — validity/identity -------------
    # Needs `Basic <base64(client_id:client_secret)>`, which the engine cannot
    # construct from a single secret, so it is emitted as a manual safe-curl note.
    rungs.append(_oauth2_token_manual())

    # --- Rung 2: userinfo (SAFE, manual) — whoami ----------------------------
    # Needs a `Bearer <access_token>` minted by rung 1; the engine never holds
    # it, so this too is a manual safe-curl note.
    rungs.append(_userinfo_manual())

    # --- Rung 3: create-payout (GATED, manual safe-curl) — IMPACT ------------
    # Sends money out (billable, state-changing). The @gated wrapper enforces
    # consent first, so without --prove + --i-am-authorized the rung is recorded
    # as blocked; even with consent it is MANUAL (needs the minted bearer token)
    # and never fires a live request.
    rungs.append(await _maybe_create_payout(consent))

    return LadderResult(
        finding=finding,
        provider="paypal",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


# --- manual SAFE rungs -------------------------------------------------------


def _oauth2_token_safe_curl() -> str:
    """The safe curl for the manual token-exchange rung (secret kept as $KEY)."""
    return (
        "curl -X POST "
        f"'{TOKEN_URL}' "
        '-H "Authorization: Basic $KEY" '
        '-H "Content-Type: application/x-www-form-urlencoded" '
        "--data 'grant_type=client_credentials'"
    )


def _oauth2_token_manual() -> ProbeResult:
    """SAFE, manual: ``POST /v1/oauth2/token`` exchanges client_id:client_secret.

    HTTP Basic auth trades the pair for an access token via
    ``grant_type=client_credentials``. ``$KEY`` here stands for
    ``base64(client_id:client_secret)``; the engine holds only one opaque secret
    and cannot build that pair, so no live call is made.
    """
    name = "oauth2-token"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        detail=(
            "manual rung: needs HTTP Basic base64(client_id:client_secret); run "
            "the safe curl by hand to mint an access token and prove the creds "
            "are live"
        ),
        evidence={"manual": True, "safe_curl": _oauth2_token_safe_curl()},
    )


def _userinfo_safe_curl() -> str:
    """The safe curl for the manual userinfo rung (bearer token kept as $KEY)."""
    return f"curl -X GET '{USERINFO_URL}' -H \"Authorization: Bearer $KEY\""


def _userinfo_manual() -> ProbeResult:
    """SAFE, manual: ``GET /v1/identity/oauth2/userinfo`` returns the OIDC profile.

    The profile (payer_id, account email, verified status) is a whoami.
    ``$KEY`` here stands for the bearer access token minted by the
    ``oauth2-token`` rung; the engine never holds it, so no live call is made.
    """
    name = "userinfo"
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        detail=(
            "manual rung: needs a Bearer access token from the oauth2-token rung; "
            "run the safe curl by hand to read the account's OIDC profile (whoami)"
        ),
        evidence={"manual": True, "safe_curl": _userinfo_safe_curl()},
    )


# --- gated (manual) rung -----------------------------------------------------


def _create_payout_safe_curl() -> str:
    """The safe curl for the manual gated payout rung (bearer token kept as $KEY)."""
    payload = json.dumps(
        {
            "sender_batch_header": {
                "sender_batch_id": "probe-batch-1",
                "email_subject": "You have a payout!",
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {"value": "1.00", "currency": "USD"},
                    "receiver": "payee@example.com",
                    "note": "probe",
                }
            ],
        }
    )
    return (
        "curl -X POST "
        f"'{PAYOUTS_URL}' "
        '-H "Authorization: Bearer $KEY" '
        '-H "Content-Type: application/json" '
        f"--data '{payload}'"
    )


@gated
async def paypal_gated_create_payout(consent: Consent) -> ProbeResult:
    """GATED: ``POST /v1/payments/payouts`` would send money out of the account.

    A batch payout is billable, state-changing impact (the action the program
    cares about). Decorated with :func:`vtx_recon.safety.gated`, so the safety
    boundary runs *before* this body and, without BOTH ``--prove`` and an
    authorized scope, raises :class:`GatedProbeBlocked` and nothing executes.
    Even with consent this rung is MANUAL: it needs a bearer access token minted
    from the creds, which the engine cannot fill, so it never fires a live
    request — it only returns a safe curl (secret kept as ``$KEY``) for an
    operator to run by hand. The public ladder records it as a blocked/manual
    note either way.
    """
    name = "create-payout"
    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=(
            "manual rung: needs a Bearer access token minted from the creds; run "
            "the safe curl by hand to exercise the money-out payout impact"
        ),
        evidence={"manual": True, "safe_curl": _create_payout_safe_curl()},
    )


async def _maybe_create_payout(consent: Consent) -> ProbeResult:
    """Attempt the gated payout rung; report it as blocked when consent is absent.

    The gating happens inside :func:`paypal_gated_create_payout`. Here we
    translate the boundary's exception into a non-fatal ``blocked``
    :class:`ProbeResult` so the ladder never raises; the safe curl is still
    surfaced so an authorized operator can run the money-out step by hand.
    """
    try:
        return await paypal_gated_create_payout(consent)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name="create-payout",
            tier=ProbeTier.GATED,
            success=False,
            blocked=True,
            detail=f"gated rung blocked: {blocked.reason}",
            evidence={
                "manual": True,
                "reason": blocked.reason,
                "safe_curl": _create_payout_safe_curl(),
            },
        )
