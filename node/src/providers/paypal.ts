/**
 * PayPal capability ladder — render the blast radius of a leaked PayPal app
 * credential (TruffleHog `PaypalOauth`).
 *
 * Unlike most providers, a PayPal credential is NOT a single standalone secret:
 * it is a `client_id` + `client_secret` pair, and every live API call needs a
 * bearer access token first **minted** from that pair via the OAuth2
 * client-credentials grant. The engine only ever holds one opaque `finding.raw`
 * value, so it can fill neither the `Basic <base64(client_id:client_secret)>`
 * token-exchange header nor the downstream `Bearer <access_token>` header. As a
 * result EVERY rung here is MANUAL: nothing is fired live; each rung emits a
 * safe curl (with the secret kept as `$KEY`) for an authorized operator to run
 * by hand. See https://developer.paypal.com/api/rest/authentication/ .
 *
 * Ordered ladder (depth of access, least -> most impactful):
 *
 *   1. `oauth2-token`  `POST /v1/oauth2/token` — SAFE, manual. Exchanges the
 *      `client_id:client_secret` (HTTP Basic) for an access token via
 *      `grant_type=client_credentials`. Success would prove the creds are live
 *      and the app exists (validity/identity). Read-only/idempotent. Requires
 *      BOTH halves of the credential, so manual.
 *   2. `userinfo`      `GET /v1/identity/oauth2/userinfo` — SAFE, manual.
 *      Returns the OpenID Connect profile (payer_id, account email, verified
 *      status) — a whoami. Read-only. Needs a bearer token first obtained from
 *      the manual token rung, so also manual.
 *   3. `create-payout` `POST /v1/payments/payouts` — GATED, manual. Sends money
 *      out of the account via a batch payout: billable and state-changing, the
 *      action the program cares about. Needs the minted bearer token; never
 *      auto-run.
 *
 * The ladder is ordered (identity first, then depth), never throws across its
 * public boundary (failures become a {@link ProbeResult} with `success=false`),
 * and never persists the raw secret: only the `$KEY`-placeholder curls land in
 * evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["PaypalOauth"] as const;

const TOKEN_URL = "https://api-m.paypal.com/v1/oauth2/token";
const USERINFO_URL =
  "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1";
const PAYOUTS_URL = "https://api-m.paypal.com/v1/payments/payouts";

// NOTE: every rung in this ladder is MANUAL — the credential is a
// `client_id:client_secret` pair and each live call needs a bearer token the
// engine cannot mint from a single secret. No rung issues an HTTP request, so
// there is intentionally no shared timeout / network-failure helper here (unlike
// the live-call providers); a rung never touches the network and so never fails
// on it.

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID (authenticates + depth shown).
 * - The key authenticated nowhere -> DENIED.
 *
 * For PayPal every rung is manual (success=false), so a single-secret finding
 * resolves to DENIED — the engine cannot mint the token to prove more.
 */
function verdictFrom(rungs: ProbeResult[]): Verdict {
  if (rungs.some((r) => r.success && r.tier === ProbeTier.GATED && !r.blocked)) {
    return Verdict.PROVEN;
  }
  if (rungs.some((r) => r.success)) {
    return Verdict.VALID;
  }
  return Verdict.DENIED;
}

/**
 * Run the ordered PayPal capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle). Every
 * rung is manual: the credential is a `client_id:client_secret` pair and each
 * live call needs a minted bearer token, neither of which the engine can fill
 * from a single secret. The SAFE rungs are emitted as manual safe-curl notes;
 * the mutating `create-payout` rung is GATED and also manual. Never throws
 * across this boundary.
 */
export async function paypalLadder(
  finding: Finding,
  consent: Consent,
  _options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // --- Rung 1: oauth2-token (SAFE, manual) — validity/identity ----------------
  // Needs `Basic <base64(client_id:client_secret)>`, which the engine cannot
  // construct from a single secret, so it is emitted as a manual safe-curl note.
  rungs.push(oauth2TokenManual());

  // --- Rung 2: userinfo (SAFE, manual) — whoami -------------------------------
  // Needs a `Bearer <access_token>` minted by rung 1; the engine never holds
  // it, so this too is a manual safe-curl note.
  rungs.push(userinfoManual());

  // --- Rung 3: create-payout (GATED, manual safe-curl) — IMPACT ---------------
  // Sends money out (billable, state-changing). The gated() wrapper enforces
  // consent first, so without --prove + --i-am-authorized the rung is recorded
  // as blocked; even with consent it is MANUAL (needs the minted bearer token)
  // and never fires a live request.
  rungs.push(await maybeCreatePayout(consent));

  return new LadderResult({
    finding,
    provider: "paypal",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- manual SAFE rungs -------------------------------------------------------

/** The safe curl for the manual token-exchange rung (secret kept as $KEY). */
function oauth2TokenSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${TOKEN_URL}' ` +
    '-H "Authorization: Basic $KEY" ' +
    '-H "Content-Type: application/x-www-form-urlencoded" ' +
    "--data 'grant_type=client_credentials'"
  );
}

/**
 * SAFE, manual: `POST /v1/oauth2/token` exchanges `client_id:client_secret`
 * (HTTP Basic) for an access token via `grant_type=client_credentials`.
 *
 * `$KEY` here stands for `base64(client_id:client_secret)`; the engine holds
 * only one opaque secret and cannot build that pair, so no live call is made.
 */
function oauth2TokenManual(): ProbeResult {
  const name = "oauth2-token";
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    detail:
      "manual rung: needs HTTP Basic base64(client_id:client_secret); run the " +
      "safe curl by hand to mint an access token and prove the creds are live",
    evidence: { manual: true, safe_curl: oauth2TokenSafeCurl() },
  });
}

/** The safe curl for the manual userinfo rung (bearer token kept as $KEY). */
function userinfoSafeCurl(): string {
  return (
    "curl -X GET " +
    `'${USERINFO_URL}' ` +
    '-H "Authorization: Bearer $KEY"'
  );
}

/**
 * SAFE, manual: `GET /v1/identity/oauth2/userinfo` returns the OpenID Connect
 * profile (payer_id, account email, verified status) — a whoami.
 *
 * `$KEY` here stands for the bearer access token minted by the `oauth2-token`
 * rung; the engine never holds it, so no live call is made.
 */
function userinfoManual(): ProbeResult {
  const name = "userinfo";
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    detail:
      "manual rung: needs a Bearer access token from the oauth2-token rung; " +
      "run the safe curl by hand to read the account's OIDC profile (whoami)",
    evidence: { manual: true, safe_curl: userinfoSafeCurl() },
  });
}

// --- gated (manual) rung -----------------------------------------------------

/** The safe curl for the manual gated payout rung (bearer token kept as $KEY). */
function createPayoutSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${PAYOUTS_URL}' ` +
    '-H "Authorization: Bearer $KEY" ' +
    '-H "Content-Type: application/json" ' +
    "--data '" +
    JSON.stringify({
      sender_batch_header: {
        sender_batch_id: "probe-batch-1",
        email_subject: "You have a payout!",
      },
      items: [
        {
          recipient_type: "EMAIL",
          amount: { value: "1.00", currency: "USD" },
          receiver: "payee@example.com",
          note: "probe",
        },
      ],
    }) +
    "'"
  );
}

/**
 * GATED: `POST /v1/payments/payouts` would send money out of the account via a
 * batch payout — billable, state-changing impact (the action the program cares
 * about).
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with consent this rung is MANUAL: it needs a bearer
 * access token minted from the creds, which the engine cannot fill, so it never
 * fires a live request — it only returns a safe curl (secret kept as `$KEY`) for
 * an operator to run by hand. The public ladder records it as a blocked/manual
 * note either way.
 */
export const paypalGatedCreatePayout = gated(
  "paypal.create-payout",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "create-payout";
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: needs a Bearer access token minted from the creds; run " +
        "the safe curl by hand to exercise the money-out payout impact",
      evidence: { manual: true, safe_curl: createPayoutSafeCurl() },
    });
  },
);

/**
 * Attempt the gated payout rung; report it as blocked when consent is absent.
 *
 * The gating happens inside {@link paypalGatedCreatePayout}. Here we translate
 * the boundary's exception into a non-fatal `blocked` ProbeResult so the ladder
 * never throws; the safe curl is still surfaced so an authorized operator can
 * run the money-out step by hand.
 */
async function maybeCreatePayout(consent: Consent): Promise<ProbeResult> {
  try {
    return await paypalGatedCreatePayout(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "create-payout",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: createPayoutSafeCurl() },
      });
    }
    throw exc;
  }
}

register([...DETECTORS], (finding, consent) => paypalLadder(finding, consent));
