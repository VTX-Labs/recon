/**
 * Twilio capability ladder — map impact for a leaked Twilio Account SID.
 *
 * Handles TruffleHog `Twilio` findings. The raw secret here is the Account SID
 * (`AC...`), which is only *half* of Twilio's HTTP-basic credential: every
 * authenticated request is `curl -u <AccountSid>:<AuthToken>`, and the paired
 * AuthToken is NOT present in the finding. The engine therefore cannot fire a
 * single authenticated request — there is nothing to verify against.
 *
 * Consequently EVERY rung is a MANUAL safe-curl note. Each prints a ready-to-run
 * curl with the SID inlined and the AuthToken kept as `$TWILIO_AUTH_TOKEN`, for
 * an authorized operator who holds the paired token to run by hand:
 *
 *   1. `twilio.account.fetch`   `GET /Accounts/{Sid}.json` — confirm the SID and
 *      read account status/name. (MANUAL — identity, but still needs the token.)
 *   2. `twilio.phone_numbers`   `GET /Accounts/{Sid}/IncomingPhoneNumbers.json` —
 *      enumerate owned phone numbers (reach / cost surface). MANUAL.
 *   3. `twilio.balance`         `GET /Accounts/{Sid}/Balance.json` — read the
 *      account balance (billing impact surface). GATED + MANUAL.
 *
 * The first two are SAFE-tier manual notes (read-only, but unrunnable without the
 * token). The balance read is GATED (billing/PII surface) and also manual. The
 * ladder never throws across its public boundary and the SID is the only secret
 * material here — it is a public-ish identifier, not the AuthToken.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import type { FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Twilio"] as const;

const API_BASE = "https://api.twilio.com/2010-04-01";

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID (authenticates + depth shown).
 * - The key authenticated nowhere -> DENIED.
 *
 * Twilio rungs are all manual, so none reports `success=true`; a finding with
 * only manual notes lands on DENIED (nothing was actually exercised).
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
 * Run the Twilio capability ladder for one finding.
 *
 * Because the finding carries only the Account SID (not the paired AuthToken),
 * NO authenticated request can be issued: every rung is a manual safe-curl note.
 * Refuses to ladder without an authorized scope. Never throws across this
 * boundary.
 */
export async function twilioLadder(
  finding: Finding,
  consent: Consent,
  _options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const sid = finding.raw;
  const rungs: ProbeResult[] = [];

  // --- Rung 1: account.fetch (SAFE, manual) ----------------------------------
  rungs.push(manualNote("twilio.account.fetch", ProbeTier.SAFE, accountFetchSafeCurl(sid)));

  // --- Rung 2: phone_numbers (SAFE, manual) ----------------------------------
  rungs.push(manualNote("twilio.phone_numbers", ProbeTier.SAFE, phoneNumbersSafeCurl(sid)));

  // --- Rung 3: balance (GATED, manual) ---------------------------------------
  rungs.push(await maybeBalance(consent, sid));

  return new LadderResult({
    finding,
    provider: "twilio",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** A SAFE manual rung: read-only but unrunnable without the paired AuthToken. */
function manualNote(name: string, tier: ProbeTier, safeCurl: string): ProbeResult {
  return new ProbeResult({
    name,
    tier,
    success: false,
    detail:
      "manual rung: needs the paired AuthToken (not in this finding); run the " +
      "safe curl by hand with -u <AccountSid>:<AuthToken>",
    evidence: { manual: true, safe_curl: safeCurl },
  });
}

// --- safe curls (SID inlined, AuthToken kept as a shell variable) ------------

function accountFetchSafeCurl(sid: string): string {
  return `curl -X GET '${API_BASE}/Accounts/${sid}.json' -u '${sid}:$TWILIO_AUTH_TOKEN'`;
}

function phoneNumbersSafeCurl(sid: string): string {
  return (
    "curl -X GET " +
    `'${API_BASE}/Accounts/${sid}/IncomingPhoneNumbers.json' ` +
    `-u '${sid}:$TWILIO_AUTH_TOKEN'`
  );
}

function balanceSafeCurl(sid: string): string {
  return (
    "curl -X GET " +
    `'${API_BASE}/Accounts/${sid}/Balance.json' ` +
    `-u '${sid}:$TWILIO_AUTH_TOKEN'`
  );
}

// --- gated (manual) rung -----------------------------------------------------

/**
 * GATED: reading the account balance is a billing/financial surface.
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body;
 * without consent it throws {@link GatedProbeBlocked}. Even with consent it is
 * MANUAL: there is no AuthToken to authenticate with, so it never fires a live
 * request — it only returns a safe curl.
 */
export const twilioGatedBalance = gated(
  "twilio.balance",
  async (_consent: Consent, sid: string): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "twilio.balance",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: reads account balance (billing surface); needs the paired " +
        "AuthToken; run the safe curl by hand",
      evidence: { manual: true, safe_curl: balanceSafeCurl(sid) },
    });
  },
);

/** Attempt the gated balance rung; report it as blocked when consent is absent. */
async function maybeBalance(consent: Consent, sid: string): Promise<ProbeResult> {
  try {
    return await twilioGatedBalance(consent, sid);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "twilio.balance",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: balanceSafeCurl(sid) },
      });
    }
    throw exc;
  }
}

register([...DETECTORS], (finding, consent) => twilioLadder(finding, consent));
