/**
 * Postmark Server API capability ladder — prove depth of access for a token.
 *
 * A TruffleHog `Postmark` finding is a Postmark **server token** (a UUID). It
 * authenticates every call through the `X-Postmark-Server-Token` header and is
 * scoped to a single Postmark server. The ladder climbs from identity to read
 * depth, then stops at a GATED rung that would actually send mail.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `get-server`     `GET /server` — SAFE. Identity / whoami: returns the
 *      server this token controls (name, id, settings). Read-only.
 *   2. `delivery-stats` `GET /deliverystats` — SAFE. Reads send / bounce
 *      statistics, confirming read depth into delivery data. This is the
 *      endpoint TruffleHog probes to verify the token. Read-only.
 *   3. `send-email`     `POST /email` — GATED. Sends transactional email from
 *      the victim's server: billable, with deliverability / reputation impact.
 *      It needs a To/From/Subject message body the engine must never fabricate
 *      (sending live mail from someone else's server is exactly the action the
 *      program cares about), so even under consent it is rendered as a MANUAL
 *      blocked safe-curl note and never auto-fired.
 *
 * Every automated rung is a READ-ONLY `GET`. The ladder never throws across its
 * public boundary: failures become a {@link ProbeResult} with `success=false`.
 * The raw token is held only transiently for the HTTP call and never lands in
 * evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

const API_BASE = "https://api.postmarkapp.com";

/** Standard Postmark Server API headers carrying the server token. */
function postmarkHeaders(key: string): Record<string, string> {
  return {
    "X-Postmark-Server-Token": key,
    Accept: "application/json",
  };
}

function networkFailure(name: string, tier: ProbeTier, exc: unknown): ProbeResult {
  return new ProbeResult({
    name,
    tier,
    success: false,
    detail: `probe could not complete: ${errName(exc)}`,
    evidence: { error: errName(exc) },
  });
}

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
}

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID (authenticates + depth shown).
 * - The key authenticated nowhere -> DENIED.
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
 * Postmark ladder: SAFE identity (/server) -> SAFE read depth (/deliverystats)
 * -> MANUAL/GATED send-email (billable; needs a message body the engine must
 * never fabricate).
 */
export async function postmarkLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: identity (SAFE) ---
  const identity = await postmarkGetServer(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: read depth into delivery data (SAFE) ---
    rungs.push(await postmarkDeliveryStats(key, fetchImpl));

    // --- Rung 3: send-email (GATED, MANUAL safe-curl) ---
    // Sending mail is billable and damages deliverability/reputation. The
    // gated() wrapper enforces consent BEFORE the body runs; without BOTH
    // --prove and --i-am-authorized it throws GatedProbeBlocked, captured here
    // as a `blocked` rung so the ladder never throws across the public
    // boundary. Even WITH consent the rung stays MANUAL: it would need a
    // To/From/Subject message the engine must never fabricate, so it returns a
    // safe curl for an operator to run by hand rather than firing live mail.
    try {
      rungs.push(await postmarkSendEmailGated(consent));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "send-email",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: {
              reason: exc.reason,
              manual: true,
              safe_curl: sendEmailSafeCurl(),
            },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "postmark",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /server` confirms the token and returns the server it controls.
 *
 * Identity / whoami for a Postmark server token: the response names the server,
 * its id, and its settings (only non-secret identifiers are kept in evidence).
 */
async function postmarkGetServer(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "get-server";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/server`, {
      headers: postmarkHeaders(key),
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (resp.status !== 200) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `token rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `controls Postmark server ${body["Name"] ?? "(unnamed)"} (id ${body["ID"]})`,
    evidence: {
      status: resp.status,
      id: body["ID"] ?? null,
      name: body["Name"] ?? null,
      color: body["Color"] ?? null,
      smtp_api_activated: body["SmtpApiActivated"] ?? null,
      delivery_type: body["DeliveryType"] ?? null,
    },
  });
}

/**
 * SAFE: `GET /deliverystats` reads send / bounce statistics for the server.
 *
 * Confirms read depth into delivery data — the bounce inactives count and the
 * per-type bounce breakdown. This is the endpoint TruffleHog probes to verify
 * the token. Read-only; only aggregate counts are kept in evidence.
 */
async function postmarkDeliveryStats(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "delivery-stats";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/deliverystats`, {
      headers: postmarkHeaders(key),
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (resp.status !== 200) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `could not read delivery stats (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const bounces = Array.isArray(body["Bounces"]) ? (body["Bounces"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `read delivery stats: ${body["InactiveMails"] ?? 0} inactive, ${bounces.length} bounce type(s)`,
    evidence: {
      status: resp.status,
      inactive_mails: body["InactiveMails"] ?? null,
      bounce_type_count: bounces.length,
    },
  });
}

/**
 * GATED (MANUAL): `POST /email` sends transactional email from the victim's
 * server — billable, with deliverability / reputation impact.
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with full consent the rung stays MANUAL: actually
 * sending mail requires a To/From/Subject message the engine must never
 * fabricate (live mail from someone else's server is the impact, not a probe),
 * so it never fires a live request — it only returns a safe curl (token kept as
 * `$KEY`) for an authorized operator to run by hand.
 */
export const postmarkSendEmailGated = gated(
  "postmark.send-email",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "send-email",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: sends billable transactional email from the victim's server " +
        "(deliverability/reputation impact); needs a From/To/Subject message the engine " +
        "will not fabricate. Run the safe curl by hand under consent to exercise the impact",
      evidence: {
        manual: true,
        success_status: [200],
        safe_curl: sendEmailSafeCurl(),
      },
    });
  },
);

/** Safe curl for the manual gated send-email rung (token kept as $KEY). */
function sendEmailSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${API_BASE}/email' ` +
    '-H "X-Postmark-Server-Token: $KEY" ' +
    '-H "Accept: application/json" ' +
    '-H "Content-Type: application/json" ' +
    `--data '{"From":"FROM_ADDRESS","To":"TO_ADDRESS","Subject":"SUBJECT","TextBody":"BODY"}'`
  );
}

register(["Postmark"], (finding, consent) => postmarkLadder(finding, consent));
