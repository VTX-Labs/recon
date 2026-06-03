/**
 * npm capability ladder — prove depth of access for a leaked npm token.
 *
 * Handles TruffleHog `NpmToken` (and `NPM`/`npm`) findings. An npm access
 * token authenticates against the registry with `Authorization: Bearer <token>`.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `npm.whoami`        `GET /-/whoami` — confirms the token and reveals the
 *      npm username it belongs to. Decides VALID vs DENIED. Read-only.
 *   2. `npm.tokens`        `GET /-/npm/v1/tokens` — reveals the token's type
 *      (automation / publish / read-only) and whether it is 2FA-bypassing.
 *      Read-only enumeration of the account's tokens (we keep only counts and
 *      the current token's type, never raw token values).
 *   3. `npm.publish`       `PUT /{package}` — GATED, state-changing (publishes a
 *      package version). Its URL needs a `{package}` the engine cannot fill, so
 *      this rung is a MANUAL safe-curl note: never auto-fired, prints a curl
 *      that keeps the secret as `$KEY`.
 *
 * Every live rung is READ-ONLY, the ladder never throws across its public
 * boundary, and the raw token never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["NpmToken", "NPM", "npm", "npmToken"] as const;

const REGISTRY_BASE = "https://registry.npmjs.org";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

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

/** Standard npm registry bearer header for an access token. */
function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/**
 * Run the ordered npm capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Climbs `whoami` first and only
 * descends into the token-type rung if the token authenticated. The publish
 * rung is GATED and, because its URL needs a `{package}` the engine cannot fill,
 * is emitted as a manual safe-curl note rather than a live call. Never throws
 * across this boundary.
 */
export async function npmLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const token = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: whoami (SAFE) — decides live/dead -----------------------------
  const identity = await npmWhoami(token, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: tokens (SAFE) ----------------------------------------------
    rungs.push(await npmTokens(token, fetchImpl));

    // --- Rung 3: publish (GATED, manual safe-curl) --------------------------
    rungs.push(await maybePublish(consent));
  }

  return new LadderResult({
    finding,
    provider: "npm",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/** SAFE: `GET /-/whoami` confirms the token and returns the npm username. */
async function npmWhoami(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "npm.whoami";
  let resp: Response;
  try {
    resp = await httpRequest(`${REGISTRY_BASE}/-/whoami`, {
      headers: bearer(token),
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
    detail: `authenticated as npm user ${body["username"] ?? "?"}`,
    evidence: { status: resp.status, username: body["username"] ?? null },
  });
}

/** SAFE: `GET /-/npm/v1/tokens` reveals the token's type / 2FA posture. */
async function npmTokens(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "npm.tokens";
  let resp: Response;
  try {
    resp = await httpRequest(`${REGISTRY_BASE}/-/npm/v1/tokens`, {
      headers: bearer(token),
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
      detail: `could not read token list (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const objects = Array.isArray(body["objects"]) ? (body["objects"] as Record<string, unknown>[]) : [];
  // Record only non-secret metadata: never the token values themselves.
  const readonlyCount = objects.filter((o) => o["readonly"] === true).length;
  const automationCount = objects.filter((o) => o["automation"] === true).length;
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `${objects.length} token(s) on account ` +
      `(${readonlyCount} read-only, ${automationCount} automation)`,
    evidence: {
      status: resp.status,
      token_count: objects.length,
      readonly_count: readonlyCount,
      automation_count: automationCount,
    },
  });
}

// --- gated (manual) rung -----------------------------------------------------

/** The safe curl printed for the manual gated publish rung (secret as $KEY). */
function publishSafeCurl(): string {
  return (
    "curl -X PUT " +
    `'${REGISTRY_BASE}/PACKAGE_NAME' ` +
    '-H "Authorization: Bearer $KEY" ' +
    '-H "Content-Type: application/json" ' +
    "--data @package-publish-body.json"
  );
}

/**
 * GATED: `PUT /{package}` would publish a package version — state-changing,
 * supply-chain impact.
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without consent, throws {@link GatedProbeBlocked}. Even with consent this rung
 * is MANUAL: the URL needs a `{package}` the engine cannot fill, so it never
 * fires a live PUT — it only returns a safe curl (secret as `$KEY`).
 */
export const npmGatedPublish = gated(
  "npm.publish",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "npm.publish",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: publishes a package version (supply-chain impact); needs a " +
        "{package}; run the safe curl by hand to exercise the impact",
      evidence: { manual: true, safe_curl: publishSafeCurl() },
    });
  },
);

/** Attempt the gated publish rung; report it as blocked when consent is absent. */
async function maybePublish(consent: Consent): Promise<ProbeResult> {
  try {
    return await npmGatedPublish(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "npm.publish",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: publishSafeCurl() },
      });
    }
    throw exc;
  }
}

register([...DETECTORS], (finding, consent) => npmLadder(finding, consent));
