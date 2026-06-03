/**
 * Datadog capability ladder — prove depth of access for a leaked API key.
 *
 * Handles the TruffleHog `DatadogToken` finding: a 32-char hex Datadog **API
 * key** (`DD-API-KEY`). Datadog splits its credentials in two: the API key alone
 * is enough to *ingest* and to call `GET /api/v1/validate`, but every read of
 * org / user / observability config additionally requires a paired
 * **application key** (`DD-APPLICATION-KEY`) — a second secret that is NOT
 * present in the raw API key. The engine can only fill the `{key}` placeholder,
 * so any rung whose headers embed `{app_key}` cannot be auto-fired.
 *
 * Ordered ladder (identity/validity first, then depth):
 *
 *   1. `validate-api-key`   SAFE. `GET /api/v1/validate` with only `DD-API-KEY`
 *      confirms the key is live (returns `{"valid": true}`). Read-only,
 *      idempotent, non-billable — this is the rung that decides VALID vs DENIED.
 *   2. `list-current-user`  SAFE/MANUAL. `GET /api/v2/current_user` returns the
 *      user/org the keys map to (name, email, org) — whoami + depth. Requires
 *      BOTH `DD-API-KEY` and a paired `DD-APPLICATION-KEY` (second secret not in
 *      the raw key), so it is never auto-fired: it renders a safe curl that keeps
 *      the API key as `$KEY` and the app key as `$APP_KEY`.
 *   3. `list-monitors`      SAFE/MANUAL. `GET /api/v1/monitor` enumerates the
 *      org's own monitors (alert configs, query content), proving read access to
 *      observability config. Also needs the paired app key, so it is rendered as
 *      a manual safe-curl note rather than a live call.
 *
 * Only the first rung makes a live request; the others are MANUAL because the
 * engine cannot supply the second secret. Every rung is ordered (validity
 * first, then depth), the live rung is a READ-ONLY GET, and the ladder never
 * throws across its public boundary: failures become a {@link ProbeResult} with
 * `success=false`. The raw key is held only transiently for the HTTP call and
 * never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["DatadogToken"] as const;

const API_BASE = "https://api.datadoghq.com";

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

// --------------------------------------------------------------------------- //
// safe-curl rendering (used only for the MANUAL app-key rungs)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl for a Datadog read that needs BOTH keys. The API
 * key is kept as the `$KEY` placeholder and the paired application key as
 * `$APP_KEY` (the second secret is not in the raw finding), so the string never
 * contains a live secret and is safe to print and to store.
 */
function safeCurl(url: string): string {
  const parts = ["curl", "-sS", "-X", "GET"];
  parts.push("-H", shquote("DD-API-KEY: $KEY"));
  parts.push("-H", shquote("DD-APPLICATION-KEY: $APP_KEY"));
  parts.push("-H", shquote("Accept: application/json"));
  parts.push(shquote(url));
  return parts.join(" ");
}

/**
 * Run the ordered Datadog capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs `validate-api-key` first (only `DD-API-KEY` is needed) and only
 * descends into the deeper rungs if the key validated. Those deeper rungs each
 * need a paired `DD-APPLICATION-KEY` (a second secret not in the raw key), so
 * they are emitted as MANUAL safe-curl notes rather than live calls. Never
 * throws across this boundary.
 */
export async function datadogLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: validate-api-key (SAFE) — validity, decides live/dead ---------
  const identity = await validateApiKey(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the key validated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-current-user (SAFE / MANUAL app-key rung) --------------
    // Needs a paired DD-APPLICATION-KEY the engine cannot supply, so it never
    // fires a live request: it is rendered as a manual safe-curl note.
    rungs.push(listCurrentUserManual());

    // --- Rung 3: list-monitors (SAFE / MANUAL app-key rung) -----------------
    rungs.push(listMonitorsManual());
  }

  return new LadderResult({
    finding,
    provider: "datadog",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/**
 * SAFE: `GET /api/v1/validate` confirms the API key is live (returns
 * `{"valid": true}`). Needs only `DD-API-KEY` — read-only, idempotent,
 * non-billable. This is the validity/identity rung that decides VALID vs DENIED.
 * Records only the non-secret `valid` flag, never the key.
 */
async function validateApiKey(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "validate-api-key";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/api/v1/validate`, {
      headers: { "DD-API-KEY": key, Accept: "application/json" },
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
      detail: `API key rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // Datadog returns 200 with {"valid": true} for a live key. Treat an explicit
  // non-true `valid` as a rejection so a soft-failure body is not a false VALID.
  const valid = body["valid"] === true;
  if (!valid) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: "API key reported not valid",
      evidence: { status: resp.status, valid: body["valid"] ?? null },
    });
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: "API key is live (validate returned valid=true)",
    evidence: { status: resp.status, valid: true },
  });
}

/**
 * SAFE/MANUAL: `GET /api/v2/current_user` returns the user/org the keys map to
 * (name, email, org) — whoami + depth. Requires BOTH `DD-API-KEY` and a paired
 * `DD-APPLICATION-KEY` (a second secret NOT present in the raw API key), so the
 * engine cannot fill the `{app_key}` header — no live call is made. The operator
 * is handed the exact safe curl (API key `$KEY`, app key `$APP_KEY`).
 */
function listCurrentUserManual(): ProbeResult {
  const name = "list-current-user";
  const url = `${API_BASE}/api/v2/current_user`;
  const curl = safeCurl(url);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs a paired DD-APPLICATION-KEY (a second secret not in the raw " +
      "API key); run this by hand to reveal the user/org the keys map to " +
      `(name, email, org): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

/**
 * SAFE/MANUAL: `GET /api/v1/monitor` enumerates the org's own monitors (alert
 * configs, query content), proving read access to observability config.
 * Read-only, non-billable. Also needs the paired `DD-APPLICATION-KEY` (second
 * secret not in the raw key), so no live call is made — the operator is handed
 * the safe curl.
 */
function listMonitorsManual(): ProbeResult {
  const name = "list-monitors";
  const url = `${API_BASE}/api/v1/monitor`;
  const curl = safeCurl(url);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the paired DD-APPLICATION-KEY (second secret not in the raw " +
      "key); run this by hand to enumerate the org's monitors (alert configs / " +
      `query content) and prove read access to observability config: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

register([...DETECTORS], (finding, consent) => datadogLadder(finding, consent));
