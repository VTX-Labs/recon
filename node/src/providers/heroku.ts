/**
 * Heroku Platform API capability ladder — prove depth of access for a leaked key.
 *
 * A TruffleHog `Heroku` finding is a Platform API key (a UUID). The key is sent
 * as `Authorization: Bearer <key>` with `Accept: application/vnd.heroku+json;
 * version=3`. The ladder climbs from identity to reach, then stops at a GATED
 * rung that would dump an app's secret config vars.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `account`           `GET /account` — SAFE. Identity / whoami: returns the
 *      account id, email, name and 2FA status. This is TruffleHog's own
 *      verification call; it decides VALID vs DENIED. Read-only.
 *   2. `list-apps`         `GET /apps` — SAFE. Enumerates every app the key can
 *      administer (names, regions, owners) — reach across deployments beyond
 *      auth. Read-only.
 *   3. `read-config-vars`  `GET /apps/APP_ID/config-vars` — GATED. Dumps an
 *      app's environment variables (DATABASE_URL, third-party API keys, secrets
 *      enabling lateral movement). Routed through {@link gated} so the SAFE tier
 *      can never reach it; and because its URL needs an `APP_ID` (from
 *      `list-apps`) the engine cannot substitute, even under full consent it
 *      never auto-fires — it renders a copy-pasteable safe curl (secret kept as
 *      `$KEY`) for the operator to run by hand. It stays GATED because it reads
 *      sensitive secret material.
 *
 * Every automated rung is a READ-ONLY `GET`. The ladder never throws across its
 * public boundary: failures become a {@link ProbeResult} with `success=false`.
 * The raw key is held only transiently for the HTTP call and never lands in
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

const API_BASE = "https://api.heroku.com";

/**
 * The exact, copy-pasteable safe curl for the manual gated rung. The secret is
 * NEVER interpolated: it stays the literal `$KEY` shell variable, and the
 * `APP_ID` placeholder is left for the operator to fill from `list-apps`.
 */
const READ_CONFIG_VARS_SAFE_CURL =
  "curl -sS -X GET " +
  "-H 'Authorization: Bearer $KEY' " +
  "-H 'Accept: application/vnd.heroku+json; version=3' " +
  "'https://api.heroku.com/apps/APP_ID/config-vars'";

/** Standard Heroku Platform API headers carrying the bearer key. */
function herokuHeaders(key: string): Record<string, string> {
  return {
    Authorization: `Bearer ${key}`,
    Accept: "application/vnd.heroku+json; version=3",
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
 * Heroku ladder: SAFE identity (/account) -> SAFE reach (/apps) -> GATED config-var
 * dump (manual safe-curl; needs an APP_ID the engine cannot fill).
 */
export async function herokuLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: identity (SAFE) ---
  const identity = await herokuAccount(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the key authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: reach across apps (SAFE) ---
    rungs.push(await herokuListApps(key, fetchImpl));

    // --- Rung 3: config-var dump (GATED, manual safe-curl) ---
    // The gated() wrapper enforces consent BEFORE the body runs; without BOTH
    // --prove and --i-am-authorized it throws GatedProbeBlocked, captured here as
    // a `blocked` rung so the ladder never throws across the public boundary.
    // When consent IS granted the body still makes no live call: the URL needs an
    // APP_ID the engine cannot fill, so it returns a manual safe-curl rung.
    try {
      rungs.push(await herokuGatedReadConfigVars(consent, key));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "read-config-vars",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: {
              reason: exc.reason,
              manual: true,
              safe_curl: READ_CONFIG_VARS_SAFE_CURL,
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
    provider: "heroku",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /account` confirms the key and returns account identity. */
async function herokuAccount(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "account";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/account`, {
      headers: herokuHeaders(key),
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
      detail: `key rejected (HTTP ${resp.status})`,
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
    detail: `authenticated as ${body["email"] ?? body["id"]} (id ${body["id"]})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      email: body["email"] ?? null,
      name: body["name"] ?? null,
      two_factor_authentication: body["two_factor_authentication"] ?? null,
    },
  });
}

/** SAFE: `GET /apps` enumerates every app the key can administer (reach). */
async function herokuListApps(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-apps";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/apps`, {
      headers: herokuHeaders(key),
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
      detail: `could not list apps (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const parsed = (await readJson(resp)) as unknown;
  const apps = Array.isArray(parsed) ? parsed : [];
  // Record only non-sensitive identifiers (app names), never app contents.
  const names = apps
    .filter((a): a is Record<string, unknown> => isObject(a) && Boolean(a["name"]))
    .map((a) => a["name"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: names.length > 0,
    detail:
      names.length > 0
        ? `${names.length} app(s) administrable: ${names.join(", ")}`
        : "no apps administrable with this key",
    evidence: { status: resp.status, app_count: names.length, apps: names.slice(0, 25) },
  });
}

/**
 * GATED + MANUAL: `GET /apps/APP_ID/config-vars` would dump an app's secrets.
 *
 * Wrapped with {@link gated}: the safety boundary throws
 * {@link GatedProbeBlocked} *before* this body runs unless BOTH `--prove` and
 * `--i-am-authorized` were supplied. Even under full consent the body makes NO
 * live call — the URL needs an `APP_ID` (a non-`{key}` placeholder, from
 * `list-apps`) the engine cannot fill — so it returns a manual safe-curl rung
 * that keeps the secret as the literal `$KEY` shell variable for an operator to
 * run by hand. Reading config vars dumps downstream secrets (DATABASE_URL, API
 * keys) usable for lateral movement, which is exactly why it is gated.
 */
export const herokuGatedReadConfigVars = gated(
  "heroku.read-config-vars",
  async (_consent: Consent, _key: string): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "read-config-vars",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL: needs an APP_ID from list-apps; dumps app env vars " +
        `(DATABASE_URL, API secrets). Run this by hand: ${READ_CONFIG_VARS_SAFE_CURL}`,
      evidence: { manual: true, safe_curl: READ_CONFIG_VARS_SAFE_CURL },
    });
  },
);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register(["Heroku"], (finding, consent) => herokuLadder(finding, consent));
