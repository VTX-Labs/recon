/**
 * Render capability ladder — prove depth of access for a leaked `rnd_` key.
 *
 * Render API keys are prefixed `rnd_` + a random string and are presented as
 * `Authorization: Bearer <key>` against `https://api.render.com/v1`. TruffleHog
 * ships **no** Render detector, so this ladder is custom-routed off the
 * distinctive `rnd_` regex and registered for the synthetic `"Render"`
 * detector name.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `list-owners`   `GET /v1/owners` — identity/whoami equivalent. Lists the
 *      workspaces (owners: ids, names, emails) the key belongs to. Confirms the
 *      key authenticates and reveals the account footprint. READ-ONLY.
 *   2. `list-services` `GET /v1/services` — enumerates every Render service the
 *      key can view (names, types, repos, URLs): depth into deployments.
 *      READ-ONLY listing of owned resources.
 *   3. `read-env-vars` `GET /v1/services/{serviceId}/env-vars` — **GATED**.
 *      Dumps a service's environment variables (downstream DB URLs, API keys,
 *      secrets for lateral movement). Gated because it reads sensitive secret
 *      material. The URL needs a `SERVICE_ID` the engine cannot fill, so even
 *      under consent this rung never auto-fires: it renders a copy-pasteable
 *      safe curl (secret kept as `$KEY`) for the operator to run by hand.
 *
 * Every rung is ordered (identity first, then depth) and never throws across the
 * public boundary: failures become a {@link ProbeResult} with `success=false`.
 * Secrets are held only transiently for the HTTP call and only non-secret values
 * ever land in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

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

/** Bearer auth header for the Render API. */
function headers(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}`, Accept: "application/json" };
}

/**
 * The exact, copy-pasteable safe curl for the manual gated rung. The secret is
 * NEVER interpolated: it stays the literal `$KEY` shell variable, and the
 * `SERVICE_ID` placeholder is left for the operator to fill from `list-services`.
 */
const READ_ENV_VARS_SAFE_CURL =
  'curl -sS -H "Authorization: Bearer $KEY" ' +
  "https://api.render.com/v1/services/SERVICE_ID/env-vars";

/**
 * Run the ordered Render capability ladder for a single finding.
 *
 * Never throws across the public boundary: any error is captured into a
 * {@link ProbeResult}. The authorized scope is required (the whole ladder
 * refuses to run without it).
 */
export async function renderLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: list-owners (SAFE) — identity/whoami ---
  const identity = await renderListOwners(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the key authenticated (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-services (SAFE) ---
    rungs.push(await renderListServices(key, fetchImpl));

    // --- Rung 3: read-env-vars (GATED, manual safe-curl) ---
    // The gated() wrapper enforces consent BEFORE the body runs; without BOTH
    // --prove and --i-am-authorized it throws GatedProbeBlocked, captured here
    // as a `blocked` rung so the ladder never throws across the public boundary.
    // When consent IS granted the body still makes no live call: the URL needs a
    // SERVICE_ID the engine cannot fill, so it returns a manual safe-curl rung.
    try {
      rungs.push(await renderGatedReadEnvVars(consent, key));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "read-env-vars",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: { reason: exc.reason, manual: true, safe_curl: READ_ENV_VARS_SAFE_CURL },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "render",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /v1/owners` — identity/whoami equivalent.
 *
 * Lists the workspaces (owners) the key belongs to. Confirms auth and reveals
 * the account footprint (ids, names, emails). Read-only.
 */
async function renderListOwners(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-owners";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.render.com/v1/owners", {
      headers: headers(key),
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

  const body = (await readJson(resp)) as unknown;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // The endpoint returns a list of { owner: { id, name, email, type } } wrappers.
  const items = Array.isArray(body) ? body : [];
  const owners = items
    .map((item) => (isObject(item) && isObject(item["owner"]) ? item["owner"] : isObject(item) ? item : null))
    .filter((o): o is Record<string, unknown> => o !== null);
  const names = owners.map((o) => o["name"]).filter((n): n is string => typeof n === "string");
  const ids = owners.map((o) => o["id"]).filter((i): i is string => typeof i === "string");

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      owners.length > 0
        ? `authenticated; key belongs to ${owners.length} workspace(s): ${names.join(", ") || "(unnamed)"}`
        : "authenticated; no workspaces visible",
    evidence: {
      status: resp.status,
      owner_count: owners.length,
      owner_ids: ids.slice(0, 25),
      owner_names: names.slice(0, 25),
    },
  });
}

/**
 * SAFE: `GET /v1/services` — enumerate every Render service the key can view.
 *
 * Read-only listing of owned resources: depth into deployments (names, types,
 * repos). Only non-secret identifiers are kept in evidence.
 */
async function renderListServices(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-services";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.render.com/v1/services", {
      headers: headers(key),
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
      detail: `could not list services (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as unknown;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // The endpoint returns a list of { service: { id, name, type, ... } } wrappers.
  const items = Array.isArray(body) ? body : [];
  const services = items
    .map((item) => (isObject(item) && isObject(item["service"]) ? item["service"] : isObject(item) ? item : null))
    .filter((s): s is Record<string, unknown> => s !== null);
  const serviceNames = services.map((s) => s["name"]).filter((n): n is string => typeof n === "string");
  const serviceIds = services.map((s) => s["id"]).filter((i): i is string => typeof i === "string");
  const types = [
    ...new Set(services.map((s) => s["type"]).filter((t): t is string => typeof t === "string")),
  ].sort();

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: services.length > 0,
    detail:
      services.length > 0
        ? `${services.length} service(s) reachable [${types.join(", ") || "?"}]: ${serviceNames.join(", ")}`
        : "no services reachable",
    evidence: {
      status: resp.status,
      service_count: services.length,
      service_ids: serviceIds.slice(0, 25),
      service_names: serviceNames.slice(0, 25),
      service_types: types,
    },
  });
}

/**
 * GATED + MANUAL: `GET /v1/services/{serviceId}/env-vars`.
 *
 * Wrapped with {@link gated}: the safety boundary throws
 * {@link GatedProbeBlocked} *before* this body runs unless BOTH `--prove` and
 * `--i-am-authorized` were supplied. Even under full consent the body makes NO
 * live call — the URL needs a `SERVICE_ID` (a non-`{key}` placeholder) the
 * engine cannot fill — so it returns a manual safe-curl rung that keeps the
 * secret as the literal `$KEY` shell variable for an operator to run by hand.
 * Reading env-vars dumps downstream secrets (DB URLs, API keys) usable for
 * lateral movement, which is exactly why it is gated.
 */
export const renderGatedReadEnvVars = gated(
  "render.read-env-vars",
  async (_consent: Consent, _key: string): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "read-env-vars",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail: `MANUAL: needs a SERVICE_ID from list-services; run this by hand: ${READ_ENV_VARS_SAFE_CURL}`,
      evidence: { manual: true, safe_curl: READ_ENV_VARS_SAFE_CURL },
    });
  },
);

register(["Render"], (finding, consent) => renderLadder(finding, consent));

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
