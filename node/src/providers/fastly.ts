/**
 * Fastly capability ladder — prove depth of access for a leaked API token.
 *
 * Handles TruffleHog `FastlyPersonalToken` findings: a 32-char
 * `[A-Za-z0-9_-]` Fastly API token. Fastly authenticates with the
 * **`Fastly-Key`** header (NOT `Authorization: Bearer`); every rung here uses
 * that header and holds the secret only transiently for the call.
 *
 * Ordered ladder (depth of access, least -> most impactful):
 *
 *   1. `token-self`    `GET /tokens/self` (SAFE) — TruffleHog's own
 *      verification call. Returns the token's id, user_id, scoped services and
 *      scope (e.g. `global:read`), created_at. Confirms auth and reveals
 *      exactly what the token can do. Read-only.
 *   2. `list-services` `GET /service` (SAFE) — enumerates every Fastly service
 *      (CDN config) the token can reach: depth into the customer's edge config.
 *      Read-only listing of owned resources.
 *   3. `purge-all`     `POST /service/SERVICE_ID/purge_all` (GATED) — purges a
 *      service's entire cache: state-changing impact (origin-load spike /
 *      cache-poisoning prep). Its URL needs a `SERVICE_ID` the engine cannot
 *      fill from the secret, so this rung is **manual**: it never fires a live
 *      call. It is still wired through {@link gated} so the safety boundary is
 *      enforced, and it renders as a blocked/manual rung carrying a safe `curl`
 *      that keeps the secret as `$KEY`.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false`. Secrets are held only transiently for the HTTP call and
 * only non-secret values land in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

const API_BASE = "https://api.fastly.com";

/** Build the Fastly auth header. Fastly uses `Fastly-Key`, not Bearer. */
function headers(key: string): Record<string, string> {
  return { "Fastly-Key": key, Accept: "application/json" };
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
 * Run the ordered Fastly capability ladder for a single finding.
 *
 * Never throws across the public boundary: any error is captured into a
 * {@link ProbeResult}. The authorized scope is required (the whole ladder
 * refuses to run without it).
 */
export async function fastlyLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: token-self (SAFE) — identity + scope. TruffleHog's verify call.
  const identity = await fastlyTokenSelf(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-services (SAFE) — reachable edge configs.
    rungs.push(await fastlyListServices(key, fetchImpl));

    // --- Rung 3: purge-all (GATED, MANUAL) — never auto-fires. The URL needs a
    // SERVICE_ID the engine cannot fill from the secret, so we render a safe
    // curl instead of issuing a live request. Still routed through the gated()
    // boundary so consent is enforced even for the manual rendering.
    try {
      rungs.push(await fastlyPurgeAll(consent));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "purge-all",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: { manual: true, reason: exc.reason, safe_curl: PURGE_ALL_CURL },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "fastly",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /tokens/self` confirms the token and returns its id, user_id,
 * scoped services, scope, and created_at. This is TruffleHog's verification
 * call; it proves auth and reveals exactly what the token can do. Read-only.
 */
async function fastlyTokenSelf(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "token-self";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/tokens/self`, {
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
      detail: `token rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // `services` may be a list of service ids the token is scoped to, or null
  // (token has access to all services). Record only the count + ids (non-secret).
  const services = Array.isArray(body["services"]) ? (body["services"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `token authenticates (id ${body["id"] ?? "?"}, ` +
      `scope ${body["scope"] ?? "?"}, user ${body["user_id"] ?? "?"})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      user_id: body["user_id"] ?? null,
      scope: body["scope"] ?? null,
      created_at: body["created_at"] ?? null,
      scoped_service_count: services.length,
      scoped_services: services.slice(0, 25),
    },
  });
}

/**
 * SAFE: `GET /service` enumerates every Fastly service (CDN config) the token
 * can reach — depth into the customer's edge config. Read-only listing of owned
 * resources. Only non-secret identifiers (ids, names) are recorded.
 */
async function fastlyListServices(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-services";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/service`, {
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

  const parsed = (await readJson(resp)) as unknown;
  const items = (Array.isArray(parsed) ? parsed : []).filter(isObject);
  // Record only non-sensitive identifiers, never service config contents.
  const ids = items
    .map((s) => (typeof s["id"] === "string" ? (s["id"] as string) : null))
    .filter((v): v is string => Boolean(v));
  const names = items
    .map((s) => (typeof s["name"] === "string" ? (s["name"] as string) : null))
    .filter((v): v is string => Boolean(v));
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: items.length > 0,
    detail:
      items.length > 0
        ? `${items.length} reachable service(s): ${names.slice(0, 5).join(", ")}`
        : "no services reachable with this token",
    evidence: {
      status: resp.status,
      service_count: items.length,
      service_ids: ids.slice(0, 25),
      service_names: names.slice(0, 25),
    },
  });
}

/** The safe, never-fired curl for the manual gated purge-all rung. */
const PURGE_ALL_CURL =
  'curl -X POST -H "Fastly-Key: $KEY" ' + `${API_BASE}/service/SERVICE_ID/purge_all`;

/**
 * GATED + MANUAL: `POST /service/SERVICE_ID/purge_all` purges a service's
 * entire cache — a state-changing impact (origin-load spike / cache-poisoning
 * prep). The URL needs a `SERVICE_ID` the engine cannot fill from the secret,
 * so this probe NEVER issues a live call: it only renders a safe `curl` that
 * keeps the secret as `$KEY`.
 *
 * It is still wrapped with {@link gated} so the safety boundary runs *before*
 * the body: without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and even the manual rendering is recorded as a
 * blocked rung. With full consent it returns a manual, non-fired ProbeResult
 * (success=false) carrying the safe curl — the engine must not auto-mutate.
 */
export const fastlyPurgeAll = gated(
  "fastly.purge-all",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "purge-all",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: purge_all needs a SERVICE_ID from list-services; " +
        "run the safe curl yourself (no live call fired)",
      evidence: {
        manual: true,
        needs: "SERVICE_ID",
        safe_curl: PURGE_ALL_CURL,
      },
    });
  },
);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register(["FastlyPersonalToken"], (finding, consent) => fastlyLadder(finding, consent));
