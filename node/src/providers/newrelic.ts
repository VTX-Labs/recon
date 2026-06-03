/**
 * Capability ladder for New Relic personal API keys (`NRAK-...`).
 *
 * New Relic personal API keys (User keys) authenticate to the NerdGraph GraphQL
 * API at `https://api.newrelic.com/graphql` via an `Api-Key: <key>` header. Every
 * rung is a single `POST` carrying a read-only GraphQL query — the POST verb is
 * an artifact of GraphQL, not a mutation: each query is idempotent and
 * non-billable. TruffleHog surfaces these under `NewRelicPersonalApiKey`. The
 * ladder climbs:
 *
 * - **`viewer-identity`** (SAFE) — `{ actor { user { id name email } } }` is the
 *   NerdGraph whoami: it returns the key owner's identity, confirming the key is
 *   live and revealing who it belongs to. Decides VALID vs DENIED.
 * - **`list-accounts`** (SAFE) — `{ actor { accounts { id name } } }` enumerates
 *   every New Relic account the key can reach, proving the scope / blast radius of
 *   access (which accounts' telemetry, dashboards and config the key can read).
 *
 * Both rungs are read-only GraphQL queries: NerdGraph returns HTTP 200 even on a
 * GraphQL-level error, so each rung treats a populated `errors` array as a
 * failure. Every rung is ordered (identity first, then depth), READ-ONLY, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false` so one dead key cannot crash a batch run. The raw key is
 * held only transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

// The single NerdGraph GraphQL endpoint every rung POSTs to.
const NERDGRAPH_URL = "https://api.newrelic.com/graphql";

// `Api-Key` auth plus JSON content-type completes the headers each rung sends.
function newrelicHeaders(key: string): Record<string, string> {
  return {
    "Api-Key": key,
    "Content-Type": "application/json",
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

/** Collect GraphQL `errors[].message` strings (NerdGraph 200s even on error). */
function graphqlErrorMessages(body: Record<string, unknown>): string[] {
  const errors = Array.isArray(body["errors"]) ? (body["errors"] as Record<string, unknown>[]) : [];
  return errors
    .map((e) => e["message"])
    .filter((m): m is string => typeof m === "string");
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
 * New Relic ladder: SAFE viewer identity (`actor.user`) -> SAFE account
 * enumeration (`actor.accounts`).
 *
 * Both rungs are read-only NerdGraph queries. The first is whoami; the second
 * sizes the blast radius by listing every account the key can reach. There is no
 * GATED rung — neither query mutates or returns third-party PII beyond the key
 * owner's own identity and the accounts they already administer.
 */
export async function newrelicLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await newrelicViewerIdentity(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the key authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await newrelicListAccounts(key, fetchImpl));
  }

  return new LadderResult({
    finding,
    provider: "newrelic",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `{ actor { user { id name email } } }` is the NerdGraph whoami — it
 * confirms the key is live and returns the owner's identity (who the key belongs
 * to). POST but a read-only, idempotent, non-billable GraphQL query.
 */
async function newrelicViewerIdentity(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "viewer-identity";
  let resp: Response;
  try {
    resp = await httpRequest(NERDGRAPH_URL, {
      method: "POST",
      headers: newrelicHeaders(key),
      body: JSON.stringify({ query: "{ actor { user { id name email } } }" }),
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

  // NerdGraph returns HTTP 200 even when the key is bad: a populated `errors`
  // array (or a null user) means the key did not authenticate.
  const errors = graphqlErrorMessages(body);
  if (errors.length > 0) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `key rejected: ${errors[0]}`,
      evidence: { status: resp.status, errors: errors.slice(0, 3) },
    });
  }

  const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
  const actor = (data["actor"] as Record<string, unknown> | undefined) ?? {};
  const user = actor["user"] as Record<string, unknown> | undefined;
  if (!user) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: "key did not resolve a viewer identity",
      evidence: { status: resp.status },
    });
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${user["name"] ?? user["email"] ?? user["id"]} (id ${
      user["id"] ?? "unknown"
    })`,
    evidence: {
      status: resp.status,
      user_id: user["id"] ?? null,
      user_name: user["name"] ?? null,
      user_email: user["email"] ?? null,
    },
  });
}

/**
 * SAFE: `{ actor { accounts { id name } } }` enumerates every New Relic account
 * the key can reach, proving the scope of access (blast radius) — which
 * accounts' telemetry, dashboards and config the key can read. Read-only
 * GraphQL.
 */
async function newrelicListAccounts(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-accounts";
  let resp: Response;
  try {
    resp = await httpRequest(NERDGRAPH_URL, {
      method: "POST",
      headers: newrelicHeaders(key),
      body: JSON.stringify({ query: "{ actor { accounts { id name } } }" }),
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
      detail: `could not list accounts (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const errors = graphqlErrorMessages(body);
  if (errors.length > 0) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `could not list accounts: ${errors[0]}`,
      evidence: { status: resp.status, errors: errors.slice(0, 3) },
    });
  }

  // Accounts arrive under data.actor.accounts; summarise ids/names to size the
  // blast radius without dumping the whole payload.
  const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
  const actor = (data["actor"] as Record<string, unknown> | undefined) ?? {};
  const accounts = Array.isArray(actor["accounts"])
    ? (actor["accounts"] as Record<string, unknown>[])
    : [];
  const names = accounts
    .map((a) => (a["name"] ?? a["id"]) as string | number | undefined)
    .filter((n): n is string | number => typeof n === "string" || typeof n === "number")
    .map((n) => String(n));

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `key can reach ${accounts.length} account(s): ${
      names.length > 0 ? names.slice(0, 5).join(", ") : "(none)"
    }`,
    evidence: {
      status: resp.status,
      account_count: accounts.length,
      account_ids: accounts
        .map((a) => a["id"] ?? null)
        .filter((id) => id !== null)
        .slice(0, 25),
      names_sample: names.slice(0, 25),
    },
  });
}

register(["NewRelicPersonalApiKey"], (finding, consent) => newrelicLadder(finding, consent));
