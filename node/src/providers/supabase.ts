/**
 * Capability ladder for Supabase service_role JWTs (`eyJ...`).
 *
 * A Supabase finding is a long, three-segment JWT. The dangerous one is the
 * `service_role` key: it bypasses Row-Level Security and can read every table
 * and every end-user account in the project. This module describes the depth of
 * access such a key grants — but every rung here is **manual**.
 *
 * Why every rung is manual: the impact endpoints all live on the project's own
 * subdomain (`https://{ref}.supabase.co/...`) and the project `ref` is NOT
 * present in the raw JWT, so the engine cannot fill the `{ref}` placeholder
 * (and `list-table-rows` additionally needs a `{table}` name discovered from
 * the OpenAPI schema). Per the ladder conventions, a rung whose URL/headers
 * carry any placeholder other than `{key}` MUST NOT fire a live call: instead it
 * records a `ProbeResult(success=false)` carrying a safe `curl` the operator can
 * run by hand, with the secret kept as the shell variable `$KEY` (never the raw
 * value).
 *
 * Rungs (ordered, identity/reachability first):
 *
 *   1. `rest-root-openapi`  `GET /rest/v1/`             — SAFE, manual. Proves
 *      the project is reachable and PostgREST accepts the JWT; returns the
 *      auto-generated OpenAPI schema (every table/view/RPC/column). Read-only,
 *      idempotent, no PII, non-billable.
 *   2. `list-table-rows`    `GET /rest/v1/{table}?limit=1` — GATED, manual. A
 *      row read of a discovered table; the data may be third-party PII.
 *   3. `list-auth-users`    `GET /auth/v1/admin/users`  — GATED, manual. GoTrue
 *      admin listing of every end-user (emails, phones, identities, metadata).
 *
 * The two GATED rungs are routed through the {@link gated} boundary so they can
 * never auto-fire without consent; even WITH consent they make no network call
 * (their URLs need `{ref}`/`{table}` the engine cannot fill) and are rendered as
 * manual safe-curl notes. The ladder never throws across its public boundary:
 * every outcome is a {@link ProbeResult} reflected in the {@link Verdict}.
 *
 * Docs: https://supabase.com/docs/guides/api ;
 * https://supabase.com/docs/reference/javascript/auth-admin-listusers
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
// (Kept for parity with the other ladders; this provider is fully manual and
// issues no live request, but the constant documents the intended bound.)
const TIMEOUT_MS = 10_000;
void TIMEOUT_MS;

// The placeholder host: the engine cannot resolve `{ref}` from the JWT, so the
// real URLs are only ever rendered into a manual curl, never fetched.
const REST_ROOT_URL = "https://{ref}.supabase.co/rest/v1/";
const LIST_TABLE_URL = "https://{ref}.supabase.co/rest/v1/{table}?limit=1";
const LIST_AUTH_USERS_URL = "https://{ref}.supabase.co/auth/v1/admin/users";

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID (authenticates + depth shown).
 * - The key authenticated nowhere -> DENIED.
 *
 * Because every Supabase rung is manual (no live call), no rung succeeds and
 * the verdict is DENIED until an operator runs the emitted curls by hand.
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
 * Render a safe curl for a manual rung, keeping the secret as `$KEY` (never the
 * raw value). The caller exports `KEY=<service_role jwt>` before running it.
 */
function safeCurl(method: string, url: string): string {
  return (
    `curl -s -X ${method} '${url}' ` +
    `-H 'apikey: $KEY' -H 'Authorization: Bearer $KEY'`
  );
}

/**
 * SAFE (manual): `GET /rest/v1/` returns the project's OpenAPI schema.
 *
 * The URL needs `{ref}` (the project subdomain), which is not in the JWT, so we
 * never call it — we emit a runnable curl instead. Proves reachability + that
 * PostgREST accepts the service_role JWT; read-only, idempotent, no PII.
 */
function restRootOpenapi(): ProbeResult {
  return new ProbeResult({
    name: "rest-root-openapi",
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "manual rung: project ref subdomain is not in the JWT — run the safe curl " +
      "to fetch the OpenAPI schema (every table/view/RPC/column). Replace {ref}.",
    evidence: {
      manual: true,
      tier: "safe",
      method: "GET",
      url: REST_ROOT_URL,
      success_status: [200],
      safe_curl: safeCurl("GET", REST_ROOT_URL),
    },
  });
}

/**
 * GATED + MANUAL: `GET /rest/v1/{table}?limit=1` reads application data,
 * proving the service_role key bypasses RLS.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and nothing happens. Even WITH consent it never
 * fires a live request — its URL needs `{ref}` and a `{table}` discovered from
 * the OpenAPI schema the engine cannot fill — so it returns a manual safe-curl
 * note. A row read may return third-party PII, which is why it is gated.
 */
export const supabaseListTableRows = gated(
  "supabase.list-table-rows",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "list-table-rows",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "gated manual rung: a service_role row read bypasses RLS and may return " +
        "third-party PII. Needs {ref} and a {table} from the OpenAPI schema; run " +
        "the safe curl by hand under explicit authorization (expect HTTP 200/206).",
      evidence: {
        manual: true,
        tier: "gated",
        method: "GET",
        url: LIST_TABLE_URL,
        success_status: [200, 206],
        safe_curl: safeCurl("GET", LIST_TABLE_URL),
      },
    });
  },
);

/**
 * GATED + MANUAL: `GET /auth/v1/admin/users` lists every end-user account
 * (emails, phones, identities, metadata) via GoTrue admin — the impact that
 * matters.
 *
 * Wrapped with {@link gated}: without full consent it throws
 * {@link GatedProbeBlocked} before any work. Even WITH consent it never fires a
 * live request — its URL needs `{ref}` the engine cannot fill — so it returns a
 * manual safe-curl note. It reads third-party PII, which is why it is gated.
 */
export const supabaseListAuthUsers = gated(
  "supabase.list-auth-users",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "list-auth-users",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "gated manual rung: the GoTrue admin endpoint lists every end-user " +
        "(emails, phones, identities, metadata). Needs {ref}; run the safe curl " +
        "by hand under explicit authorization (expect HTTP 200).",
      evidence: {
        manual: true,
        tier: "gated",
        method: "GET",
        url: LIST_AUTH_USERS_URL,
        success_status: [200],
        safe_curl: safeCurl("GET", LIST_AUTH_USERS_URL),
      },
    });
  },
);

/**
 * Climb the Supabase capability ladder for a finding.
 *
 * Every rung is manual (the project `ref` subdomain is not in the JWT), so no
 * network call is made: the ladder emits ordered, runnable safe curls — the
 * SAFE OpenAPI probe first, then the two GATED PII reads routed through the
 * {@link gated} boundary (blocked unless consent is granted; manual even with
 * it). Never throws across this boundary; the worst case is a DENIED verdict.
 */
export async function supabaseLadder(
  finding: Finding,
  consent: Consent,
  _options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  // The ladder (even its manual tier) refuses to run without a named scope.
  const scope = consent.requireLadderScope();
  // The secret is read but never persisted; the printed curls keep `$KEY`.
  void finding.raw;

  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE, manual): reachability + JWT acceptance + DB surface area.
  rungs.push(restRootOpenapi());

  // Rungs 2 & 3 (GATED, manual): RLS-bypassing data read, then the auth-user
  // dump. Each is routed through the gated() boundary so it can never auto-fire
  // without consent; if consent is missing the wrapper throws GatedProbeBlocked
  // and we record a blocked note. Even with consent the body fires no live call
  // (its URL needs {ref}/{table} the engine cannot fill) — it returns a manual
  // safe-curl note. The ladder never throws across the public boundary.
  try {
    rungs.push(await supabaseListTableRows(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "list-table-rows",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: { manual: true, safe_curl: safeCurl("GET", LIST_TABLE_URL) },
        }),
      );
    } else {
      throw exc;
    }
  }

  try {
    rungs.push(await supabaseListAuthUsers(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "list-auth-users",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: { manual: true, safe_curl: safeCurl("GET", LIST_AUTH_USERS_URL) },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "supabase",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(["Supabase"], (finding, consent) => supabaseLadder(finding, consent));
