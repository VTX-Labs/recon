/**
 * Capability ladder for Airtable Personal Access Tokens (`pat...`).
 *
 * An Airtable PAT is a two-part `pat<14 chars>.<64 hex>` bearer credential
 * scoped to a set of OAuth-style scopes (e.g. `data.records:read`,
 * `schema.bases:read`) and a set of bases. This ladder climbs three rungs,
 * identity first, never exercising a write:
 *
 * - **whoami** (SAFE) — `GET /v0/meta/whoami` is the whoami + list-scopes call:
 *   it returns the token's user id and the scopes granted to the PAT. Proves the
 *   token authenticates and exactly how deep it can reach. Read-only,
 *   idempotent, non-billable.
 * - **list-bases** (SAFE) — `GET /v0/meta/bases` enumerates every base the token
 *   can reach (ids, names, permission level), measuring the blast radius across
 *   workspaces without touching any data. Read-only.
 * - **list-base-records** (GATED) — `GET /v0/{base_id}/{table}?maxRecords=1`
 *   reads actual record contents from a reachable base: the underlying business
 *   data (which may contain third-party PII) the program cares about. It is
 *   GATED because it reads arbitrary stored data, and because its URL needs a
 *   `{base_id}` and `{table}` the engine cannot fill, it never auto-fires — it
 *   is emitted as a MANUAL safe-curl note (the secret rendered as `$KEY`) only
 *   after the gated consent boundary is satisfied.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false`. The raw token is held only transiently for the HTTP
 * call and only non-secret values are ever placed in evidence.
 *
 * Docs: https://airtable.com/developers/web/api/introduction
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

/**
 * The exact safe curl an operator runs by hand for the gated record read. The
 * live secret stays a `$KEY` placeholder and the unfillable `BASE_ID` / `TABLE`
 * are left for the operator to substitute (from the prior `list-bases` rung and
 * the base schema).
 */
const LIST_BASE_RECORDS_CURL =
  "curl -sS -X GET " +
  "-H 'Authorization: Bearer $KEY' " +
  "'https://api.airtable.com/v0/BASE_ID/TABLE?maxRecords=1'";

/**
 * Airtable ladder: SAFE whoami (/meta/whoami) -> SAFE base enumeration
 * (/meta/bases) -> GATED record read (manual, needs a {base_id}/{table} the
 * engine cannot fill).
 */
export async function airtableLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await airtableWhoami(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await airtableListBases(key, fetchImpl));

    // The record read is GATED. The gated wrapper enforces consent BEFORE any
    // work; if consent is missing it throws GatedProbeBlocked, captured here as
    // a `blocked` rung. If consent IS granted the rung still does NOT fire a
    // live call — its URL needs a {base_id} and {table} the engine cannot fill
    // — so it returns a MANUAL safe-curl note instead. The ladder never throws
    // across the public boundary.
    try {
      rungs.push(await airtableListBaseRecords(consent, key));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "airtable.list-base-records",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated record read blocked: ${exc.reason}`,
            evidence: { reason: exc.reason, manual: true, safe_curl: LIST_BASE_RECORDS_CURL },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "airtable",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /v0/meta/whoami` is the whoami + list-scopes call — confirms the
 * token authenticates and returns its user id and the scopes granted to the
 * PAT. Read-only, idempotent, non-billable.
 */
async function airtableWhoami(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "airtable.whoami";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.airtable.com/v0/meta/whoami", {
      headers: { Authorization: `Bearer ${key}` },
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

  const scopes = Array.isArray(body["scopes"])
    ? (body["scopes"] as unknown[]).filter((v): v is string => typeof v === "string")
    : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `authenticated as user ${body["id"]} ` +
      `(scopes: ${scopes.length > 0 ? scopes.join(", ") : "(none reported)"})`,
    evidence: {
      status: resp.status,
      user_id: body["id"] ?? null,
      email: body["email"] ?? null,
      scopes,
    },
  });
}

/**
 * SAFE: `GET /v0/meta/bases` enumerates every base the token can reach (ids,
 * names, permission level) — the blast radius across workspaces without touching
 * any data. Read-only listing of reachable resources.
 */
async function airtableListBases(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "airtable.list-bases";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.airtable.com/v0/meta/bases", {
      headers: { Authorization: `Bearer ${key}` },
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
      detail: `could not list bases (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const bases = Array.isArray(body["bases"]) ? (body["bases"] as Record<string, unknown>[]) : [];
  // Summarise reach, do not dump: keep ids/names/permission levels only.
  const names = bases.map((b) => b["name"]).filter((v): v is string => typeof v === "string");
  const baseIds = bases.map((b) => b["id"]).filter((v): v is string => typeof v === "string");
  const permissionLevels = [
    ...new Set(bases.map((b) => b["permissionLevel"]).filter((v): v is string => typeof v === "string")),
  ];

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `token reaches ${bases.length} base(s)` +
      (names.length > 0 ? `: ${names.slice(0, 10).join(", ")}` : ""),
    evidence: {
      status: resp.status,
      base_count: bases.length,
      base_ids: baseIds.slice(0, 25),
      base_names: names.slice(0, 25),
      permission_levels: permissionLevels,
    },
  });
}

/**
 * GATED + MANUAL: read actual record contents from a reachable base.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and nothing happens. Even *with* consent this rung
 * never fires a live request: its URL needs a `{base_id}` (from the prior
 * `list-bases` rung) and a `{table}` (from the base schema) the engine cannot
 * fill, so it emits the copy-pasteable safe curl (secret as `$KEY`) instead.
 * This reads arbitrary stored data — the underlying business records, which may
 * contain third-party PII — which is exactly why it is gated.
 */
export const airtableListBaseRecords = gated(
  "airtable.list-base-records",
  async (_consent: Consent, _key: string): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "airtable.list-base-records",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL: needs a BASE_ID (from the list-bases rung) and a TABLE name (from " +
        `the base schema); run this by hand once you have them: ${LIST_BASE_RECORDS_CURL}`,
      evidence: { manual: true, safe_curl: LIST_BASE_RECORDS_CURL },
    });
  },
);

register(["AirtablePersonalAccessToken"], (finding, consent) => airtableLadder(finding, consent));
