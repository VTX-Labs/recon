/**
 * Capability ladder for Netlify personal access / OAuth tokens.
 *
 * A Netlify token is a 43-45 char `[A-Za-z0-9_-]` bearer credential. This
 * ladder climbs three rungs, identity first, never exercising a write:
 *
 * - **user** (SAFE) — `GET /api/v1/user` is the whoami: it returns the owning
 *   user's id, email and full name, confirming the token authenticates and who
 *   it belongs to. Read-only.
 * - **list-sites** (SAFE) — `GET /api/v1/sites` enumerates every Netlify site
 *   the token can reach (names, custom domains, admin urls). This is also
 *   TruffleHog's verification call; it measures depth across deployments
 *   without changing anything.
 * - **read-site-env** (GATED) — `GET /api/v1/accounts/{account_id}/env` reads
 *   the account/site build environment variables: downstream API keys and
 *   secrets that enable lateral movement. It is GATED because it reads
 *   sensitive secret material, and because its URL needs an `ACCOUNT_ID` the
 *   engine cannot fill, it never auto-fires — it is emitted as a MANUAL
 *   safe-curl note (the secret rendered as `$KEY`) only after the gated
 *   consent boundary is satisfied.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false`. The raw token is held only transiently for the HTTP
 * call and only non-secret values are ever placed in evidence.
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
 * Netlify ladder: SAFE whoami (/user) -> SAFE site enumeration (/sites) ->
 * GATED env read (manual, needs an ACCOUNT_ID the engine cannot fill).
 */
export async function netlifyLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await netlifyUser(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await netlifyListSites(key, fetchImpl));

    // The env read is GATED. The gated wrapper enforces consent BEFORE any work;
    // if consent is missing it throws GatedProbeBlocked, captured here as a
    // `blocked` rung. If consent IS granted the rung still does NOT fire a live
    // call — its URL needs an ACCOUNT_ID the engine cannot fill — so it returns
    // a MANUAL safe-curl note instead. The ladder never throws across the
    // public boundary.
    try {
      rungs.push(await netlifyReadSiteEnv(consent, key));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "netlify.read-site-env",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated env read blocked: ${exc.reason}`,
            evidence: { reason: exc.reason, manual: true, safe_curl: READ_SITE_ENV_CURL },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "netlify",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /api/v1/user` is the whoami — confirms identity and ownership. */
async function netlifyUser(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "netlify.user";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.netlify.com/api/v1/user", {
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

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${body["full_name"] ?? body["email"] ?? "unknown"} (id ${body["id"]})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      email: body["email"] ?? null,
      full_name: body["full_name"] ?? null,
    },
  });
}

/**
 * SAFE: `GET /api/v1/sites` enumerates every reachable site — depth across
 * deployments (names, custom domains, admin urls). TruffleHog's verify call.
 */
async function netlifyListSites(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "netlify.list-sites";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.netlify.com/api/v1/sites", {
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
      detail: `could not list sites (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as unknown;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const sites = Array.isArray(body) ? (body as Record<string, unknown>[]) : [];
  // Summarise reach, do not dump: keep names/domains/account ids only.
  const names = sites.map((s) => s["name"]).filter((v): v is string => typeof v === "string");
  const customDomains = sites
    .map((s) => s["custom_domain"])
    .filter((v): v is string => typeof v === "string" && v.length > 0);
  const accountIds = [
    ...new Set(sites.map((s) => s["account_id"]).filter((v): v is string => typeof v === "string")),
  ];

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `token reaches ${sites.length} site(s)${names.length > 0 ? `: ${names.slice(0, 10).join(", ")}` : ""}`,
    evidence: {
      status: resp.status,
      site_count: sites.length,
      site_names: names.slice(0, 25),
      custom_domains: customDomains.slice(0, 25),
      account_ids: accountIds,
    },
  });
}

/**
 * The exact safe curl an operator runs by hand for the gated env read. The
 * live secret stays a `$KEY` placeholder and the unfillable `ACCOUNT_ID` is
 * left for the operator to substitute (from `GET /api/v1/accounts`).
 */
const READ_SITE_ENV_CURL =
  "curl -sS -X GET " +
  "-H 'Authorization: Bearer $KEY' " +
  "'https://api.netlify.com/api/v1/accounts/ACCOUNT_ID/env'";

/**
 * GATED + MANUAL: read account/site build environment variables.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and nothing happens. Even *with* consent this rung
 * never fires a live request: its URL needs an `ACCOUNT_ID` the engine cannot
 * fill, so it emits the copy-pasteable safe curl (secret as `$KEY`) instead.
 * This reads sensitive secret material (downstream API keys), which is exactly
 * why it is gated.
 */
export const netlifyReadSiteEnv = gated(
  "netlify.read-site-env",
  async (_consent: Consent, _key: string): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "netlify.read-site-env",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL: needs an ACCOUNT_ID (from GET /api/v1/accounts) or site_id scope; " +
        `run this by hand once you have one: ${READ_SITE_ENV_CURL}`,
      evidence: { manual: true, safe_curl: READ_SITE_ENV_CURL },
    });
  },
);

register(["Netlify"], (finding, consent) => netlifyLadder(finding, consent));
