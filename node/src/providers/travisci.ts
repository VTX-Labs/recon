/**
 * Capability ladder for Travis CI API access tokens.
 *
 * Travis tokens authenticate via the `Authorization: token {key}` header (with
 * `Travis-API-Version: 3`) against the v3 REST API at `api.travis-ci.com`.
 * TruffleHog surfaces them under the `TravisCI` detector. The token has no
 * self-identifying standalone shape, so routing relies on the detector rather
 * than a key regex. The ladder climbs:
 *
 * - **`whoami`** (SAFE) — `GET /user` confirms the token authenticates and
 *   returns the current user's login / id / account info. This is exactly the
 *   endpoint TruffleHog hits to verify the credential, so a success here is the
 *   ground truth that the key is live.
 * - **`list-repos`** (SAFE) — `GET /repos` lists every repository the token can
 *   administer / build (the reachable resource set), proving depth beyond bare
 *   identity without changing anything.
 * - **`trigger-build`** (GATED) — `POST /repo/{repository.id}/requests` would
 *   queue a build request on a reachable repo, executing CI (arbitrary code in
 *   the build environment) and consuming build minutes — state-changing and
 *   billable, the real impact of a leaked Travis token. Its URL needs a
 *   `{repository.id}` the engine cannot supply, so it is never auto-fired: it
 *   is rendered as a MANUAL gated rung with a safe curl that keeps the secret
 *   as `$KEY`.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false`. The raw token is held only transiently for the HTTP
 * call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

// Travis v3 requires these headers on every request; the API version pins the
// response schema and the explicit User-Agent is required by the API gateway.
const TRAVIS_API_VERSION = "3";
const USER_AGENT = "vtx-recon";

function authHeaders(key: string): Record<string, string> {
  return {
    Authorization: `token ${key}`,
    "Travis-API-Version": TRAVIS_API_VERSION,
    "User-Agent": USER_AGENT,
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
 * Travis CI ladder: SAFE identity (`/user`) -> SAFE reachable repos
 * (`/repos`) -> MANUAL gated `trigger-build`.
 */
export async function travisciLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await travisciWhoami(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await travisciListRepos(key, fetchImpl));
    // trigger-build is GATED *and* needs a {repository.id} the engine cannot
    // fill, so it is never auto-fired: emit a MANUAL gated note with a safe
    // curl (secret stays $KEY).
    rungs.push(travisciTriggerBuildManual());
  }

  return new LadderResult({
    finding,
    provider: "travisci",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /user` confirms the token and returns the current user's id /
 * login / name. This is the exact endpoint TruffleHog verifies against.
 */
async function travisciWhoami(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "travisci.whoami";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.travis-ci.com/user", {
      headers: authHeaders(key),
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
    detail: `authenticated as ${body["login"]} (id ${body["id"]})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      login: body["login"] ?? null,
      name: body["name"] ?? null,
    },
  });
}

/**
 * SAFE: `GET /repos` lists every repository the token can administer / build —
 * the reachable resource set / blast radius — without changing anything.
 */
async function travisciListRepos(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "travisci.list-repos";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.travis-ci.com/repos", {
      headers: authHeaders(key),
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
      detail: `could not list repos (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // Travis v3 wraps the collection: { repositories: [...] }.
  const repositories = Array.isArray(body["repositories"])
    ? (body["repositories"] as Record<string, unknown>[])
    : [];
  // Summarise the reachable repos without dumping the whole payload: the
  // slugs are enough to size the blast radius.
  const slugs = repositories
    .map((r) => (r["slug"] ?? r["name"]) as string | undefined)
    .filter((s): s is string => typeof s === "string");

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `token reaches ${repositories.length} repo(s): ${
      slugs.length > 0 ? slugs.join(", ") : "(none)"
    }`,
    evidence: {
      status: resp.status,
      repo_count: repositories.length,
      slugs,
    },
  });
}

/**
 * MANUAL (GATED-tier): `POST /repo/{repository.id}/requests`.
 *
 * Triggering a build queues a build request that executes CI (arbitrary code
 * execution in the build environment) and consumes build minutes (billable).
 * The URL needs a `{repository.id}` the engine cannot fill, so this rung is
 * NEVER auto-fired. It is recorded as a manual, blocked GATED note carrying a
 * copy-pasteable curl whose secret stays `$KEY` and whose repository id stays a
 * placeholder for the operator to fill in deliberately.
 */
function travisciTriggerBuildManual(): ProbeResult {
  const name = "travisci.trigger-build";
  const safeCurl =
    'curl -sS -X POST -H "Authorization: token $KEY" -H "Travis-API-Version: 3" ' +
    '-H "Content-Type: application/json" ' +
    '"https://api.travis-ci.com/repo/{repository.id}/requests"';
  return new ProbeResult({
    name,
    tier: ProbeTier.GATED,
    success: false,
    blocked: true,
    detail:
      "MANUAL gated rung: triggering a build is billable and executes CI " +
      "(arbitrary code execution). The {repository.id} cannot be auto-filled, " +
      `so this is never auto-fired; run it by hand only when authorized: ${safeCurl}`,
    evidence: { manual: true, billable: true, safe_curl: safeCurl },
  });
}

register(["TravisCI"], (finding, consent) => travisciLadder(finding, consent));
