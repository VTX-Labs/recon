/**
 * Capability ladder for CircleCI personal API tokens (`CCIPAT_...`).
 *
 * CircleCI tokens authenticate via the `Circle-Token` header against the v2
 * REST API. TruffleHog surfaces them under the `Circle` / `CircleCI` detectors
 * (modern tokens have the `CCIPAT_` prefix; legacy v1 tokens are bare 40-char
 * hex, which the key regex deliberately does not cover). The ladder climbs:
 *
 * - **`whoami`** (SAFE) — `GET /api/v2/me` confirms the token authenticates
 *   and returns the current user's id / login / name. This is exactly the
 *   endpoint TruffleHog hits to verify the credential, so a success here is
 *   the ground truth that the key is live.
 * - **`list-collaborations`** (SAFE) — `GET /api/v2/me/collaborations` lists
 *   every VCS org / collaboration the token can reach, proving the blast
 *   radius of accessible projects without changing anything.
 * - **`trigger-pipeline`** (GATED) — `POST /api/v2/project/{project-slug}/pipeline`
 *   would start a new pipeline, consuming compute credits (billable) and
 *   executing CI — i.e. arbitrary code execution in the build environment.
 *   Its URL needs a `{project-slug}` the engine cannot supply, so it is never
 *   auto-fired: it is rendered as a MANUAL gated rung with a safe curl that
 *   keeps the secret as `$KEY`.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default,
 * and never throws across the public boundary: failures become a
 * {@link ProbeResult} with `success=false`. The raw token is held only
 * transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier } from "../safety.js";
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
 * CircleCI ladder: SAFE identity (`/me`) -> SAFE reachable orgs
 * (`/me/collaborations`) -> MANUAL gated `trigger-pipeline`.
 */
export async function circleciLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await circleciWhoami(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await circleciCollaborations(key, fetchImpl));
    // trigger-pipeline is GATED *and* needs a {project-slug} the engine cannot
    // fill, so it is never auto-fired: emit a MANUAL gated note with a safe
    // curl (secret stays $KEY).
    rungs.push(circleciTriggerPipelineManual());
  }

  return new LadderResult({
    finding,
    provider: "circleci",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /api/v2/me` confirms the token and returns the current user's
 * id / login / name. This is the exact endpoint TruffleHog verifies against.
 */
async function circleciWhoami(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "circleci.whoami";
  let resp: Response;
  try {
    resp = await httpRequest("https://circleci.com/api/v2/me", {
      headers: { "Circle-Token": key, Accept: "application/json" },
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
 * SAFE: `GET /api/v2/me/collaborations` lists every VCS org / collaboration
 * the token can reach — the blast radius of accessible projects — without
 * changing anything.
 */
async function circleciCollaborations(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "circleci.list-collaborations";
  let resp: Response;
  try {
    resp = await httpRequest("https://circleci.com/api/v2/me/collaborations", {
      headers: { "Circle-Token": key, Accept: "application/json" },
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
      detail: `could not list collaborations (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as unknown;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const collaborations = Array.isArray(body) ? (body as Record<string, unknown>[]) : [];
  // Summarise the reachable orgs without dumping the whole payload: the
  // VCS slugs are enough to size the blast radius.
  const slugs = collaborations
    .map((c) => (c["slug"] ?? c["name"] ?? c["vcs_type"]) as string | undefined)
    .filter((s): s is string => typeof s === "string");

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `token reaches ${collaborations.length} collaboration(s): ${
      slugs.length > 0 ? slugs.join(", ") : "(none)"
    }`,
    evidence: {
      status: resp.status,
      collaboration_count: collaborations.length,
      slugs,
    },
  });
}

/**
 * MANUAL (GATED-tier): `POST /api/v2/project/{project-slug}/pipeline`.
 *
 * Triggering a pipeline consumes compute credits (billable) and executes CI —
 * arbitrary code execution in the build environment. The URL needs a
 * `{project-slug}` the engine cannot fill, so this rung is NEVER auto-fired.
 * It is recorded as a manual, blocked GATED note carrying a copy-pasteable
 * curl whose secret stays `$KEY` and whose project slug stays a placeholder
 * for the operator to fill in deliberately.
 */
function circleciTriggerPipelineManual(): ProbeResult {
  const name = "circleci.trigger-pipeline";
  const safeCurl =
    'curl -sS -X POST -H "Circle-Token: $KEY" -H "Content-Type: application/json" ' +
    '"https://circleci.com/api/v2/project/{project-slug}/pipeline"';
  return new ProbeResult({
    name,
    tier: ProbeTier.GATED,
    success: false,
    blocked: true,
    detail:
      "MANUAL gated rung: triggering a pipeline is billable and executes CI " +
      "(arbitrary code execution). The {project-slug} cannot be auto-filled, " +
      `so this is never auto-fired; run it by hand only when authorized: ${safeCurl}`,
    evidence: { manual: true, billable: true, safe_curl: safeCurl },
  });
}

register(["Circle", "CircleCI"], (finding, consent) => circleciLadder(finding, consent));
