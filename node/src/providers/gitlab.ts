/**
 * GitLab capability ladder — prove depth of access for a leaked PAT.
 *
 * Handles TruffleHog `GitLab` findings. A GitLab personal access token
 * (`glpat-...`) authenticates with the `PRIVATE-TOKEN` header. Two SAFE rungs:
 *
 *   1. `gitlab.user`         `GET /api/v4/user` — confirms identity. Decides
 *      VALID vs DENIED. Read-only, idempotent.
 *   2. `gitlab.token.scopes` `GET /api/v4/personal_access_tokens/self` — reveals
 *      the token's exact scopes (depth of access) without exercising any of
 *      them. Read-only.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY, and the ladder
 * never throws across its public boundary: failures become a {@link ProbeResult}
 * with `success=false`. The raw token is held only transiently for the HTTP call
 * and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["GitLab"] as const;

const API_BASE = "https://gitlab.com/api/v4";

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

/** GitLab ladder: SAFE identity (/user) -> SAFE token scopes (self). */
export async function gitlabLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const token = finding.raw;

  const identity = await gitlabUser(token, options.fetchImpl);
  rungs.push(identity);
  // Only probe depth if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await gitlabTokenScopes(token, options.fetchImpl));
  }

  return new LadderResult({
    finding,
    provider: "gitlab",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /api/v4/user` confirms identity. */
async function gitlabUser(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "gitlab.user";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/user`, {
      headers: { "PRIVATE-TOKEN": token },
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
    detail: `authenticated as ${body["username"]} (id ${body["id"]})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      username: body["username"] ?? null,
      is_admin: body["is_admin"] ?? null,
    },
  });
}

/** SAFE: `GET /api/v4/personal_access_tokens/self` reveals scopes. */
async function gitlabTokenScopes(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "gitlab.token.scopes";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/personal_access_tokens/self`, {
      headers: { "PRIVATE-TOKEN": token },
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
      detail: `could not read token scopes (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const scopes = (body["scopes"] as string[] | undefined) ?? [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `token scopes: ${scopes.length > 0 ? scopes.join(", ") : "(none)"}`,
    evidence: { status: resp.status, scopes, active: body["active"] ?? null },
  });
}

register([...DETECTORS], (finding, consent) => gitlabLadder(finding, consent));
