/**
 * Capability ladder for Vercel access tokens (24 chars `[a-zA-Z0-9]`).
 *
 * A Vercel access token authenticates via `Authorization: Bearer <token>`
 * against the public REST API (`api.vercel.com`). Vercel PATs carry the FULL
 * permissions of the user who created them, so depth of access here is the
 * user's entire surface: every team, project, deployment, and — critically —
 * each project's decrypted environment variables (downstream API keys, DB
 * URLs, secrets). This module proves that depth with an ordered ladder.
 *
 * SAFE rungs (run by default, read-only, non-billable, idempotent):
 *
 *   1. `user`          `GET /v2/user`     — identity / whoami. Confirms the
 *      token authenticates and reveals who owns it (id, email, username).
 *   2. `list-projects` `GET /v9/projects` — enumerates every project the token
 *      can reach: depth across deployments (names, framework, linked git repos).
 *
 * GATED rung (UNREACHABLE without BOTH `--prove` and `--i-am-authorized`):
 *
 *   * `read-project-env` `GET /v9/projects/PROJECT_ID/env?decrypt=true` — dumps
 *     a project's DECRYPTED environment variables, enabling lateral movement.
 *     Its URL needs a `PROJECT_ID` (from `list-projects`) that the engine
 *     cannot fill, so this rung is rendered as a MANUAL, gated safe-curl note:
 *     it never auto-fires. The note is emitted only behind the safety boundary
 *     (consent fully granted); without consent it is recorded as `blocked`.
 *
 * The public entry point is {@link vercelLadder}; it never throws across its
 * boundary — every failure is captured as a {@link ProbeResult} / reflected in
 * the {@link Verdict}. Secrets are held only transiently for the HTTP call and
 * never land in evidence; the manual curl keeps the secret as `$KEY`.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

function headers(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}` };
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
 * Run the ordered Vercel capability ladder for a single finding.
 *
 * Identity first (whoami); depth (project enumeration) only if the token
 * authenticated. The gated env-var read is a manual safe-curl note: its URL
 * needs a PROJECT_ID the engine cannot fill, so it never fires a live request.
 * Even the note is gated — without full consent it is recorded as `blocked`.
 */
export async function vercelLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: identity / whoami (SAFE) ---
  const identity = await vercelUser(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: enumerate projects (SAFE) ---
    rungs.push(await vercelListProjects(key, fetchImpl));

    // --- Rung 3: read decrypted project env vars (GATED, MANUAL) ---
    // The URL needs a PROJECT_ID the engine cannot fill, so this never makes a
    // live call. The gated() wrapper still enforces consent BEFORE the body
    // runs: without --prove + scope it throws GatedProbeBlocked, captured here
    // as a `blocked` rung so the ladder never throws across the boundary.
    try {
      rungs.push(await vercelReadProjectEnv(consent));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "read-project-env",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: { manual: true, safe_curl: SAFE_CURL_READ_ENV, reason: exc.reason },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "vercel",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /v2/user` confirms identity (documented whoami). */
async function vercelUser(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "user";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.vercel.com/v2/user", {
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
  // Vercel wraps the payload in a `user` object on /v2/user.
  const user = (body["user"] as Record<string, unknown> | undefined) ?? body;

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${user["username"] ?? user["email"] ?? "unknown"} (id ${user["id"] ?? user["uid"] ?? "?"})`,
    evidence: {
      status: resp.status,
      id: user["id"] ?? user["uid"] ?? null,
      username: user["username"] ?? null,
      email: user["email"] ?? null,
      name: user["name"] ?? null,
    },
  });
}

/** SAFE: `GET /v9/projects` enumerates reachable projects (depth). */
async function vercelListProjects(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-projects";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.vercel.com/v9/projects", {
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
      detail: `could not list projects (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // The /v9/projects payload is `{ projects: [...], pagination: {...} }`.
  const projects = Array.isArray(body["projects"]) ? (body["projects"] as unknown[]) : [];
  const names = projects
    .filter((p): p is Record<string, unknown> => isObject(p) && Boolean(p["name"]))
    .map((p) => p["name"] as string);
  // Record only non-secret identifiers (project names + a sample of ids), no
  // contents, no env vars.
  const ids = projects
    .filter((p): p is Record<string, unknown> => isObject(p) && Boolean(p["id"]))
    .map((p) => p["id"] as string);

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: names.length > 0,
    detail:
      names.length > 0
        ? `${names.length} project(s) reachable: ${names.slice(0, 10).join(", ")}`
        : "no projects reachable",
    evidence: {
      status: resp.status,
      project_count: names.length,
      projects_sample: names.slice(0, 25),
      project_ids_sample: ids.slice(0, 25),
    },
  });
}

/**
 * A copy/paste-safe curl the operator runs by hand once they have a PROJECT_ID
 * from `list-projects`. The secret stays a shell variable (`$KEY`); the engine
 * never substitutes it and no request is fired automatically.
 */
const SAFE_CURL_READ_ENV =
  'curl -H "Authorization: Bearer $KEY" ' +
  '"https://api.vercel.com/v9/projects/PROJECT_ID/env?decrypt=true"';

/**
 * GATED + MANUAL: `GET /v9/projects/PROJECT_ID/env?decrypt=true`.
 *
 * Dumps a project's DECRYPTED environment variables (downstream API keys, DB
 * URLs, secrets). The URL contains a `PROJECT_ID` placeholder the engine
 * cannot fill, so this rung NEVER makes a live call — it emits a manual
 * safe-curl note instead. It is still wrapped with {@link gated}: the boundary
 * runs BEFORE this body, so without BOTH `--prove` and an authorized scope it
 * throws {@link GatedProbeBlocked} and even the note is withheld (the public
 * ladder records a `blocked` rung).
 */
export const vercelReadProjectEnv = gated(
  "vercel.read-project-env",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "read-project-env",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "MANUAL gated rung: needs a PROJECT_ID from list-projects, so no live " +
        "call is made. Run the safe curl by hand to dump decrypted env vars.",
      evidence: { manual: true, safe_curl: SAFE_CURL_READ_ENV },
    });
  },
);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register(["Vercel"], (finding, consent) => vercelLadder(finding, consent));
