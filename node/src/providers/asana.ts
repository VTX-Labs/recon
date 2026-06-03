/**
 * Asana capability ladder — prove depth of access for a leaked Asana token.
 *
 * Handles TruffleHog `AsanaPersonalAccessToken` and `AsanaOauth` findings. Both
 * authenticate the same way — `Authorization: Bearer <token>` against the Asana
 * REST API at `https://app.asana.com/api/1.0` — so one ladder serves both.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `users-me` `GET /users/me` — whoami. Returns the token owner (gid, name,
 *      email) plus the workspaces they belong to. Read-only, idempotent,
 *      non-billable. SAFE.
 *   2. `list-workspaces` `GET /workspaces` — reachable-data depth: enumerates
 *      every workspace/organization the token can reach, proving the blast radius
 *      of accessible projects. Read-only. SAFE.
 *   3. `list-workspace-users` `GET /users?workspace={workspace_gid}` — IMPACT:
 *      reads the directory of all users (names, emails) in a workspace —
 *      third-party PII exposure. Read-only but reads org-member PII, so GATED.
 *      The URL needs a `{workspace_gid}` the engine cannot fill, so even with
 *      consent it is rendered as a MANUAL blocked safe-curl note (never
 *      auto-fired) — an operator supplies a gid from the prior rung and runs it
 *      by hand.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY, and never throws
 * across the public boundary: failures become a {@link ProbeResult} with
 * `success=false`. The raw secret is held only transiently for the HTTP call and
 * never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (matched case-insensitively). */
export const DETECTORS = ["AsanaPersonalAccessToken", "AsanaOauth"] as const;

const API_BASE = "https://app.asana.com/api/1.0";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
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
 * Run the ordered Asana capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle). Runs
 * two SAFE read-only rungs (identity, then workspace enumeration), then the
 * GATED PII directory rung — which is additionally MANUAL because its URL needs a
 * `{workspace_gid}` the engine cannot fill. Never throws across this boundary.
 */
export async function asanaLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: users-me (SAFE) — identity / whoami ---------------------------
  const identity = await asanaUsersMe(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-workspaces (SAFE) — reachable-data blast radius --------
    rungs.push(await asanaListWorkspaces(key, fetchImpl));

    // --- Rung 3: list-workspace-users (GATED, manual safe-curl) -------------
    // Reads org-member PII. The gated() wrapper enforces consent first, so
    // without --prove + --i-am-authorized the rung is recorded as blocked. Even
    // with consent it stays MANUAL (URL needs {workspace_gid} the engine cannot
    // fill), so it never fires a live request.
    rungs.push(await maybeListWorkspaceUsers(consent));
  }

  return new LadderResult({
    finding,
    provider: "asana",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- SAFE rungs --------------------------------------------------------------

/**
 * SAFE: `GET /users/me` confirms the token and returns the owner's identity.
 *
 * This is the whoami rung — a 200 returns the token owner (gid, name, email) and
 * the workspaces they belong to. Read-only, idempotent, non-billable.
 */
async function asanaUsersMe(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "users-me";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/users/me`, {
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

  const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
  const workspaces = (data["workspaces"] as Array<Record<string, unknown>> | undefined) ?? [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `authenticated as ${data["name"] ?? "?"} (gid ${data["gid"] ?? "?"}) ` +
      `in ${workspaces.length} workspace(s)`,
    evidence: {
      status: resp.status,
      gid: data["gid"] ?? null,
      name: data["name"] ?? null,
      email: data["email"] ?? null,
      workspace_count: workspaces.length,
    },
  });
}

/**
 * SAFE: `GET /workspaces` enumerates every workspace the token can reach.
 *
 * Reachable-data depth — listing the workspaces/organizations the token can see
 * proves the blast radius of accessible projects without touching any of them.
 * Read-only.
 */
async function asanaListWorkspaces(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-workspaces";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/workspaces`, {
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
      detail: `could not list workspaces (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const data = (body["data"] as Array<Record<string, unknown>> | undefined) ?? [];
  // Keep non-secret identifiers only: gids + names map the reachable surface.
  const workspaces = data.map((w) => ({ gid: w["gid"] ?? null, name: w["name"] ?? null }));
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `token reaches ${workspaces.length} workspace(s): ${
      workspaces.map((w) => w.name ?? w.gid).join(", ") || "(none)"
    }`,
    evidence: {
      status: resp.status,
      workspace_count: workspaces.length,
      workspaces,
    },
  });
}

// --- gated (manual) rung -----------------------------------------------------

/** Safe curl for the manual gated list-workspace-users rung (secret kept as $KEY). */
function listWorkspaceUsersSafeCurl(): string {
  return (
    `curl -s '${API_BASE}/users?workspace=WORKSPACE_GID' ` +
    '-H "Accept: application/json" ' +
    '-H "Authorization: Bearer $KEY"'
  );
}

/**
 * GATED (manual): `GET /users?workspace={workspace_gid}` reads the directory of
 * all users (names, emails) in a workspace — third-party PII exposure.
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with consent this rung is MANUAL: the URL needs a
 * `{workspace_gid}` the engine cannot fill (an operator supplies one from the
 * prior `list-workspaces` rung), so it never fires a live request — it only
 * returns a safe curl (secret kept as `$KEY`) for an operator to run by hand.
 */
export const asanaGatedListWorkspaceUsers = gated(
  "asana.list-workspace-users",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "list-workspace-users";
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: reads every user (names, emails) in a workspace — third-party PII. " +
        "Needs a {workspace_gid} from the prior list-workspaces rung, which the engine " +
        "cannot fill, so run the safe curl by hand to exercise the PII read",
      evidence: {
        manual: true,
        success_status: [200],
        safe_curl: listWorkspaceUsersSafeCurl(),
      },
    });
  },
);

/**
 * Attempt the gated list-workspace-users rung; report it as blocked when consent
 * is absent.
 *
 * The gating happens inside {@link asanaGatedListWorkspaceUsers}. Here we
 * translate the boundary's exception into a non-fatal `blocked` ProbeResult so
 * the ladder never throws; the safe curl is still surfaced so an authorized
 * operator can run the PII read by hand.
 */
async function maybeListWorkspaceUsers(consent: Consent): Promise<ProbeResult> {
  try {
    return await asanaGatedListWorkspaceUsers(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "list-workspace-users",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: {
          manual: true,
          reason: exc.reason,
          safe_curl: listWorkspaceUsersSafeCurl(),
        },
      });
    }
    throw exc;
  }
}

register([...DETECTORS], (finding, consent) => asanaLadder(finding, consent));
