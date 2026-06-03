/**
 * Capability ladder for Figma personal access tokens (PATs).
 *
 * A Figma PAT is shaped `figd_<40+ chars of [A-Za-z0-9_-]>` and authenticates
 * via the `X-Figma-Token: <token>` header — NOT `Authorization`. TruffleHog
 * surfaces these under the `FigmaPersonalAccessToken` detector. The ladder
 * climbs (depth of access, least -> most revealing):
 *
 * - **`me`** (SAFE) — `GET /v1/me` is whoami: it returns the token owner
 *   (`id`, `email`, `handle`, account name). Confirms the token is live and
 *   reveals the identity behind it. Read-only, idempotent, non-billable. This
 *   is the rung that decides VALID vs DENIED.
 * - **`list-team-projects`** (SAFE, MANUAL) — `GET /v1/teams/{team_id}/projects`
 *   enumerates the projects within a team the token can reach, proving file /
 *   design reach beyond bare identity. Its URL embeds a `team_id` the engine
 *   cannot fill (it comes from the Figma UI/URL, not the key), so this rung is
 *   NEVER auto-fired: it is rendered as a manual safe-curl note that keeps the
 *   secret as `$KEY` for an operator to run by hand.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY, and never
 * throws across the public boundary: failures become a {@link ProbeResult} with
 * `success=false` so one dead key cannot crash a batch run. The raw token is
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

/** Figma PATs authenticate with the `X-Figma-Token` header, not `Authorization`. */
function figmaHeaders(key: string): Record<string, string> {
  return { "X-Figma-Token": key };
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
 * Run the ordered Figma capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs `me` first and only descends into the deeper rung if the token
 * authenticated. The `list-team-projects` rung's URL needs a `team_id` the
 * engine cannot fill, so it is emitted as a manual safe-curl note rather than a
 * live call. Never throws across this boundary.
 */
export async function figmaLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: me (SAFE) — decides live/dead ---------------------------------
  const identity = await figmaMe(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-team-projects (SAFE, manual safe-curl) -----------------
    // The URL embeds a {team_id} the engine cannot fill, so this never fires a
    // live request: it is rendered as a manual note with the secret kept as $KEY.
    rungs.push(figmaListTeamProjectsManual());
  }

  return new LadderResult({
    finding,
    provider: "figma",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/**
 * SAFE: `GET /v1/me` confirms the token and returns the owner identity (id,
 * email, handle, account name). Read-only, idempotent, non-billable — whoami.
 */
async function figmaMe(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "me";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.figma.com/v1/me", {
      headers: figmaHeaders(key),
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

  // Record only non-secret identity fields (id, handle, email, account name);
  // never the raw token. The handle/email are the owner's own account metadata.
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${body["handle"] ?? body["email"] ?? body["id"]} (id ${body["id"] ?? "?"})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      handle: body["handle"] ?? null,
      email: body["email"] ?? null,
      img_url: body["img_url"] ?? null,
    },
  });
}

/**
 * SAFE (MANUAL): `GET /v1/teams/{team_id}/projects` enumerates the projects in a
 * team the token can reach, proving file/design reach beyond bare identity.
 *
 * The URL needs a `team_id` the engine cannot fill (it is read from the Figma
 * UI/URL, not the credential), so this rung NEVER fires a live request — it is
 * rendered as a manual safe-curl note with the secret kept as `$KEY` for an
 * authorized operator to run by hand.
 */
function figmaListTeamProjectsManual(): ProbeResult {
  return new ProbeResult({
    name: "list-team-projects",
    tier: ProbeTier.SAFE,
    success: false,
    detail:
      "manual rung: needs a team_id from the Figma UI/URL (not in the key); run the safe curl by hand to enumerate team projects",
    evidence: { manual: true, safe_curl: listTeamProjectsSafeCurl() },
  });
}

/** The safe curl printed for the manual list-team-projects rung (secret as $KEY). */
function listTeamProjectsSafeCurl(): string {
  return (
    "curl 'https://api.figma.com/v1/teams/TEAM_ID/projects' " +
    '-H "X-Figma-Token: $KEY"'
  );
}

register(["FigmaPersonalAccessToken"], (finding, consent) => figmaLadder(finding, consent));
