/**
 * Sentry capability ladder — prove depth of access for a leaked auth token.
 *
 * Handles TruffleHog `SentryToken` (modern user auth tokens, `sntryu_<64 hex>`)
 * and `SentryOrgToken` (org tokens, `sntrys_eyJ<base64>`). Both authenticate the
 * same way: `Authorization: Bearer <token>` against `https://sentry.io/api/0`.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `list-organizations`  `GET /organizations/` — TruffleHog's ACTUAL
 *      verification endpoint for both user and org tokens. 200 = live token,
 *      403 = valid token lacking org scope, 401 = revoked. Read-only; this is
 *      the rung that decides VALID vs DENIED and maps blast radius (which orgs
 *      the token can reach). The unverified `/auth/validate/` rung was dropped:
 *      it is not TruffleHog's path and was `endpoint_verified:false`.
 *   2. `list-org-projects`   `GET /organizations/{organization_slug}/projects/`
 *      — lists the projects (metadata, DSNs) within a reachable org, proving
 *      depth into the monitoring config without touching event data. Read-only,
 *      BUT its URL needs an `{organization_slug}` the engine cannot fill, so it
 *      is rendered as a MANUAL safe-curl note (no live call) with the secret
 *      kept as `$KEY`.
 *   3. `read-project-issues` `GET /projects/{organization_slug}/{project_slug}/issues/`
 *      — GATED. Reads captured issues/error events; error payloads routinely
 *      contain third-party PII, request bodies, headers, tokens and stack
 *      traces, so reading them exposes customer data. Its URL needs two slugs
 *      the engine cannot fill, so even with consent it is a MANUAL safe-curl
 *      note: never auto-fired, always rendered as a blocked/manual rung.
 *
 * Every rung is ordered (identity first, then depth), the live rung is a
 * READ-ONLY GET, and the ladder never throws across its public boundary:
 * failures become a {@link ProbeResult} with `success=false`. The raw token is
 * held only transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["SentryToken", "SentryOrgToken"] as const;

const API_BASE = "https://sentry.io/api/0";

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

/** Standard Sentry bearer header for a user/org auth token. */
function bearer(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}` };
}

/**
 * Run the ordered Sentry capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs `list-organizations` first (TruffleHog's verification endpoint) and
 * only descends if the token authenticated. The deeper rungs both embed slugs
 * the engine cannot fill, so they are emitted as manual safe-curl notes rather
 * than live calls. The `read-project-issues` rung is additionally GATED. Never
 * throws across this boundary.
 */
export async function sentryLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: list-organizations (SAFE) — decides live/dead -----------------
  const identity = await listOrganizations(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-org-projects (SAFE, manual safe-curl) ------------------
    // The URL embeds an {organization_slug} the engine cannot fill, so this
    // never fires a live request: it is rendered as a manual note.
    rungs.push(listOrgProjectsManual());

    // --- Rung 3: read-project-issues (GATED, manual safe-curl) ---------------
    // The URL embeds two slugs the engine cannot fill, so this never fires a
    // live request. The gated() wrapper still enforces consent first, so
    // without --prove + --i-am-authorized the rung is recorded as blocked.
    rungs.push(await maybeReadProjectIssues(consent));
  }

  return new LadderResult({
    finding,
    provider: "sentry",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/**
 * SAFE: `GET /organizations/` — TruffleHog's verification endpoint.
 *
 * 200 = live token (lists the orgs it can reach, mapping blast radius);
 * 403 = a valid token that lacks org scope; 401 = revoked. Read-only.
 */
async function listOrganizations(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-organizations";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/organizations/`, {
      headers: bearer(key),
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
      detail: `token rejected or lacking org scope (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as unknown;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // Sentry returns a bare JSON array of organization objects.
  const orgs = Array.isArray(body) ? (body as unknown[]) : [];
  // Record only non-secret identifiers (org slugs/names), never raw payloads.
  const slugs = orgs
    .filter((o): o is Record<string, unknown> => isObject(o) && Boolean(o["slug"]))
    .map((o) => o["slug"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      slugs.length > 0
        ? `${slugs.length} organization(s) reachable: ${slugs.slice(0, 5).join(", ")}`
        : "token authenticates but reaches no organizations",
    evidence: {
      status: resp.status,
      organization_count: slugs.length,
      organization_slugs_sample: slugs.slice(0, 25),
    },
  });
}

/**
 * SAFE (manual): `GET /organizations/{organization_slug}/projects/` lists the
 * projects (metadata, DSNs) within a reachable org.
 *
 * Read-only, but the URL needs an `{organization_slug}` from list-organizations
 * that the engine cannot fill, so this never fires a live request — it only
 * returns a safe curl (with the secret kept as `$KEY`) for an operator to run
 * by hand.
 */
function listOrgProjectsManual(): ProbeResult {
  return new ProbeResult({
    name: "list-org-projects",
    tier: ProbeTier.SAFE,
    success: false,
    detail:
      "manual rung: needs an {organization_slug} from list-organizations; run the safe curl by hand to enumerate projects/DSNs",
    evidence: { manual: true, safe_curl: listOrgProjectsSafeCurl() },
  });
}

/** The safe curl printed for the manual list-org-projects rung (secret as $KEY). */
function listOrgProjectsSafeCurl(): string {
  return (
    "curl " +
    `'${API_BASE}/organizations/ORGANIZATION_SLUG/projects/' ` +
    '-H "Authorization: Bearer $KEY"'
  );
}

// --- gated (manual) rung -----------------------------------------------------

/**
 * GATED: `GET /projects/{organization_slug}/{project_slug}/issues/` reads
 * captured issues/error events.
 *
 * Error payloads routinely contain third-party PII (request bodies, headers,
 * tokens, stack traces), so reading them exposes customer data — hence GATED.
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with consent this rung is MANUAL: the URL needs two
 * slugs the engine cannot fill, so it never fires a live request — it only
 * returns a safe curl (with the secret kept as `$KEY`) for an operator to run by
 * hand. The public ladder records it as a blocked/manual note either way.
 */
export const sentryGatedReadIssues = gated(
  "sentry.read-project-issues",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "read-project-issues";
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: needs {organization_slug}/{project_slug} from list-org-projects; run the safe curl by hand to read third-party PII",
      evidence: { manual: true, safe_curl: readIssuesSafeCurl() },
    });
  },
);

/** The safe curl printed for the manual gated read-project-issues rung (secret as $KEY). */
function readIssuesSafeCurl(): string {
  return (
    "curl " +
    `'${API_BASE}/projects/ORGANIZATION_SLUG/PROJECT_SLUG/issues/' ` +
    '-H "Authorization: Bearer $KEY"'
  );
}

/**
 * Attempt the gated issues-read rung; report it as blocked when consent is absent.
 *
 * The gating happens inside {@link sentryGatedReadIssues}. Here we translate the
 * boundary's exception into a non-fatal `blocked` ProbeResult so the ladder never
 * throws; the safe curl is still surfaced so an authorized operator can run the
 * PII-reading step by hand.
 */
async function maybeReadProjectIssues(consent: Consent): Promise<ProbeResult> {
  try {
    return await sentryGatedReadIssues(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "read-project-issues",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: readIssuesSafeCurl() },
      });
    }
    throw exc;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register([...DETECTORS], (finding, consent) => sentryLadder(finding, consent));
