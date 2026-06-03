/**
 * Capability ladder for HCP Terraform / Terraform Cloud personal tokens.
 *
 * A TruffleHog `TerraformCloudPersonalToken` finding has the shape
 * `<14>.atlasv1.<67>` (trigger keyword `.atlasv1.`). The token authenticates via
 * `Authorization: Bearer <token>` against the JSON:API at
 * `https://app.terraform.io/api/v2` (media type `application/vnd.api+json`).
 *
 * A leaked HCP Terraform token is catastrophic: it drives the *state* of real
 * cloud infrastructure. The ladder proves that blast radius, least -> most:
 *
 * SAFE rungs (run by default, read-only, non-billable, idempotent):
 *
 *   1. `account-details`     `GET /account/details` — identity / whoami.
 *      Confirms the token is live and names the principal (username, email, 2FA
 *      status). This is TruffleHog's own verification endpoint; it decides
 *      VALID vs DENIED.
 *   2. `list-organizations`  `GET /organizations` — enumerates the HCP Terraform
 *      organizations the token can reach: the set of infra-managing orgs in
 *      blast radius. Read-only.
 *
 * GATED rung (UNREACHABLE without BOTH `--prove` and `--i-am-authorized`):
 *
 *   * `create-run`           `POST /runs` — queues a Terraform run (a plan, and
 *     with apply a mutation of real cloud infrastructure). State-changing and
 *     effectively billable (it provisions / destroys cloud resources) — the
 *     catastrophic impact of the leaked token. The JSON:API body must reference
 *     a workspace id (from a workspace the operator chooses) that the engine
 *     cannot fill, so this rung is rendered as a MANUAL, gated safe-curl note:
 *     it never auto-fires. The note is emitted only behind the safety boundary
 *     (consent fully granted); without consent it is recorded as `blocked`.
 *
 * The public entry point is {@link terraformcloudLadder}; it never throws across
 * its boundary — every failure is captured as a {@link ProbeResult} / reflected
 * in the {@link Verdict}. Secrets are held only transiently for the HTTP call
 * and never land in evidence; the manual curl keeps the secret as `$KEY`.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

const API_BASE = "https://app.terraform.io/api/v2";

/** Standard HCP Terraform JSON:API headers carrying the bearer token. */
function headers(key: string): Record<string, string> {
  return {
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/vnd.api+json",
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
 * - The token authenticated nowhere -> DENIED.
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
 * Run the ordered HCP Terraform capability ladder for a single finding.
 *
 * Identity first (account whoami); org enumeration only if the token
 * authenticated. The gated `create-run` is a manual safe-curl note: its JSON:API
 * body needs a workspace id the engine cannot fill (and the action is
 * state-changing / billable), so it never fires a live request. Even the note is
 * gated — without full consent it is recorded as `blocked`.
 */
export async function terraformcloudLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: identity / whoami (SAFE) ---
  const identity = await terraformcloudAccountDetails(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: enumerate reachable organizations (SAFE) ---
    rungs.push(await terraformcloudListOrganizations(key, fetchImpl));

    // --- Rung 3: queue a Terraform run (GATED, MANUAL) ---
    // The JSON:API body must reference a workspace id the engine cannot fill,
    // and the action mutates real infra (state-changing / billable), so this
    // never makes a live call. The gated() wrapper still enforces consent
    // BEFORE the body runs: without --prove + scope it throws GatedProbeBlocked,
    // captured here as a `blocked` rung so the ladder never throws across the
    // boundary.
    try {
      rungs.push(await terraformcloudCreateRun(consent));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "create-run",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: { manual: true, safe_curl: SAFE_CURL_CREATE_RUN, reason: exc.reason },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "terraform-cloud",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /account/details` confirms identity (TruffleHog's verify call). */
async function terraformcloudAccountDetails(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "account-details";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/account/details`, {
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

  // JSON:API: { data: { id, type: "users", attributes: { username, email, ... } } }
  const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
  const attrs = (data["attributes"] as Record<string, unknown> | undefined) ?? {};

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${attrs["username"] ?? attrs["email"] ?? "unknown"} (id ${data["id"] ?? "?"})`,
    evidence: {
      status: resp.status,
      id: data["id"] ?? null,
      username: attrs["username"] ?? null,
      email: attrs["email"] ?? null,
      two_factor: isObject(attrs["two-factor"]) ? (attrs["two-factor"] as Record<string, unknown>)["enabled"] ?? null : null,
      is_service_account: attrs["is-service-account"] ?? null,
    },
  });
}

/** SAFE: `GET /organizations` enumerates reachable orgs (infra blast radius). */
async function terraformcloudListOrganizations(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-organizations";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/organizations`, {
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
      detail: `could not list organizations (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // JSON:API: { data: [ { id: "<org-name>", type: "organizations", ... }, ... ] }
  const data = Array.isArray(body["data"]) ? (body["data"] as unknown[]) : [];
  // The JSON:API `id` of an organization IS its name (a non-secret slug).
  const orgs = data
    .filter((o): o is Record<string, unknown> => isObject(o) && Boolean(o["id"]))
    .map((o) => o["id"] as string);

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: orgs.length > 0,
    detail:
      orgs.length > 0
        ? `${orgs.length} organization(s) reachable: ${orgs.slice(0, 10).join(", ")}`
        : "no organizations reachable",
    evidence: {
      status: resp.status,
      organization_count: orgs.length,
      organizations_sample: orgs.slice(0, 25),
    },
  });
}

/**
 * A copy/paste-safe curl the operator runs by hand once they have chosen a
 * target WORKSPACE_ID (from `GET /organizations/<org>/workspaces`). The secret
 * stays a shell variable (`$KEY`); the engine never substitutes it and no
 * state-changing request is fired automatically.
 */
const SAFE_CURL_CREATE_RUN =
  "curl -sS -X POST " +
  '-H "Authorization: Bearer $KEY" ' +
  '-H "Content-Type: application/vnd.api+json" ' +
  "-d '{\"data\":{\"type\":\"runs\",\"relationships\":{\"workspace\":{\"data\":{\"type\":\"workspaces\",\"id\":\"WORKSPACE_ID\"}}}}}' " +
  '"https://app.terraform.io/api/v2/runs"';

/**
 * GATED + MANUAL: `POST /runs` queues a Terraform run on a chosen workspace.
 *
 * A run executes a plan (and, with apply, mutates real cloud infrastructure):
 * state-changing and effectively billable (it provisions / destroys cloud
 * resources). The JSON:API request body must reference a `WORKSPACE_ID` the
 * engine cannot fill, so this rung NEVER makes a live call — it emits a manual
 * safe-curl note instead. It is still wrapped with {@link gated}: the boundary
 * runs BEFORE this body, so without BOTH `--prove` and an authorized scope it
 * throws {@link GatedProbeBlocked} and even the note is withheld (the public
 * ladder records a `blocked` rung).
 */
export const terraformcloudCreateRun = gated(
  "terraform-cloud.create-run",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "create-run",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "MANUAL gated rung: needs a WORKSPACE_ID and would queue a Terraform run " +
        "(state-changing / billable infra mutation), so no live call is made. Run " +
        "the safe curl by hand under consent to queue a run on a chosen workspace.",
      evidence: { manual: true, safe_curl: SAFE_CURL_CREATE_RUN },
    });
  },
);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register(["TerraformCloudPersonalToken"], (finding, consent) =>
  terraformcloudLadder(finding, consent),
);
