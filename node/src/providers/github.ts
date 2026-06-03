/**
 * GitHub capability ladder — prove depth of access for a leaked PAT.
 *
 * Handles TruffleHog `Github` findings: classic `ghp_` / `gho_` tokens,
 * fine-grained `github_pat_` tokens, and OAuth `gho_` tokens. Every rung here
 * is a READ-ONLY `GET`; no rung creates, deletes, or mutates anything, so the
 * whole safe ladder is SAFE by construction.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `identity`      `GET /user` — does the token authenticate? Who is it?
 *   2. `classic_scopes` read `X-OAuth-Scopes` from the `/user` response.
 *      Classic PATs/OAuth tokens advertise scopes in this header; fine-grained
 *      PATs do **not**, so we detect fine-grained behaviourally.
 *   3. `dangerous_scopes` flag high-impact scopes a classic token carries.
 *   4. `private_repos`  `GET /user/repos?visibility=private`.
 *   5. `org_membership` `GET /user/orgs`.
 *
 * There is intentionally **no GATED rung** in GitHub's safe ladder. To still
 * exercise — and to *prove* the safety boundary is wired — this module defines
 * one demonstration GATED probe, {@link gatedWriteProbe}, which would change
 * state (a `PUT`) and is unreachable without `--prove` + `--i-am-authorized`.
 * The ladder calls it through the guard so a consented run can climb to PROVEN.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Github", "GitHub", "GithubApp", "GitHubOauth2"] as const;

export const API_BASE = "https://api.github.com";
const TIMEOUT_MS = 15_000;

// Scopes that meaningfully escalate impact if a classic token carries them.
const DANGEROUS_SCOPES: ReadonlySet<string> = new Set([
  "repo",
  "delete_repo",
  "workflow",
  "write:packages",
  "delete:packages",
  "admin:org",
  "write:org",
  "admin:repo_hook",
  "admin:org_hook",
  "admin:public_key",
  "admin:gpg_key",
  "admin:enterprise",
  "manage_runners:org",
  "user",
  "write:discussion",
  "codespace",
]);

function headers(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "vtx-recon",
  };
}

/** Parse the comma-separated `X-OAuth-Scopes` header into a clean list. */
function parseScopes(headerValue: string | null | undefined): string[] {
  if (!headerValue) {
    return [];
  }
  return headerValue
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Run the ordered GitHub capability ladder for a single finding.
 *
 * Never throws across the public boundary: any error is captured into a
 * {@link ProbeResult} and the worst outcome is a `DENIED` / `N/A` verdict. The
 * authorized scope is required (the whole ladder refuses to run without it).
 */
export async function githubLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  // Laddering at all — even the safe tier — requires a named scope. This
  // throws ScopeRequired, a *configuration* failure (not a probe failure), so
  // we let it out for the CLI to map to an exit code.
  const scope = consent.requireLadderScope();
  const fetchImpl = options.fetchImpl;

  const result = new LadderResult({
    finding,
    provider: "github",
    verdict: Verdict.NA,
    authorizedScope: scope,
  });
  const token = finding.raw;

  // --- Rung 1: identity (SAFE) ---
  const identity = await rungIdentity(token, fetchImpl);
  result.rungs.push(identity);
  if (!identity.success) {
    const status = identity.evidence["status"];
    result.verdict = status === 401 || status === 403 ? Verdict.DENIED : Verdict.NA;
    return result;
  }

  // Token is live: at minimum this is VALID. Safe rungs may add depth.
  result.verdict = Verdict.VALID;
  const login = identity.evidence["login"];

  // --- Rung 2: classic scopes header (SAFE) ---
  const { rung: scopesRung, scopes, isFinegrained } = rungClassicScopes(identity);
  result.rungs.push(scopesRung);

  // --- Rung 3: dangerous scopes (SAFE) ---
  result.rungs.push(rungDangerousScopes(scopes, isFinegrained));

  // --- Rung 4: private repos reachable (SAFE) ---
  result.rungs.push(await rungPrivateRepos(token, fetchImpl));

  // --- Rung 5: org membership walk (SAFE) ---
  result.rungs.push(await rungOrgMembership(token, fetchImpl));

  // --- Optional gated rung: only reachable with full consent ---
  const gatedRung = await maybeGatedRung(token, consent, login, fetchImpl);
  result.rungs.push(gatedRung);
  if (gatedRung.success && !gatedRung.blocked) {
    result.verdict = Verdict.PROVEN;
  }

  return result;
}

// --- individual rungs --------------------------------------------------------

/** SAFE: `GET /user` to confirm the token is live and learn the identity. */
async function rungIdentity(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const rung = new ProbeResult({ name: "identity", tier: ProbeTier.SAFE, success: false });
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/user`, { headers: headers(token), timeoutMs: TIMEOUT_MS, fetchImpl });
  } catch (exc) {
    rung.detail = `request failed: ${errName(exc)}`;
    rung.evidence = { error: errMessage(exc) };
    return rung;
  }

  rung.evidence["status"] = resp.status;
  // Capture the scope-bearing headers now (non-secret); used by rung 2.
  rung.evidence["x_oauth_scopes"] = resp.headers.get("x-oauth-scopes");
  rung.evidence["x_accepted_oauth_scopes"] = resp.headers.get("x-accepted-oauth-scopes");

  if (resp.status !== 200) {
    rung.detail = `token did not authenticate (HTTP ${resp.status})`;
    return rung;
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  const login = body && typeof body === "object" ? body["login"] : null;
  rung.evidence["login"] = login ?? null;
  rung.evidence["account_id"] = body && typeof body === "object" ? (body["id"] ?? null) : null;
  rung.success = true;
  rung.detail = login ? `authenticated as ${JSON.stringify(login)}` : "authenticated";
  return rung;
}

/** SAFE: read `X-OAuth-Scopes` from the identity response. */
function rungClassicScopes(identity: ProbeResult): {
  rung: ProbeResult;
  scopes: string[];
  isFinegrained: boolean;
} {
  const rung = new ProbeResult({ name: "classic_scopes", tier: ProbeTier.SAFE, success: false });
  const rawHeader = identity.evidence["x_oauth_scopes"];
  const scopes = parseScopes(typeof rawHeader === "string" ? rawHeader : null);

  // Header present (even if empty string "") => classic/OAuth token.
  // Header absent (null) on an authenticated token => fine-grained PAT.
  const headerPresent = rawHeader !== null && rawHeader !== undefined;
  const isFinegrained = !headerPresent;

  rung.evidence["scopes"] = scopes;
  rung.evidence["token_type"] = isFinegrained ? "fine-grained" : "classic";
  if (isFinegrained) {
    rung.success = true;
    rung.detail =
      "fine-grained PAT: no X-OAuth-Scopes header (access is per-resource; probe behaviourally)";
  } else if (scopes.length > 0) {
    rung.success = true;
    rung.detail = `classic token scopes: ${scopes.join(", ")}`;
  } else {
    rung.success = true;
    rung.detail = "classic token with no scopes granted";
  }
  return { rung, scopes, isFinegrained };
}

/** SAFE: flag high-impact scopes carried by a classic token. */
function rungDangerousScopes(scopes: string[], isFinegrained: boolean): ProbeResult {
  const rung = new ProbeResult({ name: "dangerous_scopes", tier: ProbeTier.SAFE, success: false });
  if (isFinegrained) {
    rung.detail = "n/a for fine-grained PAT (no textual scopes; gated by resource perms)";
    rung.evidence["dangerous"] = [];
    return rung;
  }

  const dangerous = scopes.filter((s) => DANGEROUS_SCOPES.has(s)).sort();
  rung.evidence["dangerous"] = dangerous;
  if (dangerous.length > 0) {
    rung.success = true;
    rung.detail = `DANGEROUS scopes present: ${dangerous.join(", ")}`;
  } else {
    rung.detail = "no dangerous scopes detected";
  }
  return rung;
}

/** SAFE: list private repositories the token can read (a GET, no writes). */
async function rungPrivateRepos(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const rung = new ProbeResult({ name: "private_repos", tier: ProbeTier.SAFE, success: false });
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/user/repos`, {
      headers: headers(token),
      params: {
        visibility: "private",
        per_page: "100",
        affiliation: "owner,collaborator,organization_member",
      },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    rung.detail = `request failed: ${errName(exc)}`;
    rung.evidence = { error: errMessage(exc) };
    return rung;
  }

  rung.evidence["status"] = resp.status;
  if (resp.status !== 200) {
    rung.detail = `could not list private repos (HTTP ${resp.status})`;
    return rung;
  }

  let repos = (await readJson(resp)) as unknown;
  if (!Array.isArray(repos)) {
    repos = [];
  }
  // Record only non-sensitive identifiers (full_name), never repo contents.
  const names = (repos as unknown[])
    .filter((r): r is Record<string, unknown> => isObject(r) && Boolean(r["full_name"]))
    .map((r) => r["full_name"]);
  rung.evidence["private_repo_count"] = names.length;
  rung.evidence["private_repos_sample"] = names.slice(0, 25);
  rung.success = names.length > 0;
  rung.detail = names.length > 0 ? `${names.length} private repo(s) reachable` : "no private repos reachable";
  return rung;
}

/** SAFE: walk org membership reachable with the token (a GET, no writes). */
async function rungOrgMembership(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const rung = new ProbeResult({ name: "org_membership", tier: ProbeTier.SAFE, success: false });
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/user/orgs`, {
      headers: headers(token),
      params: { per_page: "100" },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    rung.detail = `request failed: ${errName(exc)}`;
    rung.evidence = { error: errMessage(exc) };
    return rung;
  }

  rung.evidence["status"] = resp.status;
  if (resp.status !== 200) {
    rung.detail = `could not list orgs (HTTP ${resp.status})`;
    return rung;
  }

  let orgs = (await readJson(resp)) as unknown;
  if (!Array.isArray(orgs)) {
    orgs = [];
  }
  const logins = (orgs as unknown[])
    .filter((o): o is Record<string, unknown> => isObject(o) && Boolean(o["login"]))
    .map((o) => o["login"] as string);
  rung.evidence["org_count"] = logins.length;
  rung.evidence["orgs"] = logins;
  rung.success = logins.length > 0;
  rung.detail =
    logins.length > 0 ? `member of ${logins.length} org(s): ${logins.join(", ")}` : "no org membership reachable";
  return rung;
}

// --- gated demonstration rung ------------------------------------------------

/**
 * GATED: a state-changing probe, unreachable without full consent.
 *
 * Wrapped with {@link gated}, so the safety boundary throws
 * {@link GatedProbeBlocked} *before* this body runs unless BOTH `--prove` and
 * `--i-am-authorized` were supplied. It stars a repo via a `PUT` (a write),
 * which is why it is gated and never part of the safe tier. This is the only
 * place in the GitHub provider that would change remote state, reachable only
 * through the guard.
 */
export const gatedWriteProbe = gated(
  "github.gated_write_probe",
  async (
    _consent: Consent,
    token: string,
    login: unknown,
    fetchImpl?: FetchLike,
  ): Promise<{ status: number; actor: unknown; state_changed: boolean }> => {
    const resp = await httpRequest(`${API_BASE}/user/starred/vtx-labs/authorized-probe`, {
      method: "PUT",
      headers: headers(token),
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
    return { status: resp.status, actor: login, state_changed: true };
  },
);

/**
 * Attempt the gated rung; report it as blocked when consent is absent. The
 * actual gating happens inside {@link gatedWriteProbe} (the wrapper). Here we
 * translate the boundary's exception into a non-fatal `blocked` ProbeResult so
 * the ladder never throws and the evidence bundle records the refusal.
 */
async function maybeGatedRung(
  token: string,
  consent: Consent,
  login: unknown,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const rung = new ProbeResult({ name: "gated_write_probe", tier: ProbeTier.GATED, success: false });
  let outcome: { status: number; actor: unknown; state_changed: boolean };
  try {
    outcome = await gatedWriteProbe(consent, token, login, fetchImpl);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rung.blocked = true;
      rung.detail = `gated rung blocked: ${exc.reason}`;
      rung.evidence["reason"] = exc.reason;
      return rung;
    }
    rung.detail = `gated probe request failed: ${errName(exc)}`;
    rung.evidence["error"] = errMessage(exc);
    return rung;
  }

  rung.success = outcome.status === 200 || outcome.status === 204;
  rung.detail = rung.success
    ? "STATE CHANGE EXERCISED under consent (repo starred)"
    : `gated probe ran but did not confirm (HTTP ${outcome.status})`;
  rung.evidence["status"] = outcome.status;
  rung.evidence["state_changed"] = outcome.state_changed;
  return rung;
}

/**
 * Register the GitHub ladder for all of its TruffleHog detector names.
 * Idempotent: re-registering simply overwrites with the same callable.
 */
export function registerGithub(): void {
  register([...DETECTORS], (finding, consent) => githubLadder(finding, consent));
}

// Import side-effect: wire the provider into the registry on import.
registerGithub();

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
}

function errMessage(exc: unknown): string {
  return exc instanceof Error ? exc.message : String(exc);
}
