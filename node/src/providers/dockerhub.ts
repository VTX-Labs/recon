/**
 * Docker Hub capability ladder — prove depth of access for a leaked PAT.
 *
 * Handles TruffleHog `Dockerhub` / `Docker` findings. A Docker Hub personal
 * access token has the shape `dckr_pat_<27>`. Crucially, the PAT is **not** a
 * Bearer credential on its own: the management API at `hub.docker.com` is driven
 * by a short-lived JWT that you must first mint by exchanging
 * `username` + PAT at `POST /v2/auth/token`. That username is **not** carried in
 * the token, and the JWT itself is produced only by that exchange — both are
 * placeholders the engine cannot fill (`<username>`, `{jwt}`).
 *
 * Per the manual-rung rule, that means **every rung is MANUAL**: no rung issues
 * a live call. Each rung instead emits a copy-pasteable, safe `curl` an operator
 * can run by hand, with the PAT kept as a `$KEY` placeholder and the minted JWT
 * kept as `$JWT`, so nothing sensitive is ever stored.
 *
 * Ordered ladder (identity first, then depth):
 *
 *   1. `auth-token-exchange` — SAFE/MANUAL. `POST /v2/auth/token` exchanges
 *      `{"identifier":"<username>","secret":"$KEY"}` for a JWT. A 200 proves the
 *      PAT is live and the decoded JWT scope claim reveals the permission level
 *      (read / read-write / read-write-delete) plus the bound username.
 *      Idempotent session mint, no state change, non-billable. MANUAL because the
 *      paired `<username>` is not in the token.
 *   2. `list-namespace-repos` — SAFE/MANUAL. `GET /v2/namespaces/{namespace}/
 *      repositories` lists the public+private repositories under a reachable
 *      namespace using the JWT from rung 1 — read-only depth of access. MANUAL
 *      (needs the `{jwt}` and a `{namespace}`).
 *   3. `delete-repository` — GATED/MANUAL. `DELETE /v2/repositories/{namespace}/
 *      {repository}` wipes a repository (only succeeds for delete-scoped PATs).
 *      Destructive, state-changing supply-chain impact (wipe/hijack images).
 *      Routed through {@link gated} so it is structurally unreachable without
 *      BOTH `--prove` and `--i-am-authorized "<scope>"`; even with consent it
 *      never auto-fires (placeholders cannot be filled) — it renders the safe
 *      curl for the operator.
 *
 * The ladder never throws across its public boundary: every failure becomes a
 * {@link ProbeResult}. Secrets are never persisted; only non-secret values land
 * in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Dockerhub", "Docker"] as const;

const API_BASE = "https://hub.docker.com";

// --------------------------------------------------------------------------- //
// safe-curl rendering (no live call is ever made by this provider)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl. The PAT is kept as the `$KEY` placeholder and the
 * minted JWT as `$JWT`; `{namespace}` / `{repository}` are left for the operator
 * to substitute. The string never contains a live secret, so it is safe to print
 * and to store.
 */
function safeCurl(args: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): string {
  const parts = ["curl", "-sS", "-X", args.method];
  for (const [headerName, headerValue] of Object.entries(args.headers)) {
    parts.push("-H", shquote(`${headerName}: ${headerValue}`));
  }
  if (args.body !== undefined) {
    parts.push("--data", shquote(args.body));
  }
  parts.push(shquote(args.url));
  return parts.join(" ");
}

// Shared header sets. `$JWT` is a placeholder — the engine cannot mint the
// session JWT from the raw PAT (the paired username is not in the token), so it
// is never replaced with a secret.
const EXCHANGE_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
};

const JWT_HEADERS: Record<string, string> = {
  Authorization: "Bearer $JWT",
  Accept: "application/json",
};

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID.
 * - Nothing succeeded -> DENIED.
 *
 * NOTE: every Docker Hub rung is manual and never makes a live call, so no rung
 * is ever `success: true`. The verdict is therefore always DENIED — the ladder
 * cannot prove live access without an out-of-band JWT (minted from the PAT plus
 * the paired username, which is not in the token).
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

// --------------------------------------------------------------------------- //
// rung 1 — SAFE / MANUAL: auth-token-exchange
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `POST /v2/auth/token` exchanges
 * `{"identifier":"<username>","secret":"$KEY"}` for a short-lived JWT.
 *
 * A 200 proves the PAT is live; the decoded JWT scope claim reveals the
 * permission level (read / read-write / read-write-delete) and the bound
 * username. Idempotent session mint, no state change, non-billable. MANUAL
 * because the paired `<username>` is not present in the token, so the engine
 * cannot build the request body — no live call is made; the operator is handed
 * the exact safe curl.
 */
function dockerhubAuthTokenExchange(): ProbeResult {
  const name = "auth-token-exchange";
  const url = `${API_BASE}/v2/auth/token`;
  const body = '{"identifier":"<username>","secret":"$KEY"}';
  const curl = safeCurl({ method: "POST", url, headers: EXCHANGE_HEADERS, body });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the paired <username> (not in the token) to exchange the PAT " +
      "for a JWT; run this by hand — a 200 proves the PAT is live and the decoded " +
      `JWT scope reveals read / read-write / read-write-delete: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE / MANUAL: list-namespace-repos
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /v2/namespaces/{namespace}/repositories` lists the
 * public+private repositories under a reachable namespace using the JWT from
 * rung 1 — read-only depth of access. MANUAL because it needs the `{jwt}` (which
 * the engine cannot mint) and a `{namespace}` placeholder; no live call is made
 * — the operator is handed the safe curl.
 */
function dockerhubListNamespaceRepos(): ProbeResult {
  const name = "list-namespace-repos";
  const url = `${API_BASE}/v2/namespaces/{namespace}/repositories`;
  const curl = safeCurl({ method: "GET", url, headers: JWT_HEADERS });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the JWT from auth-token-exchange and a {namespace}; run this " +
      `by hand to list the public+private repos reachable under that namespace: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — GATED / MANUAL: delete-repository (destructive, state-changing)
// --------------------------------------------------------------------------- //
/** The safe curl printed for the manual gated repo-delete rung (JWT as $JWT). */
function deleteRepositorySafeCurl(): string {
  return safeCurl({
    method: "DELETE",
    url: `${API_BASE}/v2/repositories/{namespace}/{repository}`,
    headers: JWT_HEADERS,
  });
}

/**
 * GATED/MANUAL: `DELETE /v2/repositories/{namespace}/{repository}` wipes a
 * repository (only succeeds for delete-scoped PATs).
 *
 * Destructive, state-changing supply-chain impact: a leaked delete-scoped PAT
 * lets an attacker wipe or hijack published images. Wrapped with {@link gated}:
 * the safety boundary runs *before* this body, so without BOTH `--prove` and an
 * authorized scope it throws {@link GatedProbeBlocked} and nothing is rendered as
 * runnable. Even with consent it is MANUAL — the engine cannot mint the JWT or
 * fill the `{namespace}`/`{repository}` placeholders, so it returns the safe curl
 * rather than firing.
 */
export const dockerhubDeleteRepository = gated(
  "dockerhub.delete-repository",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "delete-repository";
    const curl = deleteRepositorySafeCurl();
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would permanently delete a repository (supply-chain wipe/" +
        "hijack). Needs the JWT and {namespace}/{repository}; run by hand only when " +
        `authorized: ${curl}`,
      evidence: { manual: true, billable: false, safe_curl: curl, success_status: [202, 204] },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Docker Hub capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
 * call): the SAFE rungs always render their safe curl; the GATED rung is reached
 * only through the safety boundary — when consent is missing it is recorded as a
 * blocked rung, when consent is present it still only renders a safe curl. Never
 * throws across this boundary.
 */
export async function dockerhubLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE/MANUAL): identity / token-exchange. Manual rungs always render,
  // so subsequent rungs are not gated on a (never-true) success — the operator
  // gets the full hand-run plan.
  rungs.push(dockerhubAuthTokenExchange());
  // Rung 2 (SAFE/MANUAL): reachable repository surface under a namespace.
  rungs.push(dockerhubListNamespaceRepos());

  // Rung 3 (GATED/MANUAL): destructive repo delete. Reachable only via the
  // gated() wrapper; without full consent it throws GatedProbeBlocked, recorded
  // as a blocked rung (the safe curl is still surfaced as evidence). The ladder
  // never throws across its public boundary.
  try {
    rungs.push(await dockerhubDeleteRepository(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "delete-repository",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            billable: false,
            safe_curl: deleteRepositorySafeCurl(),
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "dockerhub",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register([...DETECTORS], (finding, consent) => dockerhubLadder(finding, consent));
