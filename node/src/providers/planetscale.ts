/**
 * Capability ladder for PlanetScale service tokens (`pscale_tkn_...`).
 *
 * PlanetScale authenticates with a *pair*: `Authorization: <token_id>:<token>`.
 * The token id is a distinct value that does NOT live inside the leaked secret
 * — TruffleHog's `pscale_tkn_...` match is only the token half (`{key}`). Every
 * rung in PlanetScale's documented API therefore needs at least one placeholder
 * the engine cannot fill from the secret alone:
 *
 *   1. `list-organizations`  — `GET /v1/organizations`. The whoami / scope check
 *      (TruffleHog's verification endpoint). 2xx proves the `id:token` pair
 *      authenticates. Read-only. BUT the `Authorization` header needs the token
 *      *id* (`{id}`), which is not in the secret -> this is a MANUAL safe-curl
 *      rung: the engine emits the exact curl with the token kept as `$KEY` and
 *      `$TOKEN_ID` for the operator to fill, and never fires it live.
 *   2. `list-databases`      — `GET /v1/organizations/{org}/databases`. Climbs
 *      from "which orgs" to "which databases" the token can enumerate. Needs
 *      both `{id}` (header) and `{org}` (path) -> MANUAL safe-curl rung.
 *   3. `create-branch`       — `POST /v1/organizations/{org}/databases/{db}/branches`.
 *      Creates a database branch: resource-creating, state-changing, billable.
 *      GATED. It also needs `{org}`/`{db}`, so even with consent there is no
 *      value the engine can fill -> it is rendered as a GATED manual note
 *      (a blocked rung carrying the safe curl) and is NEVER auto-fired.
 *
 * Because the token id and the org/db identifiers are never derivable from the
 * secret, this provider is fully MANUAL: it hands the operator copy-pasteable,
 * secret-redacted curls rather than making live calls. Nothing here throws
 * across the public boundary; secrets are never persisted (the printed curl
 * keeps `$KEY`).
 *
 * Docs:
 *   https://planetscale.com/docs/api/reference/list_organizations
 *   https://planetscale.com/docs/api/reference/service-tokens
 *   https://planetscale.com/docs/api/reference/create_branch
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { register } from "./registry.js";

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID (authenticates + depth shown).
 * - The key authenticated nowhere -> DENIED.
 *
 * PlanetScale is fully manual, so no rung reports `success=true`; the verdict
 * is DENIED (we could not positively exercise any capability without the
 * out-of-band token id / org / db identifiers).
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

/** Minimal single-quote shell quoting for the printable safe curl. */
function shquote(value: string): string {
  return "'" + value.split("'").join("'\\''") + "'";
}

/**
 * Build a copy-pasteable curl that NEVER contains the live secret.
 *
 * The token is rendered as `$KEY` and the out-of-band token id as `$TOKEN_ID`,
 * matching PlanetScale's `Authorization: <token_id>:<token>` scheme. Any path
 * placeholders (`{org}`, `{db}`) are left verbatim for the operator to fill.
 */
function safeCurl(
  method: string,
  url: string,
  headers: Record<string, string>,
): string {
  const parts = ["curl", "-sS", "-X", method];
  for (const [headerName, headerValue] of Object.entries(headers)) {
    parts.push("-H", shquote(`${headerName}: ${headerValue}`));
  }
  parts.push(shquote(url));
  return parts.join(" ");
}

// --------------------------------------------------------------------------- //
// PlanetScale
// --------------------------------------------------------------------------- //

/**
 * PlanetScale ladder: MANUAL identity (orgs) -> MANUAL depth (databases) ->
 * GATED manual note (create-branch).
 *
 * Every rung is manual because PlanetScale's `Authorization` header needs the
 * token *id* (not in the secret) and the depth/write rungs additionally need
 * `{org}`/`{db}` path identifiers the engine cannot supply.
 */
export async function planetscaleLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1: identity / scope check (MANUAL, SAFE-tier).
  rungs.push(planetscaleListOrganizations());

  // Rung 2: reachable databases (MANUAL, SAFE-tier). For a live ladder we would
  // only climb after the identity rung authenticated; here both are manual
  // notes (guidance, not live probes), so we always emit them.
  rungs.push(planetscaleListDatabases());

  // Rung 3: create-branch (GATED). Routed through the gated() boundary so it can
  // never auto-fire; it is rendered as a blocked/manual note carrying the safe
  // curl (it also needs {org}/{db} the engine cannot fill).
  try {
    rungs.push(await planetscaleCreateBranch(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "create-branch",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            billable: true,
            safe_curl: createBranchCurl(),
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "planetscale",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * MANUAL SAFE: `GET /v1/organizations` — whoami / scope check.
 *
 * TruffleHog's verification endpoint. A 2xx proves the `token_id:token` pair
 * authenticates and lists the orgs the service token can reach (read-only,
 * non-billable). The `Authorization` header needs the token *id*, which is not
 * inside the leaked secret, so we emit the safe curl instead of firing live.
 */
function planetscaleListOrganizations(): ProbeResult {
  const curl = safeCurl(
    "GET",
    "https://api.planetscale.com/v1/organizations",
    { Authorization: "$TOKEN_ID:$KEY" },
  );
  return new ProbeResult({
    name: "list-organizations",
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: whoami/scope check needs the token id (not in the secret). " +
      `Run by hand to confirm auth and list reachable orgs (expect HTTP 200): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

/**
 * MANUAL SAFE: `GET /v1/organizations/{org}/databases` — reachable databases.
 *
 * Climbs from "which orgs" to "which databases" the token can enumerate (depth
 * of access). Read-only, idempotent, non-billable — but needs both the token id
 * (header) and an `{org}` (path), so it is emitted as a safe curl.
 */
function planetscaleListDatabases(): ProbeResult {
  const curl = safeCurl(
    "GET",
    "https://api.planetscale.com/v1/organizations/{org}/databases",
    { Authorization: "$TOKEN_ID:$KEY" },
  );
  return new ProbeResult({
    name: "list-databases",
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the token id and an {org} from the prior rung. " +
      `Run by hand to enumerate reachable databases (expect HTTP 200): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

/** The safe curl for the GATED create-branch rung (token kept as `$KEY`). */
function createBranchCurl(): string {
  return safeCurl(
    "POST",
    "https://api.planetscale.com/v1/organizations/{org}/databases/{db}/branches",
    { Authorization: "$TOKEN_ID:$KEY", "Content-Type": "application/json" },
  );
}

/**
 * GATED: `POST .../branches` — creates a new database branch.
 *
 * Resource-creating, state-changing, and billable: the concrete write impact.
 * Wrapped with {@link gated} so the safety boundary runs *before* this body —
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. Even WITH consent the
 * engine cannot fill the required `{org}`/`{db}` path identifiers, so the body
 * never fires a live call: it returns a manual, non-success note carrying the
 * safe curl for the operator to run by hand.
 */
export const planetscaleCreateBranch = gated(
  "planetscale.create-branch",
  async (_consent: Consent): Promise<ProbeResult> => {
    const curl = createBranchCurl();
    return new ProbeResult({
      name: "create-branch",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "GATED+MANUAL: creating a database branch is state-changing and billable, " +
        "and needs {org}/{db} the engine cannot fill. Consent satisfied; run by " +
        `hand to exercise the write (expect HTTP 201): ${curl}`,
      evidence: { manual: true, billable: true, safe_curl: curl, success_status: [201] },
    });
  },
);

register(["PlanetScale"], (finding, consent) => planetscaleLadder(finding, consent));
