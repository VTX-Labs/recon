/**
 * Snowflake capability ladder — prove depth of access from a leaked credential.
 *
 * A TruffleHog `Snowflake` finding is **multipart**: an account identifier plus
 * a username and password. It is NOT a single standalone-recognizable token, so
 * routing is via the `Snowflake` detector and `key_regex` is empty. Crucially,
 * the Snowflake SQL API and resource-management REST API authenticate with a
 * **KEYPAIR_JWT** generated from a private key that is *not present* in the raw
 * credential. vtx-recon therefore cannot mint that JWT, and every rung's URL or
 * headers reference placeholders the engine cannot fill (`{account}`, `{jwt}`).
 *
 * Per the manual-rung rule, that means **every rung is MANUAL**: no rung issues
 * a live call. Each rung instead emits a copy-pasteable, safe `curl` an operator
 * can run by hand once they have produced a KEYPAIR_JWT, with the secret kept as
 * a `$JWT` placeholder so nothing sensitive is ever stored.
 *
 * Rungs (ordered, identity first):
 *
 *   1. `whoami-current-user` — SAFE/MANUAL. `POST /api/v2/statements` running
 *      `SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()` — a SELECT-only
 *      identity probe, no state change, non-billable.
 *   2. `list-databases` — SAFE/MANUAL. `GET /api/v2/databases` enumerates every
 *      database the role can see (reachable data surface). Read-only, idempotent,
 *      non-billable.
 *   3. `exfil-table-data` — GATED/MANUAL. `POST /api/v2/statements` running
 *      `SELECT * FROM <db>.<schema>.<table> LIMIT N` — reads warehouse-stored
 *      business/customer data (third-party PII risk) and spins billable compute.
 *      Routed through {@link gated} so it is structurally unreachable without
 *      BOTH `--prove` and `--i-am-authorized "<scope>"`; even when consent is
 *      granted it never auto-fires (placeholders cannot be filled) — it renders
 *      the safe curl for the operator.
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

// --------------------------------------------------------------------------- //
// safe-curl rendering (no live call is ever made by this provider)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl with the JWT kept as a `$JWT` placeholder and the
 * account left as the `{account}` placeholder the operator must substitute. The
 * string never contains a live secret, so it is safe to print and to store.
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
// KEYPAIR_JWT from the raw credential, so it is never replaced with a secret.
const STATEMENTS_HEADERS: Record<string, string> = {
  Authorization: "Bearer $JWT",
  "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
  "Content-Type": "application/json",
  Accept: "application/json",
};

const REST_HEADERS: Record<string, string> = {
  Authorization: "Bearer $JWT",
  "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
  Accept: "application/json",
};

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID.
 * - Nothing succeeded (here: all rungs are manual, so always) -> DENIED.
 *
 * NOTE: every Snowflake rung is manual and never makes a live call, so no rung
 * is ever `success: true`. The verdict is therefore always DENIED — the ladder
 * cannot prove live access without an out-of-band KEYPAIR_JWT.
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
// rung 1 — SAFE / MANUAL: whoami-current-user
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `POST /api/v2/statements` running
 * `SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()`.
 *
 * Confirms identity and effective role. SELECT-only context query, no state
 * change, non-billable. MANUAL because it needs a KEYPAIR_JWT not present in
 * the raw credential and an `{account}` URL placeholder — no live call is made;
 * the operator is handed the exact safe curl.
 */
function snowflakeWhoami(): ProbeResult {
  const name = "whoami-current-user";
  const url = "https://{account}.snowflakecomputing.com/api/v2/statements";
  const body =
    '{"statement":"SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()","timeout":60}';
  const curl = safeCurl({ method: "POST", url, headers: STATEMENTS_HEADERS, body });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs a KEYPAIR_JWT (not in the raw credential) and the {account} " +
      `host; run this by hand to confirm identity/role: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE / MANUAL: list-databases
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /api/v2/databases` — resource-management REST API
 * enumerating every database the role can see (reachable data surface / depth).
 * Read-only, idempotent, non-billable. MANUAL (KEYPAIR_JWT + `{account}`); no
 * live call is made — the operator is handed the safe curl.
 */
function snowflakeListDatabases(): ProbeResult {
  const name = "list-databases";
  const url = "https://{account}.snowflakecomputing.com/api/v2/databases";
  const curl = safeCurl({ method: "GET", url, headers: REST_HEADERS });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs a KEYPAIR_JWT (not in the raw credential) and the {account} " +
      `host; run this by hand to enumerate visible databases: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — GATED / MANUAL: exfil-table-data (billable PII read)
// --------------------------------------------------------------------------- //
/**
 * GATED/MANUAL: `POST /api/v2/statements` running
 * `SELECT * FROM <db>.<schema>.<table> LIMIT N`.
 *
 * Reads warehouse-stored business/customer data (third-party PII risk) and
 * spins billable compute. Wrapped with {@link gated}: the safety boundary runs
 * *before* this body, so without BOTH `--prove` and an authorized scope it
 * throws {@link GatedProbeBlocked} and nothing is rendered as runnable. Even
 * with consent it is MANUAL — the engine cannot mint the JWT or fill the
 * `{account}`/`<db>.<schema>.<table>` placeholders, so it returns the safe curl
 * rather than firing.
 */
export const snowflakeExfilTableData = gated(
  "snowflake.exfil-table-data",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "exfil-table-data";
    const url = "https://{account}.snowflakecomputing.com/api/v2/statements";
    const body =
      '{"statement":"SELECT * FROM <db>.<schema>.<table> LIMIT 10","timeout":60}';
    const curl = safeCurl({ method: "POST", url, headers: STATEMENTS_HEADERS, body });
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would read warehouse data and spin billable compute. Needs " +
        "a KEYPAIR_JWT and {account}/<db>.<schema>.<table>; run by hand only when " +
        `authorized: ${curl}`,
      evidence: { manual: true, billable: true, safe_curl: curl, success_status: [200] },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Snowflake capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
 * call): the SAFE rungs always render their safe curl; the GATED rung is reached
 * only through the safety boundary — when consent is missing it is recorded as a
 * blocked rung, when consent is present it still only renders a safe curl.
 */
export async function snowflakeLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE/MANUAL): identity. Manual rungs always render, so subsequent
  // rungs are not gated on a (never-true) success — the operator gets the full
  // hand-run plan.
  rungs.push(snowflakeWhoami());
  // Rung 2 (SAFE/MANUAL): reachable database surface.
  rungs.push(snowflakeListDatabases());

  // Rung 3 (GATED/MANUAL): billable PII read. Reachable only via the gated
  // wrapper; without full consent it throws GatedProbeBlocked, recorded as a
  // blocked rung (the safe curl is still surfaced as evidence). The ladder
  // never throws across its public boundary.
  const exfilBody =
    '{"statement":"SELECT * FROM <db>.<schema>.<table> LIMIT 10","timeout":60}';
  const exfilCurl = safeCurl({
    method: "POST",
    url: "https://{account}.snowflakecomputing.com/api/v2/statements",
    headers: STATEMENTS_HEADERS,
    body: exfilBody,
  });
  try {
    rungs.push(await snowflakeExfilTableData(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "exfil-table-data",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            billable: true,
            safe_curl: exfilCurl,
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "snowflake",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(["Snowflake"], (finding, consent) => snowflakeLadder(finding, consent));
