/**
 * Grafana capability ladder — prove depth of access from a leaked service-account token.
 *
 * Handles the TruffleHog `Grafana` finding: a service-account token of the form
 * `glsa_<32 base62>_<8 hex>`. Every Grafana HTTP API call is made against the
 * tenant's own instance host — a self-hosted server or a Grafana Cloud stack URL
 * (`{host}` / `https://<stack>.grafana.net`). That host is **not** present in the
 * raw token: the token authenticates *to* an instance but does not name it.
 *
 * Because every rung's URL embeds `{host}` and the engine cannot fill that
 * placeholder, the manual-rung rule applies: **every rung is MANUAL**. No rung
 * issues a live call. Each rung instead emits a copy-pasteable, safe `curl` an
 * operator can run by hand once they know the instance host, with the token kept
 * as a `$KEY` placeholder so nothing sensitive is ever stored.
 *
 * Ordered ladder (identity first, then depth):
 *
 *   1. `current-user`     SAFE/MANUAL. `GET /api/user` — whoami: returns the
 *      identity backing the token (login, email, org). Read-only, idempotent,
 *      non-billable.
 *   2. `user-permissions` SAFE/MANUAL. `GET /api/access-control/user/permissions`
 *      — list-scopes: the exact RBAC permissions granted to the token
 *      (e.g. `dashboards:read`, `datasources:write`, `org.users:read`). Read-only.
 *   3. `list-datasources` SAFE/MANUAL. `GET /api/datasources` — reachable-data
 *      depth: enumerates configured data sources (types, URLs, names), proving
 *      read access to backend wiring. Read-only.
 *
 * The ladder never throws across its public boundary: every failure becomes a
 * {@link ProbeResult}. Secrets are never persisted; only non-secret values land
 * in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier } from "../safety.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Grafana"] as const;

// --------------------------------------------------------------------------- //
// safe-curl rendering (no live call is ever made by this provider)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl for a Grafana bearer-auth call. The token is kept
 * as a `$KEY` placeholder; the instance host is left as the `{host}` placeholder
 * the operator must substitute. The string never contains a live secret, so it
 * is safe to print and to store.
 */
function safeCurl(args: { method: string; url: string }): string {
  const parts = ["curl", "-sS", "-X", args.method];
  parts.push("-H", shquote("Authorization: Bearer $KEY"));
  parts.push("-H", shquote("Accept: application/json"));
  parts.push(shquote(args.url));
  return parts.join(" ");
}

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID.
 * - Nothing succeeded -> DENIED.
 *
 * NOTE: every Grafana rung is manual and never makes a live call, so no rung is
 * ever `success: true`. The verdict is therefore always DENIED — the ladder
 * cannot prove live access without the out-of-band instance host.
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
// rung 1 — SAFE / MANUAL: current-user (identity / whoami)
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /api/user` — whoami. Returns the identity backing the
 * service-account token (login, email, org). Read-only, idempotent,
 * non-billable. MANUAL because it needs the `{host}` instance URL (not in the
 * raw token), so no live call is made — the operator is handed the exact safe
 * curl.
 */
function grafanaCurrentUser(): ProbeResult {
  const name = "current-user";
  const url = "https://{host}/api/user";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {host} Grafana instance URL (not in the raw token); run " +
      `this by hand to confirm the identity backing the token (login/email/org): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE / MANUAL: user-permissions (token RBAC scopes / depth)
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /api/access-control/user/permissions` — list-scopes. Returns
 * the exact RBAC permissions granted to the token (e.g. `dashboards:read`,
 * `datasources:write`, `org.users:read`) — depth of access without exercising
 * any of it. Read-only, non-billable. MANUAL (needs `{host}`); no live call is
 * made — the operator is handed the safe curl.
 */
function grafanaUserPermissions(): ProbeResult {
  const name = "user-permissions";
  const url = "https://{host}/api/access-control/user/permissions";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {host} Grafana instance URL; run this by hand to read the " +
      `token's exact RBAC permissions (depth of access): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — SAFE / MANUAL: list-datasources (reachable backend wiring)
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /api/datasources` — reachable-data depth. Enumerates the
 * configured data sources (types, URLs, names), proving read access to the
 * backend wiring the instance can reach. Read-only, idempotent, non-billable.
 * MANUAL (needs `{host}`); no live call is made — the operator is handed the
 * safe curl.
 */
function grafanaListDatasources(): ProbeResult {
  const name = "list-datasources";
  const url = "https://{host}/api/datasources";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {host} Grafana instance URL; run this by hand to enumerate " +
      `configured data sources (types/URLs/names — reachable backend wiring): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Grafana capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
 * call): each SAFE rung always renders its safe curl. Because manual rungs never
 * succeed, subsequent rungs are not gated on a (never-true) success — the
 * operator gets the full hand-run plan. The ladder never throws across its
 * public boundary.
 */
export async function grafanaLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE/MANUAL): identity / whoami.
  rungs.push(grafanaCurrentUser());
  // Rung 2 (SAFE/MANUAL): token RBAC permissions (depth of access).
  rungs.push(grafanaUserPermissions());
  // Rung 3 (SAFE/MANUAL): reachable data sources (backend wiring).
  rungs.push(grafanaListDatasources());

  return new LadderResult({
    finding,
    provider: "grafana",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register([...DETECTORS], (finding, consent) => grafanaLadder(finding, consent));
