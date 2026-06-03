/**
 * Zendesk capability ladder — prove depth of access from a leaked API token.
 *
 * Handles the TruffleHog `ZendeskApi` finding: a 40-char API token used with
 * Zendesk **Basic auth**. The wire credential is `Basic base64(email/token:apitoken)`
 * — i.e. the account email and the literal `/token` suffix are combined with the
 * API token, then base64-encoded. Two values needed to authenticate are *not*
 * present in the raw token:
 *
 *   - the **subdomain** (`{subdomain}.zendesk.com`) — which Zendesk instance, and
 *   - the **account email** — the first half of the `email/token:apitoken` pair.
 *
 * Because every rung's URL embeds `{subdomain}` and every header embeds the
 * account email, the engine cannot fill those placeholders. Per the manual-rung
 * rule that makes **every rung MANUAL**: no rung issues a live call. Each rung
 * instead emits a copy-pasteable, safe `curl` an operator can run by hand once
 * they know the subdomain + email, with the secret kept as a `$KEY` placeholder
 * (and the email as `$EMAIL`) so nothing sensitive is ever stored.
 *
 * Ordered ladder (identity first, then depth):
 *
 *   1. `current-user`  SAFE/MANUAL. `GET /api/v2/users/me.json` returns the
 *      authenticated user (role, email, org) — identity / whoami. Read-only,
 *      non-billable.
 *   2. `list-users`    SAFE/MANUAL. `GET /api/v2/users.json` lists agents /
 *      end-users reachable by the token — confirms account-wide read depth.
 *      Read-only, non-billable.
 *   3. `list-tickets`  GATED/MANUAL. `GET /api/v2/tickets.json` reads support
 *      tickets — third-party customer PII and conversation content. The impact
 *      the program cares about; read-only but GATED because it exfiltrates
 *      customer data. Routed through {@link gated} so it is structurally
 *      unreachable without BOTH `--prove` and `--i-am-authorized "<scope>"`; even
 *      with consent it never auto-fires (placeholders cannot be filled) — it
 *      renders the safe curl for the operator.
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
export const DETECTORS = ["ZendeskApi"] as const;

// --------------------------------------------------------------------------- //
// safe-curl rendering (no live call is ever made by this provider)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl for a Zendesk Basic-auth call. The token is kept
 * as a `$KEY` placeholder and the account email as `$EMAIL`; the subdomain is
 * left as the `{subdomain}` placeholder the operator must substitute. The string
 * never contains a live secret, so it is safe to print and to store.
 */
function safeCurl(args: { method: string; url: string }): string {
  const parts = ["curl", "-sS", "-X", args.method];
  // Zendesk Basic auth is `email/token:apitoken`; -u renders it without us ever
  // base64-encoding (let curl do it) and keeps both secrets as shell vars.
  parts.push("-u", shquote("$EMAIL/token:$KEY"));
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
 * NOTE: every Zendesk rung is manual and never makes a live call, so no rung is
 * ever `success: true`. The verdict is therefore always DENIED — the ladder
 * cannot prove live access without the out-of-band subdomain + account email.
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
 * SAFE/MANUAL: `GET /api/v2/users/me.json` returns the authenticated user (role,
 * email, org) — identity / whoami. Read-only, non-billable. MANUAL because it
 * needs the `{subdomain}` host and the account email (not in the raw token), so
 * no live call is made — the operator is handed the exact safe curl.
 */
function zendeskCurrentUser(): ProbeResult {
  const name = "current-user";
  const url = "https://{subdomain}.zendesk.com/api/v2/users/me.json";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {subdomain} host and account email (Basic email/token:apitoken; " +
      `not in the raw token); run this by hand to confirm identity/role: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE / MANUAL: list-users (account-wide read depth)
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /api/v2/users.json` lists agents / end-users reachable by
 * the token — confirms account-wide read depth. Read-only, idempotent,
 * non-billable. MANUAL (needs `{subdomain}` + account email); no live call is
 * made — the operator is handed the safe curl.
 */
function zendeskListUsers(): ProbeResult {
  const name = "list-users";
  const url = "https://{subdomain}.zendesk.com/api/v2/users.json?page[size]=10";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {subdomain} host + account email + token; run this by hand " +
      `to enumerate reachable agents/end-users (read depth): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — GATED / MANUAL: list-tickets (customer PII read)
// --------------------------------------------------------------------------- //
/** The list-tickets URL (embeds the {subdomain} placeholder the engine cannot fill). */
function listTicketsUrl(): string {
  return "https://{subdomain}.zendesk.com/api/v2/tickets.json?page[size]=5";
}

/**
 * GATED/MANUAL: `GET /api/v2/tickets.json` reads support tickets — third-party
 * customer PII and conversation content. The impact the program cares about;
 * read-only but GATED because it exfiltrates customer data.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 * and nothing is rendered as runnable. Even with consent it is MANUAL — the
 * engine cannot fill the `{subdomain}` host or supply the account email, so it
 * returns the safe curl rather than firing.
 */
export const zendeskGatedListTickets = gated(
  "zendesk.list-tickets",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "list-tickets";
    const curl = safeCurl({ method: "GET", url: listTicketsUrl() });
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would read support tickets (third-party customer PII and " +
        "conversation content). Needs the {subdomain} host + account email + token; " +
        `run by hand only when authorized: ${curl}`,
      evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Zendesk capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
 * call): the SAFE rungs always render their safe curl; the GATED rung is reached
 * only through the safety boundary — when consent is missing it is recorded as a
 * blocked rung, when consent is present it still only renders a safe curl. Never
 * throws across this boundary.
 */
export async function zendeskLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE/MANUAL): identity. Manual rungs always render, so subsequent
  // rungs are not gated on a (never-true) success — the operator gets the full
  // hand-run plan.
  rungs.push(zendeskCurrentUser());
  // Rung 2 (SAFE/MANUAL): account-wide read depth.
  rungs.push(zendeskListUsers());

  // Rung 3 (GATED/MANUAL): customer-PII read. Reachable only via the gated
  // wrapper; without full consent it throws GatedProbeBlocked, recorded as a
  // blocked rung (the safe curl is still surfaced as evidence). The ladder never
  // throws across its public boundary.
  const ticketsCurl = safeCurl({ method: "GET", url: listTicketsUrl() });
  try {
    rungs.push(await zendeskGatedListTickets(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "list-tickets",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            billable: false,
            safe_curl: ticketsCurl,
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "zendesk",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register([...DETECTORS], (finding, consent) => zendeskLadder(finding, consent));
