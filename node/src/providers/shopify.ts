/**
 * Shopify capability ladder — prove depth of access from a leaked Admin API token.
 *
 * Handles the TruffleHog `ShopifyToken` finding: a `shpat_…` Admin API access
 * token used with the header `X-Shopify-Access-Token: <token>`. The token
 * authenticates fine on its own, but EVERY Admin REST endpoint is hosted at
 * `https://{shop}.myshopify.com/...` — and the shop domain is **not present in
 * the raw token**. The engine can fill the `{key}` header, but it cannot invent
 * the `{shop}` host, so per the manual-rung rule that makes **every rung
 * MANUAL**: no rung issues a live call. Each rung instead emits a
 * copy-pasteable, safe `curl` an operator can run by hand once they know the
 * shop domain, with the secret kept as a `$KEY` placeholder and `{shop}` left
 * for the operator to substitute — nothing sensitive is ever stored.
 *
 * Ordered ladder (identity / scopes first, then depth):
 *
 *   1. `access-scopes`  SAFE/MANUAL. `GET /admin/oauth/access_scopes.json`
 *      returns the exact access scopes granted to the token (e.g.
 *      `read_products`, `write_orders`, `read_customers`) — the depth of access
 *      without exercising any of it. Read-only, idempotent, non-billable.
 *   2. `shop-info`      SAFE/MANUAL. `GET /admin/api/2024-01/shop.json` returns
 *      the store's own profile (shop name, owner email, plan, domain, currency)
 *      — identity / whoami over first-party store data. Read-only, non-billable.
 *   3. `list-customers` GATED/MANUAL. `GET /admin/api/2024-01/customers.json`
 *      reads third-party customer PII (names, emails, addresses, order history)
 *      — the data exposure the program cares about. Read-only but GATED because
 *      it reads customer PII. Routed through {@link gated} so it is structurally
 *      unreachable without BOTH `--prove` and `--i-am-authorized "<scope>"`; even
 *      with consent it never auto-fires (the `{shop}` host cannot be filled) — it
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
export const DETECTORS = ["ShopifyToken", "Shopify"] as const;

// --------------------------------------------------------------------------- //
// safe-curl rendering (no live call is ever made by this provider)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl for a Shopify Admin API call. The token is kept as
 * a `$KEY` placeholder in the `X-Shopify-Access-Token` header; the shop is left
 * as the `{shop}` placeholder the operator must substitute. The string never
 * contains a live secret, so it is safe to print and to store.
 */
function safeCurl(args: { method: string; url: string }): string {
  const parts = ["curl", "-sS", "-X", args.method];
  parts.push("-H", shquote("X-Shopify-Access-Token: $KEY"));
  parts.push("-H", shquote("Accept: application/json"));
  parts.push(shquote(args.url));
  return parts.join(" ");
}

/** The list-customers URL (embeds the {shop} placeholder the engine cannot fill). */
function listCustomersUrl(): string {
  return "https://{shop}.myshopify.com/admin/api/2024-01/customers.json?limit=1";
}

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID.
 * - Nothing succeeded -> DENIED.
 *
 * NOTE: every Shopify rung is manual and never makes a live call, so no rung is
 * ever `success: true`. The verdict is therefore always DENIED — the ladder
 * cannot prove live access without the out-of-band `{shop}` domain.
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
// rung 1 — SAFE / MANUAL: access-scopes (depth of access)
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /admin/oauth/access_scopes.json` returns the exact access
 * scopes granted to the token (e.g. `read_products`, `write_orders`,
 * `read_customers`) — depth of access without exercising any of it. Read-only,
 * idempotent, non-billable. MANUAL because the URL needs the `{shop}` host (not
 * in the raw token), so no live call is made — the operator is handed the exact
 * safe curl.
 */
function shopifyAccessScopes(): ProbeResult {
  const name = "access-scopes";
  const url = "https://{shop}.myshopify.com/admin/oauth/access_scopes.json";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {shop} host (the shop domain is not in the raw token); " +
      `run this by hand to list the exact access scopes granted to the token: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE / MANUAL: shop-info (identity / whoami)
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /admin/api/2024-01/shop.json` returns the store's own
 * profile (shop name, owner email, plan, domain, currency) — identity / whoami
 * over first-party store data. Read-only, non-billable. MANUAL (needs the
 * `{shop}` host); no live call is made — the operator is handed the safe curl.
 */
function shopifyShopInfo(): ProbeResult {
  const name = "shop-info";
  const url = "https://{shop}.myshopify.com/admin/api/2024-01/shop.json";
  const curl = safeCurl({ method: "GET", url });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the {shop} host (not in the raw token); run this by hand to " +
      `read the store's own profile (name, owner email, plan, domain, currency): ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — GATED / MANUAL: list-customers (customer PII read)
// --------------------------------------------------------------------------- //
/**
 * GATED/MANUAL: `GET /admin/api/2024-01/customers.json` reads third-party
 * customer PII (names, emails, addresses, order history) — the data exposure the
 * program cares about. Read-only but GATED because it reads customer PII.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 * and nothing is rendered as runnable. Even with consent it is MANUAL — the
 * engine cannot fill the `{shop}` host, so it returns the safe curl rather than
 * firing.
 */
export const shopifyGatedListCustomers = gated(
  "shopify.list-customers",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "list-customers";
    const curl = safeCurl({ method: "GET", url: listCustomersUrl() });
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would read third-party customer PII (names, emails, addresses, " +
        "order history). Needs the {shop} host (not in the raw token); run by hand " +
        `only when authorized: ${curl}`,
      evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Shopify capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
 * call): the SAFE rungs always render their safe curl; the GATED rung is reached
 * only through the safety boundary — when consent is missing it is recorded as a
 * blocked rung, when consent is present it still only renders a safe curl. Never
 * throws across this boundary.
 */
export async function shopifyLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE/MANUAL): depth of access (granted scopes). Manual rungs always
  // render, so subsequent rungs are not gated on a (never-true) success — the
  // operator gets the full hand-run plan.
  rungs.push(shopifyAccessScopes());
  // Rung 2 (SAFE/MANUAL): identity / first-party store profile.
  rungs.push(shopifyShopInfo());

  // Rung 3 (GATED/MANUAL): customer-PII read. Reachable only via the gated
  // wrapper; without full consent it throws GatedProbeBlocked, recorded as a
  // blocked rung (the safe curl is still surfaced as evidence). The ladder never
  // throws across its public boundary.
  const customersCurl = safeCurl({ method: "GET", url: listCustomersUrl() });
  try {
    rungs.push(await shopifyGatedListCustomers(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "list-customers",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            billable: false,
            safe_curl: customersCurl,
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "shopify",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register([...DETECTORS], (finding, consent) => shopifyLadder(finding, consent));
