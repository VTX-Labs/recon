/**
 * Stripe capability ladder — prove depth of access for a leaked API key.
 *
 * Handles TruffleHog `StripeAccessToken` and `Stripe` findings. A Stripe
 * secret/restricted key (`sk_...` / `rk_...`) authenticates with
 * `Authorization: Bearer <key>`.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `stripe.auth_check`           `GET /v1/balance` — cheap, non-PII probe
 *      that only proves the key authenticates. Decides VALID vs DENIED.
 *   2. `stripe.products.list`        `GET /v1/products?limit=1` — SAFE scope
 *      probe. A restricted key may be denied here (403) yet still be live; both
 *      200 and 403 are recorded as a successful reachability/scope signal.
 *   3. `stripe.balance_transactions` `GET /v1/balance_transactions?limit=1` —
 *      SAFE depth: confirms ledger read access. We keep only whether it was
 *      reachable and the count, never amounts.
 *   4. `stripe.account.read`         `GET /v1/account` — GATED. Returns live
 *      business PII (legal name, support email, payout hints).
 *   5. `stripe.charges.list`         `GET /v1/charges?limit=1` — GATED. Returns
 *      customer PII (names, emails, card metadata).
 *
 * The two GATED rungs run only if the operator supplied BOTH `--prove` and an
 * authorized scope; otherwise they are recorded as `blocked` and no request is
 * issued. Every live rung is READ-ONLY, the ladder never throws across its
 * public boundary, and the raw key never lands in evidence (only `redact()`ed).
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { redact } from "../redact.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["StripeAccessToken", "Stripe"] as const;

const API_BASE = "https://api.stripe.com/v1";

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

/** Standard Stripe bearer header for a secret/restricted key. */
function bearer(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}` };
}

/**
 * Stripe ladder: SAFE auth check -> SAFE scope/depth probes -> GATED PII reads.
 *
 * The SAFE rungs only prove the key authenticates and map its read reach. The
 * account read and charges read are GATED because they return live PII; they
 * run only if the operator supplied BOTH `--prove` and an authorized scope.
 */
export async function stripeLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const token = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: auth_check (SAFE) — decides live/dead -------------------------
  const auth = await stripeAuthCheck(token, fetchImpl);
  rungs.push(auth);

  // Only climb deeper if the key authenticates (ordered ladder). The gated
  // wrappers enforce consent BEFORE any network call; if consent is missing
  // they throw GatedProbeBlocked, captured here as a `blocked` rung so the
  // ladder never throws across the public boundary.
  if (auth.success) {
    // --- Rung 2: products.list (SAFE scope probe) ----------------------------
    rungs.push(await stripeProductsList(token, fetchImpl));

    // --- Rung 3: balance_transactions (SAFE depth) ---------------------------
    rungs.push(await stripeBalanceTransactions(token, fetchImpl));

    // --- Rung 4: account.read (GATED PII) ------------------------------------
    try {
      rungs.push(await stripeAccountRead(consent, token, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(gatedBlocked("stripe.account.read", exc));
      } else {
        throw exc;
      }
    }

    // --- Rung 5: charges.list (GATED PII) ------------------------------------
    try {
      rungs.push(await stripeChargesList(consent, token, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(gatedBlocked("stripe.charges.list", exc));
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "stripe",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

function gatedBlocked(name: string, exc: GatedProbeBlocked): ProbeResult {
  return new ProbeResult({
    name,
    tier: ProbeTier.GATED,
    success: false,
    blocked: true,
    detail: `gated PII read blocked: ${exc.reason}`,
    evidence: { reason: exc.reason },
  });
}

// --- SAFE rungs --------------------------------------------------------------

/**
 * SAFE: hit read-only `/v1/balance` purely to confirm the key works. Balance
 * is account-level money data but not third-party PII; we keep no figures from
 * it — only whether the key authenticated.
 */
async function stripeAuthCheck(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "stripe.auth_check";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/balance`, {
      headers: bearer(token),
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
      detail: `key rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: "key authenticates (live secret/restricted key)",
    evidence: { status: resp.status, key_prefix: redact(token) },
  });
}

/**
 * SAFE: `GET /v1/products?limit=1` maps read scope. A restricted key may be
 * forbidden here (403) yet still be a live key; we treat both 200 (read access)
 * and 403 (live key, scope withheld) as a successful reachability signal.
 */
async function stripeProductsList(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "stripe.products.list";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/products`, {
      headers: bearer(token),
      params: { limit: "1" },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (resp.status === 403) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: true,
      detail: "products read forbidden (restricted key, scope withheld)",
      evidence: { status: resp.status, readable: false },
    });
  }

  if (resp.status !== 200) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `products probe failed (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  const data = body && Array.isArray(body["data"]) ? (body["data"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `products readable (${data.length} sampled)`,
    evidence: { status: resp.status, readable: true, sample_count: data.length },
  });
}

/**
 * SAFE: `GET /v1/balance_transactions?limit=1` confirms ledger read depth. We
 * keep only the reachability and a sample count — never amounts.
 */
async function stripeBalanceTransactions(
  token: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "stripe.balance_transactions";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/balance_transactions`, {
      headers: bearer(token),
      params: { limit: "1" },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (resp.status === 403) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: true,
      detail: "balance transactions forbidden (restricted key, scope withheld)",
      evidence: { status: resp.status, readable: false },
    });
  }

  if (resp.status !== 200) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `balance transactions probe failed (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  const data = body && Array.isArray(body["data"]) ? (body["data"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `balance ledger readable (${data.length} sampled)`,
    evidence: { status: resp.status, readable: true, sample_count: data.length },
  });
}

// --- GATED rungs -------------------------------------------------------------

/**
 * GATED: `GET /v1/account` returns live business PII.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. The public ladder
 * catches that and records a `blocked` rung.
 */
export const stripeAccountRead = gated(
  "stripe.account.read",
  async (_consent: Consent, token: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "stripe.account.read";
    let resp: Response;
    try {
      resp = await httpRequest(`${API_BASE}/account`, {
        headers: bearer(token),
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return networkFailure(name, ProbeTier.GATED, exc);
    }

    if (resp.status !== 200) {
      return new ProbeResult({
        name,
        tier: ProbeTier.GATED,
        success: false,
        detail: `account read refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    const body = (await readJson(resp)) as Record<string, unknown> | undefined;
    if (body === undefined) {
      return networkFailure(name, ProbeTier.GATED, new SyntaxError("invalid JSON"));
    }

    // PII is summarised, not dumped: prove access without hoarding the data.
    const piiFields = ["email", "business_profile"].filter((k) => k in body).sort();
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail:
        `read live account ${body["id"]} ` +
        `(${body["business_type"] ?? "unknown"} in ${body["country"] ?? "??"})`,
      evidence: {
        status: resp.status,
        account_id: body["id"] ?? null,
        country: body["country"] ?? null,
        business_type: body["business_type"] ?? null,
        charges_enabled: body["charges_enabled"] ?? null,
        pii_fields_present: piiFields,
      },
    });
  },
);

/**
 * GATED: `GET /v1/charges?limit=1` returns customer PII.
 *
 * Wrapped with {@link gated}; without consent it throws {@link GatedProbeBlocked}
 * before any request. We summarise (count + which PII fields were present),
 * never dump card/customer data.
 */
export const stripeChargesList = gated(
  "stripe.charges.list",
  async (_consent: Consent, token: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "stripe.charges.list";
    let resp: Response;
    try {
      resp = await httpRequest(`${API_BASE}/charges`, {
        headers: bearer(token),
        params: { limit: "1" },
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return networkFailure(name, ProbeTier.GATED, exc);
    }

    if (resp.status !== 200) {
      return new ProbeResult({
        name,
        tier: ProbeTier.GATED,
        success: false,
        detail: `charges read refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    const body = (await readJson(resp)) as Record<string, unknown> | undefined;
    if (body === undefined) {
      return networkFailure(name, ProbeTier.GATED, new SyntaxError("invalid JSON"));
    }

    const data = Array.isArray(body["data"]) ? (body["data"] as Record<string, unknown>[]) : [];
    const first = data[0] ?? {};
    const piiFields = ["billing_details", "receipt_email", "customer"]
      .filter((k) => k in first)
      .sort();
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: `read live charges (${data.length} sampled, customer PII reachable)`,
      evidence: {
        status: resp.status,
        charge_count: data.length,
        pii_fields_present: piiFields,
      },
    });
  },
);

register([...DETECTORS], (finding, consent) => stripeLadder(finding, consent));
