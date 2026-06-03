/**
 * Capability ladder for Square access tokens.
 *
 * Square OAuth / personal access tokens (`EAAA...`) authenticate via an
 * `Authorization: Bearer <token>` header against `connect.squareup.com`.
 * TruffleHog surfaces them under the `Square` detector. Every request is pinned
 * to a fixed API version (`Square-Version: 2024-01-18`) so the parsed shapes are
 * stable. The ladder climbs:
 *
 * - **`list-locations`** (SAFE) — `GET /v2/locations` confirms the token
 *   authenticates and reaches the seller account, returning the seller's own
 *   business locations (names, addresses, status). Read-only, idempotent, and
 *   no third-party PII — this is the whoami / ground-truth that the key is live.
 * - **`retrieve-merchant-me`** (SAFE) — `GET /v2/merchants/me` resolves the
 *   merchant the token is scoped to (merchant_id, business_name, country,
 *   currency). Identity depth; requires `MERCHANT_PROFILE_READ`.
 * - **`list-team-members`** (SAFE) — `POST /v2/team-members/search` lists the
 *   seller's own team members (employees), proving `EMPLOYEES_READ`. A POST, but
 *   a read-only search: no state change, no billing. The PII is first-party (the
 *   operator's own staff), so it stays SAFE.
 * - **`create-payment`** (GATED) — `POST /v2/payments` charges money via the
 *   seller's Square account (`PAYMENTS_WRITE`). Billable and state-changing — the
 *   real impact. It is GATED *and* rendered MANUAL: a live charge needs a
 *   `source_id`, `amount_money`, and `idempotency_key` that the engine cannot
 *   synthesise, so the rung never fires — even with consent it only hands back a
 *   safe curl that keeps the secret as `$KEY`.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false` so one dead key cannot crash a batch run. The raw token is
 * held only transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

// Every Square request is pinned to one API version so parsed shapes are stable;
// Bearer auth completes the headers each rung sends.
const SQUARE_VERSION = "2024-01-18";

function squareHeaders(key: string): Record<string, string> {
  return {
    Authorization: `Bearer ${key}`,
    "Square-Version": SQUARE_VERSION,
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

/** A `\\`-joined, shell-safe curl string that keeps the live secret as `$KEY`. */
function safeCurl(opts: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): string {
  const parts = [`curl -X ${opts.method} ${JSON.stringify(opts.url)}`];
  for (const [name, value] of Object.entries(opts.headers)) {
    parts.push(`-H ${JSON.stringify(`${name}: ${value}`)}`);
  }
  if (opts.body !== undefined) {
    parts.push(`-d ${JSON.stringify(opts.body)}`);
  }
  return parts.join(" \\\n  ");
}

/**
 * Square ladder: SAFE locations (`/v2/locations`) -> SAFE merchant identity
 * (`/v2/merchants/me`) -> SAFE team enumeration (`/v2/team-members/search`) ->
 * GATED+MANUAL payment charge (`/v2/payments`).
 *
 * The three SAFE rungs only prove the token authenticates and size the account's
 * reach. The payment rung is GATED because it charges money; it is also MANUAL
 * (the engine cannot build a real charge body), so it never fires — it only
 * renders a safe curl, and only after BOTH `--prove` and an authorized scope.
 */
export async function squareLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await squareListLocations(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await squareRetrieveMerchantMe(key, fetchImpl));
    rungs.push(await squareListTeamMembers(key, fetchImpl));

    // Ordered: only attempt the gated payment rung once the token authenticates.
    // The gated wrapper enforces consent BEFORE any work; if consent is missing
    // it throws GatedProbeBlocked, captured here as a `blocked` rung so the
    // ladder never throws across the public boundary. Even with consent the rung
    // is MANUAL and never fires a real charge.
    try {
      rungs.push(await squareCreatePayment(consent));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "create-payment",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: { safe_curl: createPaymentSafeCurl(), reason: exc.reason },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "square",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /v2/locations` confirms the token authenticates and reaches the
 * seller account, returning the seller's own business locations (names,
 * addresses, status). Read-only, idempotent, no third-party PII — the
 * ground-truth that the key is live.
 */
async function squareListLocations(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-locations";
  let resp: Response;
  try {
    resp = await httpRequest("https://connect.squareup.com/v2/locations", {
      headers: squareHeaders(key),
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

  // Locations arrive under `locations`; summarise names + status to size the
  // seller's footprint without dumping the whole payload.
  const locations = Array.isArray(body["locations"])
    ? (body["locations"] as Record<string, unknown>[])
    : [];
  const names = locations
    .map((l) => (l["name"] ?? l["id"]) as string | undefined)
    .filter((n): n is string => typeof n === "string");

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticates: ${locations.length} business location(s)${
      names.length > 0 ? ` (${names.join(", ")})` : ""
    }`,
    evidence: {
      status: resp.status,
      location_count: locations.length,
      location_names: names,
    },
  });
}

/**
 * SAFE: `GET /v2/merchants/me` resolves the merchant the token is scoped to
 * (merchant_id, business_name, country, currency) — identity depth. Requires
 * `MERCHANT_PROFILE_READ`. Own-business metadata, not third-party PII.
 */
async function squareRetrieveMerchantMe(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "retrieve-merchant-me";
  let resp: Response;
  try {
    resp = await httpRequest("https://connect.squareup.com/v2/merchants/me", {
      headers: squareHeaders(key),
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
      detail: `could not resolve merchant (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // The merchant is nested under `merchant`; surface only the non-secret
  // whoami fields.
  const merchant = (body["merchant"] as Record<string, unknown> | undefined) ?? {};
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `merchant ${merchant["id"]} — ${merchant["business_name"] ?? "unknown"} (${
      merchant["country"] ?? "??"
    }, ${merchant["currency"] ?? "??"})`,
    evidence: {
      status: resp.status,
      merchant_id: merchant["id"] ?? null,
      business_name: merchant["business_name"] ?? null,
      country: merchant["country"] ?? null,
      currency: merchant["currency"] ?? null,
    },
  });
}

/**
 * SAFE: `POST /v2/team-members/search` lists the seller's own team members,
 * proving `EMPLOYEES_READ`. A POST, but a read-only search — no state change, no
 * billing. The PII is first-party (the operator's own staff), so it stays SAFE.
 * An empty `query` body returns the workspace's team members.
 */
async function squareListTeamMembers(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-team-members";
  let resp: Response;
  try {
    resp = await httpRequest("https://connect.squareup.com/v2/team-members/search", {
      method: "POST",
      headers: { ...squareHeaders(key), "Content-Type": "application/json" },
      body: JSON.stringify({}),
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
      detail: `could not search team members (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // Team members arrive under `team_members`; count them and note how many are
  // active to size first-party staff exposure, never their personal values.
  const members = Array.isArray(body["team_members"])
    ? (body["team_members"] as Record<string, unknown>[])
    : [];
  const activeCount = members.filter((m) => m["status"] === "ACTIVE").length;

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `EMPLOYEES_READ: ${members.length} team member(s), ${activeCount} active`,
    evidence: {
      status: resp.status,
      team_member_count: members.length,
      active_count: activeCount,
    },
  });
}

/** The safe curl printed for the manual gated payment rung (secret as `$KEY`). */
function createPaymentSafeCurl(): string {
  return safeCurl({
    method: "POST",
    url: "https://connect.squareup.com/v2/payments",
    headers: {
      Authorization: "Bearer $KEY",
      "Square-Version": SQUARE_VERSION,
      "Content-Type": "application/json",
    },
    body: '{"source_id":"<card-nonce>","idempotency_key":"<uuid>","amount_money":{"amount":<cents>,"currency":"<CUR>"}}',
  });
}

/**
 * GATED/MANUAL: `POST /v2/payments` charges money via the seller's Square
 * account (`PAYMENTS_WRITE`). Billable and state-changing — the action the
 * program actually cares about, and the one that must never auto-run.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and nothing is rendered as runnable. Even *with*
 * consent it is MANUAL — a real charge needs a `source_id`, `amount_money`, and
 * `idempotency_key` that the engine cannot synthesise — so it never fires; it
 * only hands back the safe curl (secret kept as `$KEY`).
 */
export const squareCreatePayment = gated(
  "square.create-payment",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "create-payment";
    const curl = createPaymentSafeCurl();
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would charge money via the seller's Square account " +
        "(PAYMENTS_WRITE) — billable and state-changing. Needs a real source_id, " +
        "amount_money, and idempotency_key the engine cannot synthesise; run by " +
        `hand only when authorized: ${curl}`,
      evidence: { manual: true, billable: true, safe_curl: curl, success_status: [200] },
    });
  },
);

register(["Square"], (finding, consent) => squareLadder(finding, consent));
