/**
 * Mailchimp Marketing API capability ladder — prove depth of access for a
 * leaked API key.
 *
 * Handles TruffleHog `Mailchimp` findings. A Mailchimp Marketing key is 32 hex
 * characters followed by a datacenter suffix, e.g. `…-us21`. The datacenter
 * (`{dc}`) is *not* a free placeholder: it is encoded in the key itself (the
 * segment after the final dash) and is required to address every Marketing API
 * endpoint (`https://{dc}.api.mailchimp.com/3.0/…`). The key authenticates with
 * HTTP Basic auth (`Authorization: Basic <key>`), per the provider spec.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `api-root`        `GET /3.0/` — the whoami for a Mailchimp key. Confirms
 *      the key authenticates and returns account identity (account id, login
 *      email, contact, total subscribers). Read-only, idempotent. This is the
 *      rung that decides VALID vs DENIED.
 *   2. `list-audiences`  `GET /3.0/lists?count=10` — enumerates the audiences /
 *      lists the key can reach (names, member counts) — reachable resources,
 *      deeper than identity. Read-only enumeration.
 *   3. `add-list-member` `POST /3.0/lists/{list_id}/members` — GATED, mutating.
 *      Writes a subscriber into an audience; state-changing and injects into a
 *      marketing pipeline that emails third parties. Its URL needs a `{list_id}`
 *      from `list-audiences` that the engine cannot fill, so this rung is
 *      rendered as a MANUAL safe-curl note: it is never auto-fired and prints a
 *      curl that keeps the secret as `$KEY`.
 *
 * Every rung is ordered (identity first, then depth), the live rungs are all
 * READ-ONLY GETs, and the ladder never throws across its public boundary:
 * failures become a {@link ProbeResult} with `success=false`. The raw key is
 * held only transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Mailchimp"] as const;

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

/** Standard Mailchimp HTTP Basic header (the key is the credential, per spec). */
function basic(key: string): Record<string, string> {
  return { Authorization: `Basic ${key}` };
}

/**
 * Derive the datacenter (`{dc}`) from the key: the segment after the final dash
 * (e.g. `us21`). Returns `null` for a key that has no such suffix, in which case
 * no Marketing endpoint can be addressed and the ladder reports DENIED.
 */
function datacenterOf(key: string): string | null {
  const dash = key.lastIndexOf("-");
  if (dash < 0 || dash === key.length - 1) {
    return null;
  }
  return key.slice(dash + 1);
}

/**
 * Run the ordered Mailchimp capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs `api-root` first and only descends into the deeper SAFE rung if the
 * key authenticated. The mutating `add-list-member` rung is GATED and, because
 * its URL needs a `{list_id}` the engine cannot fill, is emitted as a manual
 * safe-curl note rather than a live call. Never throws across this boundary.
 */
export async function mailchimpLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;
  const dc = datacenterOf(key);

  // --- Rung 1: api-root (SAFE) — decides live/dead ---------------------------
  const identity = await apiRoot(key, dc, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the key authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-audiences (SAFE) ---------------------------------------
    rungs.push(await listAudiences(key, dc, fetchImpl));

    // --- Rung 3: add-list-member (GATED, manual safe-curl) -------------------
    // The URL embeds a {list_id} the engine cannot fill, so this never fires a
    // live request: it is rendered as a manual note. The gated() wrapper still
    // enforces consent first, so without --prove + --i-am-authorized the rung
    // is recorded as blocked.
    rungs.push(await maybeAddListMember(consent, dc));
  }

  return new LadderResult({
    finding,
    provider: "mailchimp",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/**
 * SAFE: `GET /3.0/` is the whoami for a Mailchimp key — it returns account
 * identity (account id, login email, contact, total subscribers) and is the
 * rung that decides VALID vs DENIED.
 */
async function apiRoot(
  key: string,
  dc: string | null,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "api-root";
  if (dc === null) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: "key has no datacenter suffix (expected <32hex>-us<NN>); cannot address the API",
      evidence: { datacenter: null },
    });
  }

  let resp: Response;
  try {
    resp = await httpRequest(`https://${dc}.api.mailchimp.com/3.0/`, {
      headers: basic(key),
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
      evidence: { status: resp.status, datacenter: dc },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `key authenticates as ${String(body["login_id"] ?? body["account_id"] ?? "?")} ` +
      `(${String(body["account_name"] ?? body["email"] ?? "account")})`,
    evidence: {
      status: resp.status,
      datacenter: dc,
      account_id: body["account_id"] ?? null,
      account_name: body["account_name"] ?? null,
      login_id: body["login_id"] ?? null,
      email: body["email"] ?? null,
      total_subscribers: body["total_subscribers"] ?? null,
    },
  });
}

/**
 * SAFE: `GET /3.0/lists?count=10` enumerates the audiences/lists the key can
 * reach (names, member counts) — reachable resources, deeper than identity.
 */
async function listAudiences(
  key: string,
  dc: string | null,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-audiences";
  if (dc === null) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: "key has no datacenter suffix; cannot address the API",
      evidence: { datacenter: null },
    });
  }

  let resp: Response;
  try {
    resp = await httpRequest(`https://${dc}.api.mailchimp.com/3.0/lists`, {
      headers: basic(key),
      params: { count: "10" },
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
      detail: `could not list audiences (HTTP ${resp.status})`,
      evidence: { status: resp.status, datacenter: dc },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const lists = Array.isArray(body["lists"]) ? (body["lists"] as unknown[]) : [];
  // Record only non-secret identifiers (audience names + ids), never member PII.
  const names = lists
    .filter((l): l is Record<string, unknown> => isObject(l) && Boolean(l["name"]))
    .map((l) => l["name"] as string);
  const totalItems = typeof body["total_items"] === "number" ? (body["total_items"] as number) : names.length;
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      names.length > 0
        ? `${totalItems} audience(s); reachable: ${names.slice(0, 5).join(", ")}`
        : "no audiences reachable",
    evidence: {
      status: resp.status,
      datacenter: dc,
      total_items: totalItems,
      audiences_sample: names.slice(0, 25),
    },
  });
}

// --- gated (manual) rung -----------------------------------------------------

/** The safe curl printed for the manual gated add-member rung (secret as $KEY). */
function addMemberSafeCurl(dc: string | null): string {
  const host = dc ?? "DC";
  return (
    "curl -X POST " +
    `'https://${host}.api.mailchimp.com/3.0/lists/LIST_ID/members' ` +
    '-H "Authorization: Basic $KEY" ' +
    '-H "Content-Type: application/json" ' +
    `--data '{"email_address":"probe@example.com","status":"subscribed"}'`
  );
}

/**
 * GATED: `POST /3.0/lists/{list_id}/members` would write a subscriber into an
 * audience — state-changing and it injects into a marketing pipeline that emails
 * third parties.
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with consent this rung is MANUAL: the URL needs a
 * `{list_id}` (from `list-audiences`) the engine cannot fill, so it never fires a
 * live request — it only returns a safe curl (with the secret kept as `$KEY`) for
 * an operator to run by hand. The public ladder records it as a blocked/manual
 * note either way.
 */
export const mailchimpGatedAddMember = gated(
  "mailchimp.add-list-member",
  async (_consent: Consent, dc: string | null): Promise<ProbeResult> => {
    const name = "add-list-member";
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: needs a list_id from list-audiences; run the safe curl by hand to exercise the mutating impact",
      evidence: { manual: true, safe_curl: addMemberSafeCurl(dc) },
    });
  },
);

/**
 * Attempt the gated add-member rung; report it as blocked when consent is absent.
 *
 * The gating happens inside {@link mailchimpGatedAddMember}. Here we translate the
 * boundary's exception into a non-fatal `blocked` ProbeResult so the ladder never
 * throws; the safe curl is still surfaced so an authorized operator can run the
 * mutating step by hand.
 */
async function maybeAddListMember(consent: Consent, dc: string | null): Promise<ProbeResult> {
  try {
    return await mailchimpGatedAddMember(consent, dc);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "add-list-member",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: addMemberSafeCurl(dc) },
      });
    }
    throw exc;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register([...DETECTORS], (finding, consent) => mailchimpLadder(finding, consent));
