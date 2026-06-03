/**
 * Mailgun capability ladder — prove depth of access for a leaked API key.
 *
 * Handles TruffleHog `Mailgun` findings. A Mailgun key is either the legacy
 * `key-<32 hex/alnum>` form or the newer `<32 hex>-<8 hex>-<8 hex>` form, and
 * authenticates as the password of HTTP Basic auth (username `api`). Per the
 * provider spec the header is rendered as `Authorization: Basic {key}`, where
 * the engine substitutes `{key}` with the live secret before the call.
 *
 * Mailgun has NO whoami endpoint, so the domains list doubles as the identity
 * proof and the depth proof — it is also the family TruffleHog probes.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `list-domains`      `GET /v4/domains?limit=10` — confirms the key
 *      authenticates and reveals which sending domains it can reach (reachable
 *      resources you own). This is the identity/depth rung and decides VALID vs
 *      DENIED. Read-only, non-billable.
 *   2. `list-domain-keys`  `GET /v1/dkim/keys?limit=10` — reads DKIM signing-key
 *      metadata across all domains, confirming account-wide read depth beyond a
 *      single domain. Read-only, non-billable.
 *   3. `send-message`      `POST /v3/{domain}/messages` — GATED, billable and
 *      reputation-impacting (sends email on the victim's domain). Its URL needs
 *      a `{domain}` path segment (from `list-domains`) the engine cannot fill,
 *      so this rung is rendered as a MANUAL safe-curl note: it is never
 *      auto-fired and prints a curl that keeps the secret as `$KEY`.
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
export const DETECTORS = ["Mailgun"] as const;

const API_BASE = "https://api.mailgun.net";

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

/** Mailgun HTTP Basic header per the provider spec (`Basic {key}`). */
function basicAuth(key: string): Record<string, string> {
  return { Authorization: `Basic ${key}` };
}

/**
 * Run the ordered Mailgun capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs `list-domains` first (Mailgun has no whoami) and only descends into
 * the deeper SAFE rung if the key authenticated. The billable `send-message`
 * rung is GATED and, because its URL needs a `{domain}` segment the engine
 * cannot fill, is emitted as a manual safe-curl note rather than a live call.
 * Never throws across this boundary.
 */
export async function mailgunLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: list-domains (SAFE) — identity/depth, decides live/dead -------
  const identity = await listDomains(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the key authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: list-domain-keys (SAFE) -------------------------------------
    rungs.push(await listDomainKeys(key, fetchImpl));

    // --- Rung 3: send-message (GATED, manual safe-curl) ----------------------
    // The URL embeds a {domain} segment the engine cannot fill, so this never
    // fires a live request: it is rendered as a manual note. The gated()
    // wrapper still enforces consent first, so without --prove +
    // --i-am-authorized the rung is recorded as blocked.
    rungs.push(await maybeSendMessage(consent));
  }

  return new LadderResult({
    finding,
    provider: "mailgun",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/**
 * SAFE: `GET /v4/domains?limit=10` confirms the key and lists reachable sending
 * domains. Mailgun has no whoami; this list is the identity AND the depth
 * proof. Records only non-secret domain names/states, never message contents.
 */
async function listDomains(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-domains";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v4/domains`, {
      headers: basicAuth(key),
      params: { limit: "10" },
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

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const items = Array.isArray(body["items"]) ? (body["items"] as unknown[]) : [];
  // Record only non-secret identifiers (domain names), never message data.
  const names = items
    .filter((d): d is Record<string, unknown> => isObject(d) && Boolean(d["name"]))
    .map((d) => d["name"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      names.length > 0
        ? `key authenticates; ${names.length} domain(s) reachable: ${names.slice(0, 5).join(", ")}`
        : "key authenticates; no sending domains reachable",
    evidence: {
      status: resp.status,
      domain_count: names.length,
      domains_sample: names.slice(0, 25),
      total_count: typeof body["total_count"] === "number" ? body["total_count"] : null,
    },
  });
}

/**
 * SAFE: `GET /v1/dkim/keys?limit=10` reads DKIM signing-key metadata across all
 * domains, confirming account-wide read depth beyond a single domain. Records
 * only non-secret metadata (counts / signing domains), never private key
 * material.
 */
async function listDomainKeys(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-domain-keys";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v1/dkim/keys`, {
      headers: basicAuth(key),
      params: { limit: "10" },
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
      detail: `could not read DKIM keys (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const items = Array.isArray(body["items"]) ? (body["items"] as unknown[]) : [];
  // Record only the signing-domain names (non-secret), never key material.
  const signing = items
    .filter((k): k is Record<string, unknown> => isObject(k) && Boolean(k["signing_domain"]))
    .map((k) => k["signing_domain"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `${items.length} DKIM signing-key record(s) readable account-wide`,
    evidence: {
      status: resp.status,
      dkim_key_count: items.length,
      signing_domains_sample: signing.slice(0, 25),
    },
  });
}

// --- gated (manual) rung -----------------------------------------------------

/** The safe curl printed for the manual gated send-message rung (secret as $KEY). */
function sendMessageSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${API_BASE}/v3/DOMAIN/messages' ` +
    '-H "Authorization: Basic $KEY" ' +
    '-H "Content-Type: application/x-www-form-urlencoded" ' +
    "--data-urlencode 'from=probe@DOMAIN' " +
    "--data-urlencode 'to=you@example.com' " +
    "--data-urlencode 'subject=vtx-recon authorized probe' " +
    "--data-urlencode 'text=authorized capability proof'"
  );
}

/**
 * GATED: `POST /v3/{domain}/messages` would send email on the victim's domain —
 * billable and reputation-impacting impact (the action the program cares about).
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with consent this rung is MANUAL: the URL needs a
 * `{domain}` segment (from `list-domains`) the engine cannot fill, so it never
 * fires a live request — it only returns a safe curl (with the secret kept as
 * `$KEY`) for an operator to run by hand. The public ladder records it as a
 * blocked/manual note either way.
 */
export const mailgunGatedSendMessage = gated(
  "mailgun.send-message",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "send-message";
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: needs a {domain} from list-domains; run the safe curl by hand to exercise the billable send impact",
      evidence: { manual: true, safe_curl: sendMessageSafeCurl() },
    });
  },
);

/**
 * Attempt the gated send-message rung; report it as blocked when consent is absent.
 *
 * The gating happens inside {@link mailgunGatedSendMessage}. Here we translate the
 * boundary's exception into a non-fatal `blocked` ProbeResult so the ladder never
 * throws; the safe curl is still surfaced so an authorized operator can run the
 * billable step by hand.
 */
async function maybeSendMessage(consent: Consent): Promise<ProbeResult> {
  try {
    return await mailgunGatedSendMessage(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "send-message",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: sendMessageSafeCurl() },
      });
    }
    throw exc;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register([...DETECTORS], (finding, consent) => mailgunLadder(finding, consent));
