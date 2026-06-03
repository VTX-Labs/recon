/**
 * Cloudflare capability ladder — prove depth of access for a leaked API token.
 *
 * Handles TruffleHog `CloudflareApiToken`, `CloudflareGlobalApiKey`, and
 * `CloudflareCaKey` findings. A Cloudflare scoped API token is 40 chars of
 * `[A-Za-z0-9_-]` and authenticates with `Authorization: Bearer <token>`. The
 * Global API Key (`X-Auth-Email` + `X-Auth-Key`) and the origin-CA key route
 * here too; the ladder below uses the Bearer form, which is the dominant and
 * TruffleHog-verified shape.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `verify-token`      `GET /user/tokens/verify` — TruffleHog's own
 *      verification call. Confirms the token authenticates and returns its id,
 *      `status:active`, and `not_before`/`expires_on`. Read-only, idempotent.
 *      This is the rung that decides VALID vs DENIED.
 *   2. `token-permissions` `GET /user/tokens/permission_groups` — enumerates
 *      the permission groups available/assignable, mapping the token's scope
 *      depth (DNS edit, Workers, zone read). Read-only enumeration.
 *   3. `list-zones`        `GET /zones` — enumerates every domain/zone the
 *      token can reach (zone ids, names, account) — depth into the DNS estate.
 *      Read-only listing of owned resources.
 *   4. `edit-dns-record`   `POST /zones/{ZONE_ID}/dns_records` — GATED, mutating.
 *      Creating/changing a DNS record is state-changing impact (subdomain
 *      takeover, MX/traffic hijack). Its URL needs a `ZONE_ID` the engine
 *      cannot fill, so this rung is rendered as a MANUAL safe-curl note: it is
 *      never auto-fired and prints a curl that keeps the secret as `$KEY`.
 *
 * Every rung is ordered (identity first, then depth), the live rungs are all
 * READ-ONLY GETs, and the ladder never throws across its public boundary:
 * failures become a {@link ProbeResult} with `success=false`. The raw token is
 * held only transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = [
  "CloudflareApiToken",
  "CloudflareGlobalApiKey",
  "CloudflareCaKey",
] as const;

const API_BASE = "https://api.cloudflare.com/client/v4";

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

/** Standard Cloudflare bearer header for a scoped API token. */
function bearer(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}` };
}

/**
 * Run the ordered Cloudflare capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs `verify-token` first and only descends into the deeper SAFE rungs if
 * the token authenticated. The mutating `edit-dns-record` rung is GATED and,
 * because its URL needs a `ZONE_ID` the engine cannot fill, is emitted as a
 * manual safe-curl note rather than a live call. Never throws across this
 * boundary.
 */
export async function cloudflareLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: verify-token (SAFE) — decides live/dead -----------------------
  const identity = await verifyToken(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: token-permissions (SAFE) ------------------------------------
    rungs.push(await tokenPermissions(key, fetchImpl));

    // --- Rung 3: list-zones (SAFE) -------------------------------------------
    rungs.push(await listZones(key, fetchImpl));

    // --- Rung 4: edit-dns-record (GATED, manual safe-curl) -------------------
    // The URL embeds a ZONE_ID the engine cannot fill, so this never fires a
    // live request: it is rendered as a manual note. The gated() wrapper still
    // enforces consent first, so without --prove + --i-am-authorized the rung
    // is recorded as blocked.
    rungs.push(await maybeEditDnsRecord(consent));
  }

  return new LadderResult({
    finding,
    provider: "cloudflare",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/** SAFE: `GET /user/tokens/verify` confirms the token and returns its status. */
async function verifyToken(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "verify-token";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/user/tokens/verify`, {
      headers: bearer(key),
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

  // Cloudflare wraps payloads as { success, result, errors, messages }.
  const result = (body["result"] as Record<string, unknown> | undefined) ?? {};
  const ok = body["success"] === true && (result["status"] ?? null) === "active";
  if (!ok) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `token not active (status ${String(result["status"] ?? "unknown")})`,
      evidence: { status: resp.status, token_status: result["status"] ?? null },
    });
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `token active (id ${String(result["id"] ?? "?")})`,
    evidence: {
      status: resp.status,
      token_id: result["id"] ?? null,
      token_status: result["status"] ?? null,
      not_before: result["not_before"] ?? null,
      expires_on: result["expires_on"] ?? null,
    },
  });
}

/** SAFE: `GET /user/tokens/permission_groups` maps the token's scope depth. */
async function tokenPermissions(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "token-permissions";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/user/tokens/permission_groups`, {
      headers: bearer(key),
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
      detail: `could not list permission groups (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const groups = Array.isArray(body["result"]) ? (body["result"] as unknown[]) : [];
  // Record only non-secret identifiers (group names), never raw payloads.
  const names = groups
    .filter((g): g is Record<string, unknown> => isObject(g) && Boolean(g["name"]))
    .map((g) => g["name"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `${names.length} permission group(s) assignable to this token`,
    evidence: {
      status: resp.status,
      permission_group_count: names.length,
      permission_groups_sample: names.slice(0, 25),
    },
  });
}

/** SAFE: `GET /zones` enumerates every zone/domain the token can reach. */
async function listZones(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-zones";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/zones`, {
      headers: bearer(key),
      params: { per_page: "50" },
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
      detail: `could not list zones (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const zones = Array.isArray(body["result"]) ? (body["result"] as unknown[]) : [];
  // Record only non-sensitive identifiers (zone names), never DNS contents.
  const names = zones
    .filter((z): z is Record<string, unknown> => isObject(z) && Boolean(z["name"]))
    .map((z) => z["name"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: names.length > 0,
    detail:
      names.length > 0 ? `${names.length} zone(s) reachable: ${names.slice(0, 5).join(", ")}` : "no zones reachable",
    evidence: {
      status: resp.status,
      zone_count: names.length,
      zones_sample: names.slice(0, 25),
    },
  });
}

// --- gated (manual) rung -----------------------------------------------------

/**
 * GATED: `POST /zones/{ZONE_ID}/dns_records` would create/change a DNS record —
 * state-changing impact (subdomain takeover, MX/traffic hijack).
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body and,
 * without BOTH `--prove` and an authorized scope, throws {@link GatedProbeBlocked}
 * and nothing executes. Even with consent this rung is MANUAL: the URL needs a
 * `ZONE_ID` the engine cannot fill, so it never fires a live request — it only
 * returns a safe curl (with the secret kept as `$KEY`) for an operator to run by
 * hand. The public ladder records it as a blocked/manual note either way.
 */
export const cloudflareGatedEditDns = gated(
  "cloudflare.edit-dns-record",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "edit-dns-record";
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: needs a ZONE_ID from list-zones; run the safe curl by hand to exercise the mutating impact",
      evidence: { manual: true, safe_curl: editDnsSafeCurl() },
    });
  },
);

/** The safe curl printed for the manual gated DNS-write rung (secret as $KEY). */
function editDnsSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${API_BASE}/zones/ZONE_ID/dns_records' ` +
    '-H "Authorization: Bearer $KEY" ' +
    '-H "Content-Type: application/json" ' +
    `--data '{"type":"A","name":"probe.example.com","content":"192.0.2.1","ttl":60,"proxied":false}'`
  );
}

/**
 * Attempt the gated DNS-write rung; report it as blocked when consent is absent.
 *
 * The gating happens inside {@link cloudflareGatedEditDns}. Here we translate the
 * boundary's exception into a non-fatal `blocked` ProbeResult so the ladder never
 * throws; the safe curl is still surfaced so an authorized operator can run the
 * mutating step by hand.
 */
async function maybeEditDnsRecord(consent: Consent): Promise<ProbeResult> {
  try {
    return await cloudflareGatedEditDns(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "edit-dns-record",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: editDnsSafeCurl() },
      });
    }
    throw exc;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register([...DETECTORS], (finding, consent) => cloudflareLadder(finding, consent));
