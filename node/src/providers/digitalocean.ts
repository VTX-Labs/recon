/**
 * DigitalOcean capability ladder — prove depth of access from a leaked token.
 *
 * A TruffleHog `DigitalOceanV2` / `DigitalOceanToken` finding is a modern
 * DigitalOcean credential — a Personal Access Token or OAuth token shaped
 * `dop_v1_` / `doo_v1_` / `dor_v1_` followed by 64 hex chars. Every rung uses
 * the same `Authorization: Bearer {key}` header against `api.digitalocean.com`.
 *
 * The ordered ladder (least -> most revealing, then impact):
 *
 *   1. `account`        SAFE. `GET /v2/account` — TruffleHog's own verification
 *      call. Returns the account email, uuid, status and resource limits:
 *      confirms the token authenticates and reveals the owning account.
 *      Read-only; decides VALID vs DENIED.
 *   2. `list-droplets`  SAFE. `GET /v2/droplets` — enumerates every droplet the
 *      token can reach (`droplet:read`): depth of access into compute, public
 *      IPs, regions. A read-only listing of owned resources.
 *   3. `create-droplet` GATED. `POST /v2/droplets` — would provision a new
 *      *billable* droplet (a 202-Accepted, state-changing, crypto-mining/abuse
 *      vector). Routed through {@link gated} so the SAFE tier can never reach
 *      it, AND — because creation needs a request body the engine cannot fill
 *      from `{key}` alone (name/region/size/image) — it never auto-fires even
 *      under full consent: it renders a safe curl only, so no billable droplet
 *      is ever created and the "no state changed" attestation holds.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false`. The raw token is held only transiently for the HTTP call
 * and only non-secret fields ever land in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

const API_BASE = "https://api.digitalocean.com";

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

/**
 * DigitalOcean ladder: SAFE account whoami -> SAFE droplet listing ->
 * GATED (never-auto-fired) droplet creation.
 */
export async function digitaloceanLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // Rung 1 (SAFE): identity / whoami. Decides VALID vs DENIED.
  const identity = await doAccount(key, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token actually authenticated (ordered ladder).
  if (identity.success) {
    // Rung 2 (SAFE): enumerate reachable droplets (depth of compute access).
    rungs.push(await doListDroplets(key, fetchImpl));

    // Rung 3 (GATED): droplet creation. Reachable only with full consent; even
    // then it never fires a real POST (creation is billable and needs a body
    // the engine cannot fill) — the gated wrapper throws GatedProbeBlocked when
    // consent is absent, otherwise we render a safe curl. Either way we record
    // a non-success rung so the "no state changed" attestation holds.
    try {
      rungs.push(await doCreateDropletGated(consent, key));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "create-droplet",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: { manual: true, reason: exc.reason, safe_curl: createDropletCurl() },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "digitalocean",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /v2/account` — TruffleHog's verification call.
 *
 * Returns the account email, uuid, status and resource limits, proving the
 * token is live and revealing the owning account. Read-only; no billable
 * action. Success here is the difference between VALID and DENIED.
 */
async function doAccount(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "account";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v2/account`, {
      headers: { Authorization: `Bearer ${key}` },
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
  const account = (body["account"] as Record<string, unknown> | undefined) ?? {};

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `authenticated as ${account["email"] ?? "unknown"} ` +
      `(status ${account["status"] ?? "?"})`,
    evidence: {
      status: resp.status,
      email: account["email"] ?? null,
      uuid: account["uuid"] ?? null,
      account_status: account["status"] ?? null,
      droplet_limit: account["droplet_limit"] ?? null,
      email_verified: account["email_verified"] ?? null,
    },
  });
}

/**
 * SAFE: `GET /v2/droplets` — enumerate every droplet the token can reach.
 *
 * Proves depth of access into compute (`droplet:read`): how many droplets, in
 * which regions, with which public IPs. Read-only listing of owned resources;
 * only non-secret identifiers (ids, names, regions, counts) are recorded.
 */
async function doListDroplets(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "list-droplets";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v2/droplets`, {
      headers: { Authorization: `Bearer ${key}` },
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
      detail: `could not list droplets (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const droplets = Array.isArray(body["droplets"])
    ? (body["droplets"] as Array<Record<string, unknown>>)
    : [];
  // Record only non-sensitive identifiers — never any droplet's contents.
  const names = droplets
    .map((d) => (typeof d["name"] === "string" ? (d["name"] as string) : null))
    .filter((n): n is string => Boolean(n));
  const regions = [
    ...new Set(
      droplets
        .map((d) => {
          const region = d["region"] as Record<string, unknown> | undefined;
          return region && typeof region["slug"] === "string" ? (region["slug"] as string) : null;
        })
        .filter((r): r is string => Boolean(r)),
    ),
  ].sort();

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: droplets.length > 0,
    detail:
      droplets.length > 0
        ? `${droplets.length} droplet(s) reachable across ${regions.length} region(s)`
        : "no droplets reachable (token may still create new ones)",
    evidence: {
      status: resp.status,
      droplet_count: droplets.length,
      regions,
      droplet_names_sample: names.slice(0, 25),
    },
  });
}

/**
 * The safe, copy-pasteable curl an operator would run by hand to exercise the
 * gated creation — with the secret kept as the `$DO_TOKEN` shell variable so it
 * is never rendered into evidence. This is what the gated rung prints instead
 * of provisioning anything.
 */
function createDropletCurl(): string {
  return (
    'curl -sS -X POST "https://api.digitalocean.com/v2/droplets" ' +
    '-H "Authorization: Bearer $DO_TOKEN" -H "Content-Type: application/json" ' +
    `-d '{"name":"authorized-probe","region":"nyc3","size":"s-1vcpu-1gb","image":"ubuntu-22-04-x64"}'`
  );
}

/**
 * GATED: `POST /v2/droplets` would provision a new *billable* droplet.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and nothing is sent. Even WITH full consent we do
 * not fire the POST — droplet creation is billable and irreversible, and the
 * request body (name/region/size/image) is operator-supplied data the engine
 * cannot fill from `{key}`. So this rung is manual by design: it renders a safe
 * curl and returns a non-success result, never creating a droplet.
 */
export const doCreateDropletGated = gated(
  "digitalocean.create-droplet",
  async (_consent: Consent, _key: string): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "create-droplet",
      tier: ProbeTier.GATED,
      success: false,
      // Consent WAS granted (the gated boundary let this body run), so this is
      // not a `blocked` rung — it is a deliberate MANUAL no-op: the request body
      // (name/region/size/image) cannot be filled from `{key}`, so we render a
      // safe curl instead of provisioning a billable droplet.
      blocked: false,
      detail:
        "gated billable action: droplet creation is never auto-run " +
        "(state-changing, returns 202); run the safe curl by hand if authorized",
      evidence: { manual: true, safe_curl: createDropletCurl(), success_status: 202 },
    });
  },
);

register(["DigitalOceanV2", "DigitalOceanToken"], (finding, consent) =>
  digitaloceanLadder(finding, consent),
);
