/**
 * PagerDuty capability ladder — prove depth of access from a leaked API key.
 *
 * Handles the TruffleHog `PagerDutyApiKey` finding: a REST API key used with the
 * `Authorization: Token token={key}` header (works for both account-level and
 * user-scoped tokens). The key alone is enough to authenticate, so the read-only
 * rungs fire live; only the impactful write needs an out-of-band value.
 *
 * Ordered ladder (identity / capability first, then depth, then impact):
 *
 *   1. `abilities`        SAFE. `GET /abilities` lists the account's enabled
 *      abilities/features — the cheapest validity + capability check. Works for
 *      account and user tokens alike. Read-only, idempotent, non-billable.
 *   2. `list-users`       SAFE. `GET /users?limit=1` enumerates the account's
 *      own operator staff — proves `users.read` scope and full-account (vs
 *      scoped) reach. Read-only, non-billable.
 *   3. `create-incident`  GATED / MANUAL. `POST /incidents` triggers a REAL
 *      incident: pages on-call responders and notifies third parties. This is
 *      the impact the program cares about — state-changing and human-notifying,
 *      so it never auto-fires. It is also MANUAL: the request needs a `From:`
 *      header (an account email) that is NOT present in the raw key, so the
 *      engine cannot fill it. Routed through {@link gated} so it is structurally
 *      unreachable without BOTH `--prove` and `--i-am-authorized "<scope>"`; even
 *      with consent it only renders a safe curl (secret kept as `$KEY`).
 *
 * The ladder never throws across its public boundary: every failure becomes a
 * {@link ProbeResult}. Secrets are held only transiently for the live HTTP calls
 * and never land in evidence; only non-secret values (ids, names, scopes,
 * counts) are recorded.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["PagerDutyApiKey"] as const;

// A single shared timeout: probes must be quick and must never hang a batch.
const TIMEOUT_MS = 10_000;

// PagerDuty REST API requires this versioned Accept header.
const ACCEPT = "application/vnd.pagerduty+json;version=2";

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
 *
 * NOTE: the only GATED rung here is MANUAL (it never fires a live call, so it is
 * never `success: true`), meaning a clean run tops out at VALID — proving live
 * impact requires the operator to run the rendered curl by hand.
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
// safe-curl rendering (for the MANUAL gated rung — no live call is made there)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl for the gated `POST /incidents` call. The token is
 * kept as a `$KEY` placeholder and the required `From:` account email as
 * `$FROM_EMAIL`; the JSON body is left as a `$BODY` placeholder. The string never
 * contains a live secret, so it is safe to print and to store.
 */
function createIncidentCurl(): string {
  const parts = ["curl", "-sS", "-X", "POST"];
  parts.push("-H", shquote("Authorization: Token token=$KEY"));
  parts.push("-H", shquote(`Accept: ${ACCEPT}`));
  parts.push("-H", shquote("Content-Type: application/json"));
  parts.push("-H", shquote("From: $FROM_EMAIL"));
  parts.push("-d", shquote("$BODY"));
  parts.push(shquote("https://api.pagerduty.com/incidents"));
  return parts.join(" ");
}

// --------------------------------------------------------------------------- //
// rung 1 — SAFE: abilities (validity + account capability)
// --------------------------------------------------------------------------- //
/**
 * SAFE: `GET /abilities` lists the account's enabled abilities/features. The
 * cheapest validity check that also reveals capability, and it works for both
 * account and user tokens. Read-only, idempotent, non-billable.
 */
async function pagerdutyAbilities(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "abilities";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.pagerduty.com/abilities", {
      headers: { Authorization: `Token token=${key}`, Accept: ACCEPT },
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

  const abilities = Array.isArray(body["abilities"]) ? (body["abilities"] as string[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `key authenticates; account has ${abilities.length} enabled abilities`,
    evidence: {
      status: resp.status,
      ability_count: abilities.length,
      // A small, bounded sample of NON-secret feature names proves capability
      // without dumping the whole list.
      abilities_sample: abilities.slice(0, 10),
    },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE: list-users (reachable-data depth / scope)
// --------------------------------------------------------------------------- //
/**
 * SAFE: `GET /users?limit=1` enumerates the account's own operator staff,
 * proving `users.read` scope and whether the token has full-account (vs scoped)
 * reach. First-party staff data, read-only, non-billable. We record only counts
 * and non-secret identifiers — never email/PII bodies.
 */
async function pagerdutyListUsers(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "list-users";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.pagerduty.com/users?limit=1", {
      headers: { Authorization: `Token token=${key}`, Accept: ACCEPT },
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
      detail: `could not enumerate users (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const users = Array.isArray(body["users"]) ? (body["users"] as Record<string, unknown>[]) : [];
  const first = users[0];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `enumerated account users (users.read confirmed; ` +
      `more=${body["more"] === true}, page total=${users.length})`,
    evidence: {
      status: resp.status,
      returned: users.length,
      more: body["more"] ?? null,
      // Non-secret identifiers from the first record only; no emails/PII bodies.
      first_user_id: first?.["id"] ?? null,
      first_user_role: first?.["role"] ?? null,
    },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — GATED / MANUAL: create-incident (real-world impact)
// --------------------------------------------------------------------------- //
/**
 * GATED / MANUAL: `POST /incidents` triggers a REAL incident — pages on-call
 * responders and notifies third parties. This is the impact the program cares
 * about: state-changing and human-notifying, so it must NEVER auto-fire.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 * and nothing is rendered as runnable. Even WITH consent it is MANUAL — the
 * request needs a `From:` account-email header that is not in the raw key, so the
 * engine cannot fill it. It therefore returns the safe curl for the operator
 * rather than firing.
 */
export const pagerdutyGatedCreateIncident = gated(
  "pagerduty.create-incident",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "create-incident";
    const curl = createIncidentCurl();
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would trigger a REAL incident (pages on-call responders, " +
        "notifies third parties). Needs a From: account-email header not in the raw " +
        `key; run by hand only when authorized: ${curl}`,
      evidence: { manual: true, billable: false, safe_curl: curl, success_status: [201] },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered PagerDuty capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. The two SAFE rungs fire live
 * (identity/capability first, then read depth) and only climb if the key
 * authenticated. The GATED `create-incident` rung is reached only through the
 * safety boundary: when consent is missing it is recorded as a blocked rung;
 * when consent is present it still only renders a safe curl (MANUAL — the From
 * email is not in the key). Never throws across this boundary.
 */
export async function pagerdutyLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // Rung 1 (SAFE): validity + capability. Identity rung — only climb deeper if
  // the key authenticated at all (ordered ladder).
  const identity = await pagerdutyAbilities(key, fetchImpl);
  rungs.push(identity);

  if (identity.success) {
    // Rung 2 (SAFE): reachable-data depth / scope.
    rungs.push(await pagerdutyListUsers(key, fetchImpl));

    // Rung 3 (GATED/MANUAL): real-world impact. Reachable only via the gated
    // wrapper; without full consent it throws GatedProbeBlocked, recorded as a
    // blocked rung (the safe curl is still surfaced as evidence). The ladder
    // never throws across its public boundary.
    const incidentCurl = createIncidentCurl();
    try {
      rungs.push(await pagerdutyGatedCreateIncident(consent));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "create-incident",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated rung blocked: ${exc.reason}`,
            evidence: {
              reason: exc.reason,
              manual: true,
              billable: false,
              safe_curl: incidentCurl,
            },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "pagerduty",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register([...DETECTORS], (finding, consent) => pagerdutyLadder(finding, consent));
