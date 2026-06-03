/**
 * Capability ladder for a GCP service-account JSON key.
 *
 * A TruffleHog `GCP` / `GCPApplicationDefaultCredentials` finding is a JSON
 * blob — `{ ... "client_email", "private_key", "token_uri",
 * "auth_provider_x509_cert_url" ... }`. It is **not** a bearer token: nothing
 * in the key can be sent verbatim to a Google API. To use it you must sign a
 * JWT with the embedded RSA `private_key` and exchange that assertion at
 * `token_uri` for a short-lived OAuth2 access token; every subsequent API call
 * carries the *minted token*, never the key itself.
 *
 * Because the engine cannot sign that JWT (and the later rungs need either the
 * minted token or a `PROJECT_ID` it cannot supply), **every rung here is
 * MANUAL**: the ladder never issues a live request. Instead each rung records
 * the exact, copy-pasteable safe curl an operator runs by hand, with the secret
 * held only as a `$KEY` placeholder so nothing secret is ever stored. The raw
 * JSON key is never persisted to evidence.
 *
 * Ordered rungs (least -> most revealing):
 *
 *   1. `mint-access-token`    `POST oauth2.googleapis.com/token` — SAFE, manual.
 *      Sign a JWT with the embedded `private_key` and exchange it
 *      (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`). A 200 proves
 *      the key is live and the SA is not disabled (identity/auth proof).
 *   2. `tokeninfo`            `GET oauth2/v3/tokeninfo` — SAFE, manual. Decode
 *      the *minted* access token to reveal the bound SA email, scopes and
 *      expiry — WHO it impersonates and WHAT scopes it carries (v3, current).
 *   3. `list-projects`        `GET cloudresourcemanager.googleapis.com/v1/projects`
 *      — SAFE, manual. Enumerate every project the SA can see (depth/reach),
 *      `Authorization: Bearer <minted token>`.
 *   4. `list-storage-buckets` `GET storage.googleapis.com/storage/v1/b` — GATED,
 *      manual. Lists Cloud Storage buckets in a target project — the doorway to
 *      reading/exfiltrating bucket objects (third-party PII). Needs a
 *      `PROJECT_ID` from rung 3 plus the minted Bearer, so it can never
 *      auto-fire; it is rendered as a gated, manual note.
 *
 * The public entry point is {@link gcpLadder}; it never throws across its
 * boundary — every rung is captured as a {@link ProbeResult} and the verdict
 * reflects what (if anything) was proven. With every rung manual, no automated
 * capability is exercised, so the automated verdict is DENIED until an operator
 * runs the curls by hand.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
const DETECTORS = ["GCP", "GCPApplicationDefaultCredentials"];

// The minted-token placeholder. In rungs 2-4 the spec's `{key}` means the
// short-lived OAuth2 access token you mint in rung 1 — NOT the raw JSON key —
// so the safe curl carries `$TOKEN`. Rung 1's body needs a signed JWT the
// engine cannot produce, so it too is manual.
const TOKEN_PLACEHOLDER = "$TOKEN";
// A literal placeholder the operator fills from rung 3's output.
const PROJECT_PLACEHOLDER = "PROJECT_ID";

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID.
 * - Nothing succeeded (all manual / refused) -> DENIED.
 *
 * Every rung in this ladder is manual, so in practice this returns DENIED: no
 * automated probe can succeed when the engine cannot mint the token.
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

/** Minimal single-quote shell quoting for a printable safe curl. */
function shquote(value: string): string {
  return "'" + value.split("'").join("'\\''") + "'";
}

/**
 * Build a copy-pasteable safe curl. Secrets are NEVER interpolated: the JSON
 * key stays `$KEY`, the minted token stays `$TOKEN`. Safe to print and store.
 */
function safeCurl(args: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  data?: string;
}): string {
  const parts = ["curl", "-sS", "-X", args.method];
  for (const [name, value] of Object.entries(args.headers ?? {})) {
    parts.push("-H", shquote(`${name}: ${value}`));
  }
  if (args.data !== undefined) {
    parts.push("--data", shquote(args.data));
  }
  parts.push(shquote(args.url));
  return parts.join(" ");
}

/**
 * A SAFE manual rung: the engine cannot fill the placeholder (signed JWT or
 * minted token), so it never makes a live call — it hands the operator the
 * exact curl. Recorded as success=false with `manual:true` evidence; the raw
 * key never appears (only `$KEY` / `$TOKEN`).
 */
function manualRung(name: string, curl: string, proves: string): ProbeResult {
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail: `MANUAL (needs a minted OAuth2 token; no live call): ${proves} Run by hand: ${curl}`,
    evidence: { manual: true, safe_curl: curl, proves },
  });
}

// --------------------------------------------------------------------------
// rung 1 — SAFE (manual): mint the OAuth2 access token.
// --------------------------------------------------------------------------
/**
 * SAFE manual rung. Sign a JWT with the embedded `private_key` and exchange it
 * at `token_uri` for a short-lived access token. A 200 proves the JSON key is
 * live and the SA is not disabled (identity/auth proof). The engine cannot sign
 * the JWT, so this is rendered as a safe curl only.
 */
function mintAccessToken(): ProbeResult {
  const curl = safeCurl({
    method: "POST",
    url: "https://oauth2.googleapis.com/token",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    data: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$SIGNED_JWT",
  });
  return manualRung(
    "mint-access-token",
    curl,
    "A 200 proves the JSON key is live and the SA is not disabled: signing a JWT " +
      "with the embedded private_key and exchanging it returns a valid OAuth2 access token.",
  );
}

// --------------------------------------------------------------------------
// rung 2 — SAFE (manual): tokeninfo on the minted token.
// --------------------------------------------------------------------------
/**
 * SAFE manual rung. Decode the *minted* access token to reveal the bound SA
 * email, scopes and expiry — confirms WHO it impersonates and WHAT scopes it
 * carries. Uses the current oauth2/v3 endpoint (v1 is deprecated). The
 * `access_token` is the minted token, which the engine does not hold, so this
 * is a safe curl only.
 */
function tokeninfo(): ProbeResult {
  const curl = safeCurl({
    method: "GET",
    url: `https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${TOKEN_PLACEHOLDER}`,
  });
  return manualRung(
    "tokeninfo",
    curl,
    "Decodes the minted access token to reveal the bound SA email, scopes and expiry " +
      "(WHO it impersonates and WHAT scopes it carries). Read-only, v3 (current) endpoint.",
  );
}

// --------------------------------------------------------------------------
// rung 3 — SAFE (manual): list every project the SA can see.
// --------------------------------------------------------------------------
/**
 * SAFE manual rung. Enumerate every GCP project the SA can see
 * (`resourcemanager.projects.get`) — depth/reach across the org. Read-only
 * listing, authenticated via `Bearer <minted token>`, which the engine does
 * not hold, so this is a safe curl only.
 */
function listProjects(): ProbeResult {
  const curl = safeCurl({
    method: "GET",
    url: "https://cloudresourcemanager.googleapis.com/v1/projects",
    headers: { Authorization: `Bearer ${TOKEN_PLACEHOLDER}` },
  });
  return manualRung(
    "list-projects",
    curl,
    "Enumerates every GCP project the SA can see (resourcemanager.projects.get) — " +
      "depth/reach across the org. Read-only listing via Bearer <minted token>.",
  );
}

// --------------------------------------------------------------------------
// rung 4 — GATED (manual): list Cloud Storage buckets in a target project.
// --------------------------------------------------------------------------
/**
 * GATED manual rung. Lists Cloud Storage buckets in a target project
 * (`storage.buckets.list`) — the doorway to reading/exfiltrating bucket objects
 * which may hold third-party PII. It requires BOTH a `PROJECT_ID` from rung 3
 * and the minted Bearer token, so it can never auto-fire.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without `--prove` + `--i-am-authorized` it throws {@link GatedProbeBlocked}.
 * Even when consent IS granted, the body still cannot make a live call (no
 * minted token, unfilled `PROJECT_ID`), so it always renders the safe curl as a
 * gated manual note rather than firing.
 */
const gcpGatedListStorageBuckets = gated(
  "gcp.list-storage-buckets",
  async (_consent: Consent): Promise<ProbeResult> => {
    const curl = safeCurl({
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b?project=${PROJECT_PLACEHOLDER}`,
      headers: { Authorization: `Bearer ${TOKEN_PLACEHOLDER}` },
    });
    const proves =
      "Lists Cloud Storage buckets in a target project (storage.buckets.list) — the " +
      "doorway to reading/exfiltrating bucket objects which may hold third-party PII. " +
      "Requires a PROJECT_ID from list-projects and the minted Bearer token.";
    return new ProbeResult({
      name: "list-storage-buckets",
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail: `GATED + MANUAL (needs PROJECT_ID + minted token; no live call): ${proves} Run by hand: ${curl}`,
      evidence: { manual: true, safe_curl: curl, proves },
    });
  },
);

/**
 * Climb the GCP service-account capability ladder for a finding.
 *
 * Every rung is MANUAL (the engine cannot mint the OAuth2 token), so the ladder
 * issues no network I/O: it records the safe curls for the operator to run by
 * hand. The gated bucket-list rung is routed through the safety {@link guard}
 * via {@link gated}; without consent it is recorded as a blocked rung. Never
 * throws across this boundary.
 */
export async function gcpLadder(
  finding: Finding,
  consent: Consent,
  _options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  // The ladder (even its safe, manual tier) refuses to run without a named scope.
  const scope = consent.requireLadderScope();

  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE, manual): the identity/auth proof — must be first.
  rungs.push(mintAccessToken());
  // Ordered: the deeper rungs all depend on the minted token from rung 1.
  rungs.push(tokeninfo());
  rungs.push(listProjects());

  // Rung 4 (GATED, manual): bucket enumeration. Reachable only via the safety
  // boundary. Without consent the gated wrapper throws GatedProbeBlocked, which
  // we record as a blocked rung; with consent it still only renders the safe
  // curl (no live call is possible). Never let either escape.
  try {
    rungs.push(await gcpGatedListStorageBuckets(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      const curl = safeCurl({
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b?project=${PROJECT_PLACEHOLDER}`,
        headers: { Authorization: `Bearer ${TOKEN_PLACEHOLDER}` },
      });
      rungs.push(
        new ProbeResult({
          name: "list-storage-buckets",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: { manual: true, safe_curl: curl, reason: exc.reason },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "gcp",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(DETECTORS, (finding, consent) => gcpLadder(finding, consent));
