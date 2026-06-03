/**
 * Algolia capability ladder — prove depth of access from a leaked Admin API key.
 *
 * A TruffleHog `AlgoliaAdminKey` finding is a 32-hex API key. Algolia, however,
 * authenticates with TWO halves: the API key AND the application's
 * **Application ID**, sent together in `X-Algolia-API-Key` /
 * `X-Algolia-Application-Id`. The App ID is NOT contained in the 32-hex key and
 * TruffleHog does not pair it on the finding, so the engine cannot fill the
 * `{appid}` placeholder that every Algolia endpoint requires. Per the ladder
 * conventions, a rung whose URL/headers need any placeholder other than `{key}`
 * MUST be MANUAL: vtx-recon never fires a live request it cannot fully address.
 * Each rung therefore records the exact, copy-pasteable **safe curl** (with the
 * secret kept as `$KEY` and the App ID as `$APP_ID`) for an operator to run by
 * hand once they supply the App ID.
 *
 * Rungs (ordered by blast radius):
 *
 *   1. `get-own-key-acl` — SAFE/MANUAL. `GET /1/keys/{key}` is the key's own
 *      whoami: it returns the ACL (addObject, deleteIndex, settings,
 *      listIndexes), index scope, validity and rate limits — exactly how
 *      powerful the leaked key is. Read-only, non-billable.
 *   2. `list-all-keys` — SAFE/MANUAL. `GET /1/keys` only succeeds for an
 *      admin-capable key, so success proves admin privileges: the deepest auth
 *      proof short of writing. Read-only, non-billable.
 *   3. `list-indices` — SAFE/MANUAL. `GET /1/indexes` enumerates every index
 *      (record counts, sizes) the key can reach. Read-only, non-billable.
 *   4. `clear-index` — GATED/MANUAL. `POST /1/indexes/{index}/clear` deletes all
 *      records from an index — destructive, state-changing — the worst-case
 *      write impact an admin key enables. Routed through {@link gated} so it is
 *      structurally unreachable without BOTH `--prove` and an authorized scope;
 *      even with consent it is rendered as a manual safe-curl note and never
 *      auto-fired (the engine cannot fill `{appid}`/`{index}`).
 *
 * The ladder never throws across its public boundary: every outcome is a
 * {@link ProbeResult}, and a key that authenticates nowhere here (because no
 * rung can run automatically) is reported with the manual curls so a human can
 * complete the proof.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { type FetchLike } from "./http.js";
import { register } from "./registry.js";

// Placeholder the engine fills with the live secret. ANY other placeholder
// (notably {appid} / {index}) cannot be filled -> the rung must be MANUAL.
// Because every Algolia rung is MANUAL, this ladder makes NO live HTTP call:
// the `fetchImpl` option is accepted only for signature parity with the other
// providers, and no `networkFailure`/`HttpError` path is reachable.
const KEY_PLACEHOLDER = "{key}";

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID (authenticates + depth shown).
 * - The key authenticated nowhere (all manual / refused) -> DENIED.
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

/** Minimal single-quote shell quoting for the printable safe curl. */
function shquote(value: string): string {
  return "'" + value.split("'").join("'\\''") + "'";
}

/**
 * Build a copy-pasteable curl with NO secret material: the live key is replaced
 * by `$KEY` and the unfillable `{appid}` / `{index}` placeholders are rendered
 * as `$APP_ID` / `$INDEX` for the operator to substitute. Safe to print and to
 * store in evidence.
 */
function safeCurl(method: string, url: string, headers: Record<string, string>): string {
  const render = (s: string): string =>
    s
      .split(KEY_PLACEHOLDER)
      .join("$KEY")
      .split("{appid}")
      .join("$APP_ID")
      .split("{index}")
      .join("$INDEX");
  const parts = ["curl", "-sS", "-X", method];
  for (const [headerName, headerValue] of Object.entries(headers)) {
    parts.push("-H", shquote(`${headerName}: ${render(headerValue)}`));
  }
  parts.push(shquote(render(url)));
  return parts.join(" ");
}

/**
 * Render a MANUAL safe rung: no live call (a non-`{key}` placeholder is
 * present), record the safe curl so an operator can run it by hand.
 */
function manualRung(
  name: string,
  tier: ProbeTier,
  method: string,
  url: string,
  headers: Record<string, string>,
  proves: string,
): ProbeResult {
  const curl = safeCurl(method, url, headers);
  return new ProbeResult({
    name,
    tier,
    success: false,
    blocked: false,
    detail: `MANUAL (App ID required; engine cannot fill {appid}): ${proves} Run by hand: ${curl}`,
    evidence: { manual: true, safe_curl: curl },
  });
}

// The exact URL/headers for the destructive clear, reused by both the gated
// body and the blocked-rung note so the two render identical safe curls.
const CLEAR_INDEX_URL = "https://{appid}.algolia.net/1/indexes/{index}/clear";
const CLEAR_INDEX_HEADERS: Record<string, string> = {
  "X-Algolia-API-Key": "{key}",
  "X-Algolia-Application-Id": "{appid}",
  "Content-Type": "application/json",
};

// --------------------------------------------------------------------------- //
// rung 1 — SAFE/MANUAL: get-own-key-acl
// --------------------------------------------------------------------------- //
/**
 * SAFE: `GET /1/keys/{key}` — whoami for the key itself. Returns its ACL,
 * index scope, validity and rate limits: exactly how powerful the leaked key
 * is. Read-only, non-billable. MANUAL because the host carries `{appid}`.
 */
function algoliaGetOwnKeyAcl(): ProbeResult {
  return manualRung(
    "get-own-key-acl",
    ProbeTier.SAFE,
    "GET",
    "https://{appid}.algolia.net/1/keys/{key}",
    {
      "X-Algolia-API-Key": "{key}",
      "X-Algolia-Application-Id": "{appid}",
      Accept: "application/json",
    },
    "Whoami for the key itself — returns its ACL (addObject, deleteIndex, settings, " +
      "listIndexes), index scope, validity and rate limits; reveals exactly how powerful " +
      "the leaked key is. Read-only, non-billable.",
  );
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE/MANUAL: list-all-keys
// --------------------------------------------------------------------------- //
/**
 * SAFE: `GET /1/keys` — only an admin-capable key can list ALL of the
 * application's API keys, so success proves admin privileges (the deepest auth
 * proof short of writing). Read-only, non-billable. MANUAL (App ID).
 */
function algoliaListAllKeys(): ProbeResult {
  return manualRung(
    "list-all-keys",
    ProbeTier.SAFE,
    "GET",
    "https://{appid}.algolia.net/1/keys",
    {
      "X-Algolia-API-Key": "{key}",
      "X-Algolia-Application-Id": "{appid}",
      Accept: "application/json",
    },
    "Only an admin-capable key can list ALL of the application's API keys — success proves " +
      "admin privileges, the deepest auth proof short of writing. Read-only, non-billable.",
  );
}

// --------------------------------------------------------------------------- //
// rung 3 — SAFE/MANUAL: list-indices
// --------------------------------------------------------------------------- //
/**
 * SAFE: `GET /1/indexes` — enumerates every index with record counts and sizes
 * (requires the listIndexes ACL): which searchable datasets the key can reach.
 * Read-only, non-billable. MANUAL (App ID).
 */
function algoliaListIndices(): ProbeResult {
  return manualRung(
    "list-indices",
    ProbeTier.SAFE,
    "GET",
    "https://{appid}.algolia.net/1/indexes",
    {
      "X-Algolia-API-Key": "{key}",
      "X-Algolia-Application-Id": "{appid}",
      Accept: "application/json",
    },
    "Enumerates every index with record counts and sizes (requires listIndexes ACL) — which " +
      "searchable datasets the key can reach. Read-only, non-billable.",
  );
}

// --------------------------------------------------------------------------- //
// rung 4 — GATED/MANUAL: clear-index
// --------------------------------------------------------------------------- //
/**
 * GATED: `POST /1/indexes/{index}/clear` deletes all records from an index
 * (destructive, state-changing; requires the deleteIndex ACL) — the worst-case
 * write impact an admin key enables.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and the public ladder records a `blocked` rung.
 * Even WITH consent this rung never auto-fires — the URL needs `{appid}` and
 * `{index}`, which the engine cannot fill — so it only renders the safe-curl
 * note for an operator to run by hand.
 */
export const algoliaClearIndex = gated(
  "algolia.clear-index",
  async (_consent: Consent): Promise<ProbeResult> => {
    return manualRung(
      "clear-index",
      ProbeTier.GATED,
      "POST",
      CLEAR_INDEX_URL,
      CLEAR_INDEX_HEADERS,
      "Deletes all records from an index (destructive, state-changing; requires deleteIndex " +
        "ACL) — the worst-case write impact an admin key enables.",
    );
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Algolia ladder: three SAFE manual rungs (key ACL -> all keys -> indices) then
 * one GATED manual rung (clear index). Every rung is MANUAL because Algolia auth
 * also needs the Application ID, which is not in the 32-hex key, so the ladder
 * makes no live HTTP call (the `fetchImpl` option is accepted only for parity
 * with the other providers).
 */
export async function algoliaLadder(
  finding: Finding,
  consent: Consent,
  _options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE): the key's own ACL — its whoami.
  rungs.push(algoliaGetOwnKeyAcl());

  // Every rung is MANUAL (no live call possible), so we cannot "climb on
  // success"; instead we surface every rung's safe curl so the operator has the
  // full ordered ladder to run by hand once they supply the App ID.
  rungs.push(algoliaListAllKeys());
  rungs.push(algoliaListIndices());

  // Rung 4 (GATED): destructive clear. The gated wrapper enforces consent BEFORE
  // the body; without it GatedProbeBlocked is thrown and captured here as a
  // blocked rung so the ladder never throws across the public boundary.
  try {
    rungs.push(await algoliaClearIndex(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      const curl = safeCurl("POST", CLEAR_INDEX_URL, CLEAR_INDEX_HEADERS);
      rungs.push(
        new ProbeResult({
          name: "clear-index",
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
    provider: "algolia",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(["AlgoliaAdminKey"], (finding, consent) => algoliaLadder(finding, consent));
