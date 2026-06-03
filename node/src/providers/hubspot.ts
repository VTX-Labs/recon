/**
 * Capability ladder for HubSpot private-app / OAuth access tokens.
 *
 * HubSpot tokens (`pat-na...` / `pat-eu...` private-app tokens, plus OAuth
 * access tokens) authenticate against `api.hubapi.com`. TruffleHog surfaces
 * them under the `HubSpot` detector. The ladder climbs:
 *
 * - **`token-info`** (SAFE) — `GET /oauth/v1/access-tokens/{token}` is HubSpot's
 *   path-based token introspection: it returns `hub_id`, `user`, `hub_domain`,
 *   `app_id` and the granted scopes. This is whoami + list-scopes in one call.
 *   It works for OAuth access tokens; private-app `pat-` tokens return 400 here,
 *   which is why the next rung exists as a fallback. The token is embedded in
 *   the URL path, so the request URL itself is a secret and is NEVER stored in
 *   evidence. Read-only, idempotent, non-billable.
 * - **`account-info`** (SAFE) — `GET /account-info/v3/details` is the whoami
 *   fallback for private-app `pat-` tokens (which cannot use the introspection
 *   endpoint): it returns `portalId`, account type, time zone, and the
 *   data-hosting region via a read-only `Authorization: Bearer` call.
 * - **`list-contacts`** (GATED) — `GET /crm/v3/objects/contacts?limit=1` reads
 *   CRM contact records (names, emails, phone numbers) — third-party customer
 *   PII, the data exposure the program cares about. Read-only, but GATED because
 *   it reads customer PII. It runs only if the operator supplied BOTH `--prove`
 *   and an authorized scope; otherwise it is recorded as a `blocked` rung.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false` so one dead key cannot crash a batch run. The raw token
 * is held only transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

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

/**
 * HubSpot ladder: SAFE token introspection (`/oauth/v1/access-tokens/{token}`)
 * -> SAFE account whoami fallback (`/account-info/v3/details`) -> GATED CRM
 * contact PII read (`/crm/v3/objects/contacts`).
 *
 * The two SAFE rungs only prove the token authenticates and reveal its hub /
 * scopes. The contacts read is GATED because it returns live customer PII; it
 * runs only if the operator supplied BOTH `--prove` and an authorized scope.
 */
export async function hubspotLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  // Two whoami rungs: token-info works for OAuth tokens, account-info is the
  // fallback for private-app `pat-` tokens. Either one authenticating is enough
  // to prove the token is live, so we run both and treat success as "authed".
  const tokenInfo = await hubspotTokenInfo(key, fetchImpl);
  rungs.push(tokenInfo);
  const accountInfo = await hubspotAccountInfo(key, fetchImpl);
  rungs.push(accountInfo);

  // Only climb to the gated PII read if the token authenticated somewhere.
  if (tokenInfo.success || accountInfo.success) {
    // Ordered: only attempt the gated PII read if the token authenticates. The
    // gated wrapper enforces consent BEFORE any network call; if consent is
    // missing it throws GatedProbeBlocked, captured here as a `blocked` rung so
    // the ladder never throws across the public boundary.
    try {
      rungs.push(await hubspotListContacts(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "hubspot.list-contacts",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated PII read blocked: ${exc.reason}`,
            evidence: { reason: exc.reason },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "hubspot",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /oauth/v1/access-tokens/{token}` introspects the token — whoami +
 * list-scopes in one call. Returns `hub_id`, `user`, `hub_domain`, `app_id` and
 * the granted scopes. Works for OAuth access tokens; private-app `pat-` tokens
 * return 400 here (the `account-info` rung is the fallback for those).
 *
 * The token is embedded in the URL path, so the request URL is itself secret —
 * it is NEVER placed into evidence; only the parsed non-secret fields are.
 */
async function hubspotTokenInfo(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "hubspot.token-info";
  let resp: Response;
  try {
    resp = await httpRequest(
      `https://api.hubapi.com/oauth/v1/access-tokens/${encodeURIComponent(key)}`,
      {
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      },
    );
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (resp.status !== 200) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `token introspection rejected (HTTP ${resp.status}) — likely a private-app pat- token; see account-info`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // Scopes prove depth of access without exercising any of them.
  const scopes = Array.isArray(body["scopes"]) ? (body["scopes"] as string[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${body["user"] ?? "unknown"} on hub ${
      body["hub_id"] ?? "?"
    } (${body["hub_domain"] ?? "?"}); ${scopes.length} scope(s)`,
    evidence: {
      status: resp.status,
      hub_id: body["hub_id"] ?? null,
      hub_domain: body["hub_domain"] ?? null,
      user: body["user"] ?? null,
      user_id: body["user_id"] ?? null,
      app_id: body["app_id"] ?? null,
      token_type: body["token_type"] ?? null,
      scopes,
    },
  });
}

/**
 * SAFE: `GET /account-info/v3/details` is the whoami fallback for private-app
 * `pat-` tokens (which cannot use the introspection endpoint). Returns
 * `portalId`, account type, time zone, and the data-hosting region via a
 * read-only `Authorization: Bearer` call.
 */
async function hubspotAccountInfo(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "hubspot.account-info";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.hubapi.com/account-info/v3/details", {
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
      detail: `account-info rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
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
    detail: `authenticated on portal ${body["portalId"] ?? "?"} (${
      body["accountType"] ?? "?"
    }, region ${body["dataHostingLocation"] ?? "?"})`,
    evidence: {
      status: resp.status,
      portal_id: body["portalId"] ?? null,
      account_type: body["accountType"] ?? null,
      time_zone: body["timeZone"] ?? null,
      data_hosting_location: body["dataHostingLocation"] ?? null,
      ui_domain: body["uiDomain"] ?? null,
    },
  });
}

/**
 * GATED: `GET /crm/v3/objects/contacts?limit=1` reads CRM contact records
 * (names, emails, phone numbers) — third-party customer PII, the data exposure
 * the program cares about. This is the real impact: read-only, but gated
 * because it reads customer PII.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. The public ladder
 * catches that and records a `blocked` rung.
 */
export const hubspotListContacts = gated(
  "hubspot.list-contacts",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "hubspot.list-contacts";
    let resp: Response;
    try {
      resp = await httpRequest("https://api.hubapi.com/crm/v3/objects/contacts?limit=1", {
        headers: { Authorization: `Bearer ${key}` },
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
        detail: `contacts read refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    const body = (await readJson(resp)) as Record<string, unknown> | undefined;
    if (body === undefined) {
      return networkFailure(name, ProbeTier.GATED, new SyntaxError("invalid JSON"));
    }

    // PII is summarised, not dumped: prove the read without hoarding customer
    // data. We only note which PII fields are present on a record, never their
    // values.
    const contacts = Array.isArray(body["results"]) ? (body["results"] as Record<string, unknown>[]) : [];
    const first = (contacts[0] ?? {}) as Record<string, unknown>;
    const props = (first["properties"] as Record<string, unknown> | undefined) ?? {};
    const piiFields = ["firstname", "lastname", "email", "phone"].filter((k) => k in props).sort();

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: `read ${contacts.length} CRM contact record(s) — live third-party customer PII`,
      evidence: {
        status: resp.status,
        sample_count: contacts.length,
        pii_fields_present: piiFields,
      },
    });
  },
);

register(["HubSpot"], (finding, consent) => hubspotLadder(finding, consent));
