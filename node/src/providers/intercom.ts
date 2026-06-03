/**
 * Capability ladder for Intercom access tokens.
 *
 * Intercom OAuth / personal access tokens authenticate via a
 * `Authorization: Bearer <token>` header against `api.intercom.io`. TruffleHog
 * surfaces them under the `Intercom` detector. Every request is pinned to a
 * fixed API version (`Intercom-Version: 2.11`) so the parsed shapes are stable.
 * The ladder climbs:
 *
 * - **`me`** (SAFE) — `GET /me` returns the authorized admin plus the embedded
 *   workspace / app object. This is whoami: it confirms the token is live and
 *   reveals *which workspace* the token controls. This is exactly the kind of
 *   identity probe that is the ground truth that a key is valid.
 * - **`list-admins`** (SAFE) — `GET /admins` lists every teammate / admin in
 *   the workspace, enumerating the org the token can reach. This is own-org
 *   metadata (teammates), not customer PII, so it stays SAFE.
 * - **`list-contacts`** (GATED) — `GET /contacts?per_page=5` reads customer
 *   contact records (names, emails, phone, location) — third-party PII. This is
 *   the real impact: read-only, but GATED because it exfiltrates customer data.
 *   It runs only if the operator supplied BOTH `--prove` and an authorized
 *   scope; otherwise it is recorded as a `blocked` rung.
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

// Every Intercom request is pinned to one API version so parsed shapes are
// stable; Accept + Bearer auth complete the headers each rung sends.
function intercomHeaders(key: string): Record<string, string> {
  return {
    Authorization: `Bearer ${key}`,
    Accept: "application/json",
    "Intercom-Version": "2.11",
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

/**
 * Intercom ladder: SAFE identity (`/me`) -> SAFE teammate enumeration
 * (`/admins`) -> GATED customer PII read (`/contacts`).
 *
 * The two SAFE rungs only prove the token authenticates and size the org. The
 * contacts read is GATED because it returns live customer PII; it runs only if
 * the operator supplied BOTH `--prove` and an authorized scope.
 */
export async function intercomLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await intercomMe(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await intercomListAdmins(key, fetchImpl));

    // Ordered: only attempt the gated PII read if the token authenticates. The
    // gated wrapper enforces consent BEFORE any network call; if consent is
    // missing it throws GatedProbeBlocked, captured here as a `blocked` rung so
    // the ladder never throws across the public boundary.
    try {
      rungs.push(await intercomListContacts(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "intercom.list-contacts",
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
    provider: "intercom",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /me` confirms the token and returns the authorized admin plus the
 * embedded workspace / app object — whoami and which workspace the token
 * controls.
 */
async function intercomMe(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "intercom.me";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.intercom.io/me", {
      headers: intercomHeaders(key),
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

  // The workspace/app object is embedded under `app`; summarise it so we prove
  // which workspace the token controls without dumping the whole payload.
  const app = (body["app"] as Record<string, unknown> | undefined) ?? {};
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${body["email"] ?? body["name"]} (admin ${body["id"]}) on workspace ${
      app["name"] ?? app["id_code"] ?? "unknown"
    }`,
    evidence: {
      status: resp.status,
      admin_id: body["id"] ?? null,
      email: body["email"] ?? null,
      name: body["name"] ?? null,
      app_id_code: app["id_code"] ?? null,
      app_name: app["name"] ?? null,
    },
  });
}

/**
 * SAFE: `GET /admins` lists every teammate / admin in the workspace —
 * enumerating the org the token can reach (own-org metadata, not customer PII).
 */
async function intercomListAdmins(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "intercom.list-admins";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.intercom.io/admins", {
      headers: intercomHeaders(key),
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
      detail: `could not list admins (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  // Admins arrive under `admins`; summarise the teammate emails to size the org
  // without dumping the whole payload.
  const admins = Array.isArray(body["admins"]) ? (body["admins"] as Record<string, unknown>[]) : [];
  const emails = admins
    .map((a) => (a["email"] ?? a["name"]) as string | undefined)
    .filter((e): e is string => typeof e === "string");

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `workspace has ${admins.length} teammate(s): ${
      emails.length > 0 ? emails.join(", ") : "(none)"
    }`,
    evidence: {
      status: resp.status,
      admin_count: admins.length,
      emails,
    },
  });
}

/**
 * GATED: `GET /contacts?per_page=5` reads customer contact records (names,
 * emails, phone, location) — third-party PII. This is the real impact:
 * read-only, but gated because it exfiltrates customer data.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. The public ladder
 * catches that and records a `blocked` rung.
 */
export const intercomListContacts = gated(
  "intercom.list-contacts",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "intercom.list-contacts";
    let resp: Response;
    try {
      resp = await httpRequest("https://api.intercom.io/contacts?per_page=5", {
        headers: intercomHeaders(key),
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
    // data. `total_count` sizes the exposure; we only note which PII fields are
    // present on a record, never their values.
    const contacts = Array.isArray(body["data"]) ? (body["data"] as Record<string, unknown>[]) : [];
    const first = (contacts[0] ?? {}) as Record<string, unknown>;
    const piiFields = ["name", "email", "phone", "location"]
      .filter((k) => k in first)
      .sort();
    const totalCount = (body["total_count"] as number | undefined) ?? contacts.length;

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: `read ${contacts.length} of ${totalCount} customer contact(s) — live third-party PII`,
      evidence: {
        status: resp.status,
        total_count: totalCount,
        sample_count: contacts.length,
        pii_fields_present: piiFields,
      },
    });
  },
);

register(["Intercom"], (finding, consent) => intercomLadder(finding, consent));
