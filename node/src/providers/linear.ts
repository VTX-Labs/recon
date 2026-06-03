/**
 * Capability ladder for Linear API keys.
 *
 * Linear personal API keys are shaped `lin_api_<40 chars>` and authenticate
 * against the single GraphQL endpoint `https://api.linear.app/graphql`. Unlike
 * almost every other provider, Linear expects the raw key in the
 * `Authorization` header WITHOUT a `Bearer ` prefix; the value is the key
 * verbatim. Every rung is a `POST` carrying a GraphQL query, but each one is
 * read-only and idempotent. TruffleHog surfaces these under the `LinearAPI`
 * detector. The ladder climbs:
 *
 * - **`viewer-identity`** (SAFE) — `query { viewer { id name email } }` is
 *   whoami: it returns the key owner, confirming the key is live and revealing
 *   who it belongs to. POST, but read-only GraphQL, idempotent, non-billable.
 *   Decides VALID vs DENIED.
 * - **`organization`** (SAFE) — `query { organization { id name urlKey
 *   userCount } }` reveals the org the key can reach and its size — the
 *   reachable-data depth beyond the bare identity. Read-only GraphQL.
 * - **`list-org-users`** (GATED) — `query { users { nodes { name email } } }`
 *   enumerates every org member's name and email — third-party PII exposure.
 *   Read-only, but GATED because it reads member PII; it runs only if the
 *   operator supplied BOTH `--prove` and an authorized scope, otherwise it is
 *   recorded as a `blocked` rung.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false` so one dead key cannot crash a batch run. The raw key is
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

// The one GraphQL endpoint every rung POSTs to.
const GRAPHQL_URL = "https://api.linear.app/graphql";

// Linear is unusual: the Authorization header is the raw key with NO `Bearer `
// prefix. Content-Type marks the GraphQL JSON body.
function linearHeaders(key: string): Record<string, string> {
  return {
    Authorization: key,
    "Content-Type": "application/json",
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
 * A GraphQL response with a top-level `errors` array is an application-level
 * failure even on HTTP 200 (Linear returns 200 with `errors` for an invalid
 * key or a denied field). Treat any non-empty `errors` as a failed rung.
 */
function graphqlErrors(body: Record<string, unknown>): string | undefined {
  const errors = body["errors"];
  if (Array.isArray(errors) && errors.length > 0) {
    const first = errors[0] as Record<string, unknown> | undefined;
    const message = first && typeof first["message"] === "string" ? first["message"] : "unknown";
    return message;
  }
  return undefined;
}

/**
 * Linear ladder: SAFE viewer identity (`viewer`) -> SAFE org reach
 * (`organization`) -> GATED member-PII enumeration (`users`).
 *
 * The two SAFE rungs only prove the key authenticates and size the org. The
 * user enumeration is GATED because it returns third-party member PII (names,
 * emails); it runs only if the operator supplied BOTH `--prove` and an
 * authorized scope.
 */
export async function linearLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await linearViewerIdentity(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the key authenticated at all (ordered ladder).
  if (identity.success) {
    rungs.push(await linearOrganization(key, fetchImpl));

    // Ordered: only attempt the gated PII enumeration if the key authenticates.
    // The gated wrapper enforces consent BEFORE any network call; if consent is
    // missing it throws GatedProbeBlocked, captured here as a `blocked` rung so
    // the ladder never throws across the public boundary.
    try {
      rungs.push(await linearListOrgUsers(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "list-org-users",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated member-PII read blocked: ${exc.reason}`,
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
    provider: "linear",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `query { viewer { id name email } }` confirms the key and returns the
 * key owner — whoami. POST, but read-only GraphQL, idempotent, non-billable.
 */
async function linearViewerIdentity(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "viewer-identity";
  let resp: Response;
  try {
    resp = await httpRequest(GRAPHQL_URL, {
      method: "POST",
      headers: linearHeaders(key),
      body: JSON.stringify({ query: "query { viewer { id name email } }" }),
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

  // Linear returns HTTP 200 with a top-level `errors` array for an invalid key;
  // treat that as a rejected rung rather than a successful identity.
  const gqlError = graphqlErrors(body);
  if (gqlError !== undefined) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `key rejected: ${gqlError}`,
      evidence: { status: resp.status, error: gqlError },
    });
  }

  const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
  const viewer = (data["viewer"] as Record<string, unknown> | undefined) ?? {};
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${viewer["name"] ?? viewer["email"] ?? viewer["id"] ?? "unknown"}`,
    evidence: {
      status: resp.status,
      viewer_id: viewer["id"] ?? null,
      name: viewer["name"] ?? null,
      email: viewer["email"] ?? null,
    },
  });
}

/**
 * SAFE: `query { organization { id name urlKey userCount } }` reveals the org
 * the key can reach and its size — reachable-data depth beyond bare identity.
 * Read-only GraphQL.
 */
async function linearOrganization(
  key: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "organization";
  let resp: Response;
  try {
    resp = await httpRequest(GRAPHQL_URL, {
      method: "POST",
      headers: linearHeaders(key),
      body: JSON.stringify({
        query: "query { organization { id name urlKey userCount } }",
      }),
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
      detail: `could not read organization (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as Record<string, unknown> | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const gqlError = graphqlErrors(body);
  if (gqlError !== undefined) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `could not read organization: ${gqlError}`,
      evidence: { status: resp.status, error: gqlError },
    });
  }

  const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
  const org = (data["organization"] as Record<string, unknown> | undefined) ?? {};
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `reachable org ${org["name"] ?? org["urlKey"] ?? org["id"] ?? "unknown"} (${
      org["userCount"] ?? "?"
    } users)`,
    evidence: {
      status: resp.status,
      org_id: org["id"] ?? null,
      name: org["name"] ?? null,
      url_key: org["urlKey"] ?? null,
      user_count: org["userCount"] ?? null,
    },
  });
}

/**
 * GATED: `query { users { nodes { name email } } }` enumerates every org
 * member's name and email — third-party PII exposure.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. The public ladder
 * catches that and records a `blocked` rung. Names/emails are summarised (a
 * small sample plus a count), never the full directory dump.
 */
export const linearListOrgUsers = gated(
  "linear.list-org-users",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "list-org-users";
    let resp: Response;
    try {
      resp = await httpRequest(GRAPHQL_URL, {
        method: "POST",
        headers: linearHeaders(key),
        body: JSON.stringify({ query: "query { users { nodes { name email } } }" }),
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
        detail: `user enumeration refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    const body = (await readJson(resp)) as Record<string, unknown> | undefined;
    if (body === undefined) {
      return networkFailure(name, ProbeTier.GATED, new SyntaxError("invalid JSON"));
    }

    const gqlError = graphqlErrors(body);
    if (gqlError !== undefined) {
      return new ProbeResult({
        name,
        tier: ProbeTier.GATED,
        success: false,
        detail: `user enumeration refused: ${gqlError}`,
        evidence: { status: resp.status, error: gqlError },
      });
    }

    // PII is summarised, not dumped: prove the read without hoarding the full
    // member directory. We keep a small sample of names plus the total count.
    const data = (body["data"] as Record<string, unknown> | undefined) ?? {};
    const users = (data["users"] as Record<string, unknown> | undefined) ?? {};
    const nodes = Array.isArray(users["nodes"]) ? (users["nodes"] as Record<string, unknown>[]) : [];
    const names = nodes
      .map((u) => (u["name"] || u["email"]) as string | undefined)
      .filter((n): n is string => typeof n === "string");

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: `enumerated ${nodes.length} org member(s): ${
        names.length > 0 ? names.slice(0, 5).join(", ") : "(none)"
      } — third-party PII`,
      evidence: {
        status: resp.status,
        user_count: nodes.length,
        names_sample: names.slice(0, 25),
      },
    });
  },
);

register(["LinearAPI"], (finding, consent) => linearLadder(finding, consent));
