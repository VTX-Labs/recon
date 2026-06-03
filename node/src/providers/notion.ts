/**
 * Capability ladder for Notion integration tokens.
 *
 * Notion internal/OAuth integration tokens are shaped `secret_<43+ chars>` or
 * the newer `ntn_<43+ chars>` and authenticate via an
 * `Authorization: Bearer <token>` header. Every request is pinned to the
 * `Notion-Version: 2022-06-28` API version so the parsed shapes stay stable.
 * TruffleHog surfaces these under the `Notion` detector. The ladder climbs:
 *
 * - **`bot-user`** (SAFE) — `GET /v1/users/me` returns the bot user tied to the
 *   integration token, including `bot.owner` (workspace vs user install) and the
 *   workspace name. This is whoami: it confirms the token is live and reveals the
 *   scope of the integration. Read-only, non-billable, exposes no third-party
 *   PII (only the integration's own bot). Decides VALID vs DENIED.
 * - **`list-users`** (GATED) — `GET /v1/users` enumerates every member of the
 *   workspace, and each `person` user object carries that member's email —
 *   third-party PII exposure. Read-only, but GATED because it reads member PII;
 *   it runs only if the operator supplied BOTH `--prove` and an authorized
 *   scope, otherwise it is recorded as a `blocked` rung. Names are summarised (a
 *   small sample plus counts), never the full directory dump, and emails never
 *   land in evidence.
 * - **`search-shared-content`** (GATED) — `POST /v1/search` returns the actual
 *   pages and databases shared with the integration — potentially sensitive
 *   workspace content. Read-only, but GATED because it surfaces real document
 *   data; it runs only if the operator supplied BOTH `--prove` and an authorized
 *   scope, otherwise it is recorded as a `blocked` rung. The body is capped
 *   (`page_size: 5`) so an empty body never dumps everything shared.
 *
 * Every rung is ordered (identity first, then depth), READ-ONLY by default, and
 * never throws across the public boundary: failures become a {@link ProbeResult}
 * with `success=false` so one dead key cannot crash a batch run. The raw token is
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

// Every Notion request is pinned to one API version so parsed shapes are stable;
// Bearer auth completes the headers each rung sends.
function notionHeaders(key: string): Record<string, string> {
  return {
    Authorization: `Bearer ${key}`,
    "Notion-Version": "2022-06-28",
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
 * Notion ladder: SAFE bot identity (`/users/me`) -> GATED workspace member-PII
 * enumeration (`/users`) -> GATED shared-content read (`/search`).
 *
 * The one SAFE rung only proves the token authenticates and sizes the bot's
 * scope. Member enumeration is GATED because it returns third-party PII (member
 * emails) and the search read is GATED because it returns real shared document
 * data; both run only if the operator supplied BOTH `--prove` and an authorized
 * scope.
 */
export async function notionLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const identity = await notionBotUser(key, fetchImpl);
  rungs.push(identity);
  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // Ordered: only attempt the gated member-PII enumeration if the token
    // authenticates. The gated wrapper enforces consent BEFORE any network call;
    // if consent is missing it throws GatedProbeBlocked, captured here as a
    // `blocked` rung so the ladder never throws across the public boundary.
    try {
      rungs.push(await notionListUsers(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "list-users",
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

    // Ordered: only attempt the gated content read if the token authenticates.
    try {
      rungs.push(await notionSearchSharedContent(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "search-shared-content",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated content read blocked: ${exc.reason}`,
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
    provider: "notion",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/**
 * SAFE: `GET /v1/users/me` confirms the token and returns the bot user tied to
 * the integration — whoami plus `bot.owner` (workspace vs user) and the
 * workspace name, which together map the scope of the integration. Read-only,
 * non-billable, and exposes no third-party PII (only the integration's own bot).
 */
async function notionBotUser(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "bot-user";
  let resp: Response;
  try {
    resp = await httpRequest("https://api.notion.com/v1/users/me", {
      headers: notionHeaders(key),
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

  // The bot object is embedded under `bot`; `bot.owner.type` is "workspace" or
  // "user". Summarise it so we prove the integration's scope without dumping the
  // whole payload.
  const bot = (body["bot"] as Record<string, unknown> | undefined) ?? {};
  const owner = (bot["owner"] as Record<string, unknown> | undefined) ?? {};
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as bot ${body["name"] ?? body["id"]} (owner type ${
      owner["type"] ?? "unknown"
    }, workspace ${bot["workspace_name"] ?? "unknown"})`,
    evidence: {
      status: resp.status,
      bot_id: body["id"] ?? null,
      bot_name: body["name"] ?? null,
      type: body["type"] ?? null,
      owner_type: owner["type"] ?? null,
      workspace_name: bot["workspace_name"] ?? null,
    },
  });
}

/**
 * GATED: `GET /v1/users` enumerates every member of the workspace; each
 * `person` user object carries that member's email — third-party PII exposure.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. The public ladder
 * catches that and records a `blocked` rung. Names are summarised (a small
 * sample plus counts), never the full directory dump, and emails never land in
 * evidence.
 */
export const notionListUsers = gated(
  "notion.list-users",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "list-users";
    let resp: Response;
    try {
      resp = await httpRequest("https://api.notion.com/v1/users", {
        headers: notionHeaders(key),
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
        detail: `could not list users (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    const body = (await readJson(resp)) as Record<string, unknown> | undefined;
    if (body === undefined) {
      return networkFailure(name, ProbeTier.GATED, new SyntaxError("invalid JSON"));
    }

    // PII is summarised, not dumped: prove the read without hoarding the full
    // member directory. We keep a small sample of names plus counts; member
    // emails are never recorded.
    const users = Array.isArray(body["results"]) ? (body["results"] as Record<string, unknown>[]) : [];
    const names = users
      .map((u) => (u["name"] ?? u["id"]) as string | undefined)
      .filter((n): n is string => typeof n === "string");
    const personCount = users.filter((u) => u["type"] === "person").length;

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: `enumerated ${users.length} workspace member(s) (${personCount} person): ${
        names.length > 0 ? names.slice(0, 5).join(", ") : "(none)"
      } — third-party PII`,
      evidence: {
        status: resp.status,
        user_count: users.length,
        person_count: personCount,
        names_sample: names.slice(0, 25),
      },
    });
  },
);

/**
 * GATED: `POST /v1/search` returns the actual pages and databases shared with
 * the integration — potentially sensitive workspace content. Read-only, but
 * GATED because it surfaces real document data.
 *
 * Wrapped with {@link gated}: the safety boundary runs *before* this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and no request is ever sent. The public ladder
 * catches that and records a `blocked` rung. The body caps `page_size` to 5 so
 * an empty body never returns everything shared.
 */
export const notionSearchSharedContent = gated(
  "notion.search-shared-content",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "search-shared-content";
    let resp: Response;
    try {
      resp = await httpRequest("https://api.notion.com/v1/search", {
        method: "POST",
        headers: { ...notionHeaders(key), "Content-Type": "application/json" },
        body: JSON.stringify({ page_size: 5 }),
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
        detail: `search refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    const body = (await readJson(resp)) as Record<string, unknown> | undefined;
    if (body === undefined) {
      return networkFailure(name, ProbeTier.GATED, new SyntaxError("invalid JSON"));
    }

    // Content is summarised, not dumped: prove the read without hoarding shared
    // document data. We only count objects and note object types / whether more
    // pages exist, never page titles or body content.
    const results = Array.isArray(body["results"]) ? (body["results"] as Record<string, unknown>[]) : [];
    const objectTypes = [...new Set(results.map((r) => r["object"]).filter((o): o is string => typeof o === "string"))].sort();
    const hasMore = Boolean(body["has_more"]);

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: `read ${results.length} shared object(s)${
        hasMore ? " (more available)" : ""
      } — live workspace content`,
      evidence: {
        status: resp.status,
        sample_count: results.length,
        object_types: objectTypes,
        has_more: hasMore,
      },
    });
  },
);

register(["Notion"], (finding, consent) => notionLadder(finding, consent));
