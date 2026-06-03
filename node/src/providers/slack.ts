/**
 * Slack capability ladder — prove depth of access for a leaked Slack token.
 *
 * Handles TruffleHog `Slack` and `SlackWebhook` findings. A Slack bot/user
 * token (`xox...`) authenticates with `Authorization: Bearer <token>` against
 * the Web API, which answers `{ ok: true|false, ... }` with HTTP 200 even on
 * auth failure — so each rung inspects the `ok` flag, not the status code.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `slack.auth.test`           `POST auth.test` — confirms the token and
 *      reveals the team / user it belongs to. Decides VALID vs DENIED.
 *   2. `slack.conversations.list`  `GET conversations.list` — channels reachable
 *      (workspace topology). Read-only enumeration of metadata.
 *   3. `slack.users.list`          `GET users.list` — directory reachable (member
 *      count). Read-only; we keep only the count, never the roster.
 *   4. `slack.files.list`          `GET files.list` — files reachable (file count).
 *      Read-only; we keep only the count, never file contents.
 *   5. `slack.conversations.history` `GET conversations.history` — GATED. Reading
 *      message content is third-party PII; needs a `{channel_id}` the engine
 *      cannot fill, so it is a MANUAL safe-curl note (never auto-fired).
 *   6. `slack.chat.postMessage`    `POST chat.postMessage` — GATED, state-changing
 *      (sends a message). Needs a `{channel_id}`, so it is a MANUAL safe-curl
 *      note (never auto-fired).
 *
 * Every rung is ordered (identity first, then depth), the live rungs are all
 * READ-ONLY, and the ladder never throws across its public boundary: failures
 * become a {@link ProbeResult} with `success=false`. The raw token is held only
 * transiently for the HTTP call and never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Slack", "SlackWebhook"] as const;

const API_BASE = "https://slack.com/api";

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

/** Standard Slack bearer header for a bot/user token. */
function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/**
 * Run the ordered Slack capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Climbs `auth.test` first and
 * only descends into the deeper SAFE rungs if the token authenticated. The
 * message-reading and message-sending rungs are GATED and, because their URLs
 * need a `{channel_id}` the engine cannot fill, are emitted as manual safe-curl
 * notes rather than live calls. Never throws across this boundary.
 */
export async function slackLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const token = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: auth.test (SAFE) — decides live/dead --------------------------
  const identity = await slackAuthTest(token, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: conversations.list (SAFE) -----------------------------------
    rungs.push(await slackConversationsList(token, fetchImpl));

    // --- Rung 3: users.list (SAFE) -------------------------------------------
    rungs.push(await slackUsersList(token, fetchImpl));

    // --- Rung 4: files.list (SAFE) -------------------------------------------
    rungs.push(await slackFilesList(token, fetchImpl));

    // --- Rung 5: conversations.history (GATED, manual safe-curl) -------------
    rungs.push(await maybeReadHistory(consent));

    // --- Rung 6: chat.postMessage (GATED, manual safe-curl) ------------------
    rungs.push(await maybePostMessage(consent));
  }

  return new LadderResult({
    finding,
    provider: "slack",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/** SAFE: `POST auth.test` confirms the token and returns team/user ids. */
async function slackAuthTest(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "slack.auth.test";
  let resp: Response;
  let body: Record<string, unknown>;
  try {
    resp = await httpRequest(`${API_BASE}/auth.test`, {
      method: "POST",
      headers: bearer(token),
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
    const parsed = await readJson(resp);
    if (parsed === undefined) {
      throw new SyntaxError("invalid JSON");
    }
    body = parsed as Record<string, unknown>;
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (!body["ok"]) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `token rejected: ${(body["error"] as string) ?? "not_authed"}`,
      evidence: { status: resp.status, error: body["error"] ?? null },
    });
  }

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as ${body["user"]} on team ${body["team"]}`,
    evidence: {
      status: resp.status,
      team: body["team"] ?? null,
      team_id: body["team_id"] ?? null,
      user: body["user"] ?? null,
      user_id: body["user_id"] ?? null,
    },
  });
}

/** SAFE: `GET conversations.list` — channels reachable (workspace topology). */
async function slackConversationsList(
  token: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "slack.conversations.list";
  const body = await slackGet(name, "conversations.list", token, fetchImpl, {
    limit: "200",
    types: "public_channel,private_channel",
  });
  if (body instanceof ProbeResult) return body;

  const channels = Array.isArray(body["channels"]) ? (body["channels"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `${channels.length} channel(s) reachable`,
    evidence: { status: 200, channel_count: channels.length },
  });
}

/** SAFE: `GET users.list` — directory reachable (member count only). */
async function slackUsersList(
  token: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "slack.users.list";
  const body = await slackGet(name, "users.list", token, fetchImpl, { limit: "200" });
  if (body instanceof ProbeResult) return body;

  const members = Array.isArray(body["members"]) ? (body["members"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `${members.length} directory member(s) reachable`,
    evidence: { status: 200, member_count: members.length },
  });
}

/** SAFE: `GET files.list` — files reachable (file count only). */
async function slackFilesList(
  token: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const name = "slack.files.list";
  const body = await slackGet(name, "files.list", token, fetchImpl, { count: "200" });
  if (body instanceof ProbeResult) return body;

  const files = Array.isArray(body["files"]) ? (body["files"] as unknown[]) : [];
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `${files.length} file(s) reachable`,
    evidence: { status: 200, file_count: files.length },
  });
}

/**
 * Shared SAFE GET helper. Returns the parsed body on `{ ok: true }`, or a
 * non-success {@link ProbeResult} on transport failure / bad JSON / `ok:false`.
 */
async function slackGet(
  name: string,
  method: string,
  token: string,
  fetchImpl: FetchLike | undefined,
  params: Record<string, string>,
): Promise<Record<string, unknown> | ProbeResult> {
  let resp: Response;
  let body: Record<string, unknown>;
  try {
    resp = await httpRequest(`${API_BASE}/${method}`, {
      headers: bearer(token),
      params,
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
    const parsed = await readJson(resp);
    if (parsed === undefined) {
      throw new SyntaxError("invalid JSON");
    }
    body = parsed as Record<string, unknown>;
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (!body["ok"]) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `not reachable: ${(body["error"] as string) ?? "error"}`,
      evidence: { status: resp.status, error: body["error"] ?? null },
    });
  }
  return body;
}

// --- gated (manual) rungs ----------------------------------------------------

/** Safe curl for the manual gated history read (secret as $KEY, channel placeholder). */
function readHistorySafeCurl(): string {
  return (
    "curl -X GET " +
    `'${API_BASE}/conversations.history?channel=CHANNEL_ID&limit=10' ` +
    '-H "Authorization: Bearer $KEY"'
  );
}

/** Safe curl for the manual gated message send (secret as $KEY, channel placeholder). */
function postMessageSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${API_BASE}/chat.postMessage' ` +
    '-H "Authorization: Bearer $KEY" ' +
    '-H "Content-Type: application/json; charset=utf-8" ' +
    `--data '{"channel":"CHANNEL_ID","text":"vtx-recon authorized probe"}'`
  );
}

/**
 * GATED: `GET conversations.history` reads live message content (PII).
 *
 * Wrapped with {@link gated} so the safety boundary runs *before* this body;
 * without consent it throws {@link GatedProbeBlocked} and nothing executes.
 * Even with consent this rung is MANUAL: the URL needs a `{channel_id}` the
 * engine cannot fill, so it never fires a live request — it only returns a safe
 * curl (secret kept as `$KEY`) for an operator to run by hand.
 */
export const slackGatedReadHistory = gated(
  "slack.conversations.history",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "slack.conversations.history",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: reads message content (PII); needs a channel_id from " +
        "conversations.list; run the safe curl by hand to exercise the read",
      evidence: { manual: true, safe_curl: readHistorySafeCurl() },
    });
  },
);

/**
 * GATED: `POST chat.postMessage` sends a message — state-changing impact.
 *
 * Wrapped with {@link gated}; MANUAL because its body needs a `{channel_id}`
 * the engine cannot fill, so it never auto-fires.
 */
export const slackGatedPostMessage = gated(
  "slack.chat.postMessage",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "slack.chat.postMessage",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: sends a message (state-changing); needs a channel_id; " +
        "run the safe curl by hand to exercise the impact",
      evidence: { manual: true, safe_curl: postMessageSafeCurl() },
    });
  },
);

/** Attempt the gated history read; report it as blocked when consent is absent. */
async function maybeReadHistory(consent: Consent): Promise<ProbeResult> {
  try {
    return await slackGatedReadHistory(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "slack.conversations.history",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: readHistorySafeCurl() },
      });
    }
    throw exc;
  }
}

/** Attempt the gated message send; report it as blocked when consent is absent. */
async function maybePostMessage(consent: Consent): Promise<ProbeResult> {
  try {
    return await slackGatedPostMessage(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "slack.chat.postMessage",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: postMessageSafeCurl() },
      });
    }
    throw exc;
  }
}

register([...DETECTORS], (finding, consent) => slackLadder(finding, consent));
