/**
 * Discord capability ladder — prove depth of access for a leaked bot token.
 *
 * Handles TruffleHog `DiscordBotToken` (and `Discord`/`DiscordWebhook`)
 * findings. A Discord bot token authenticates with the non-standard
 * `Authorization: Bot <token>` scheme against the v10 REST API.
 *
 * Ordered ladder (depth of access, least -> most revealing):
 *
 *   1. `discord.users.me`     `GET /users/@me` — confirms the token and reveals
 *      the bot's identity (id, username). Decides VALID vs DENIED. Read-only.
 *   2. `discord.guilds`       `GET /users/@me/guilds?limit=200` — enumerates the
 *      guilds (servers) the bot has joined — reach into the estate. Read-only;
 *      we keep only the guild count and names.
 *   3. `discord.channel.history` `GET /channels/{channel_id}/messages` — GATED.
 *      Reading message content is third-party PII; needs a `{channel_id}` the
 *      engine cannot fill, so it is a MANUAL safe-curl note (never auto-fired).
 *   4. `discord.channel.send` `POST /channels/{channel_id}/messages` — GATED,
 *      state-changing (sends a message). Needs a `{channel_id}`, so it is a
 *      MANUAL safe-curl note (never auto-fired).
 *
 * Every live rung is READ-ONLY, the ladder never throws across its public
 * boundary, and the raw token never lands in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["DiscordBotToken", "Discord", "DiscordWebhook"] as const;

const API_BASE = "https://discord.com/api/v10";

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

/** Discord bot auth header — note the `Bot ` scheme, not `Bearer`. */
function botAuth(token: string): Record<string, string> {
  return { Authorization: `Bot ${token}` };
}

/**
 * Run the ordered Discord capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Climbs `users/@me` first and
 * only enumerates guilds if the token authenticated. The message-reading and
 * message-sending rungs are GATED and, because their URLs need a `{channel_id}`
 * the engine cannot fill, are emitted as manual safe-curl notes rather than live
 * calls. Never throws across this boundary.
 */
export async function discordLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const token = finding.raw;
  const fetchImpl = options.fetchImpl;

  // --- Rung 1: users/@me (SAFE) — decides live/dead --------------------------
  const identity = await discordUsersMe(token, fetchImpl);
  rungs.push(identity);

  // Only climb deeper if the token authenticated at all (ordered ladder).
  if (identity.success) {
    // --- Rung 2: guilds (SAFE) ----------------------------------------------
    rungs.push(await discordGuilds(token, fetchImpl));

    // --- Rung 3: channel history (GATED, manual safe-curl) ------------------
    rungs.push(await maybeReadHistory(consent));

    // --- Rung 4: channel send (GATED, manual safe-curl) ---------------------
    rungs.push(await maybeSendMessage(consent));
  }

  return new LadderResult({
    finding,
    provider: "discord",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

// --- individual rungs --------------------------------------------------------

/** SAFE: `GET /users/@me` confirms the bot token and returns its identity. */
async function discordUsersMe(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "discord.users.me";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/users/@me`, {
      headers: botAuth(token),
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

  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `authenticated as bot ${body["username"] ?? "?"} (id ${body["id"] ?? "?"})`,
    evidence: {
      status: resp.status,
      id: body["id"] ?? null,
      username: body["username"] ?? null,
      bot: body["bot"] ?? null,
    },
  });
}

/** SAFE: `GET /users/@me/guilds` enumerates the guilds (servers) the bot reaches. */
async function discordGuilds(token: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "discord.guilds";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/users/@me/guilds`, {
      headers: botAuth(token),
      params: { limit: "200" },
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
      detail: `could not list guilds (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = await readJson(resp);
  const guilds = Array.isArray(body) ? (body as Record<string, unknown>[]) : [];
  // Record only non-sensitive identifiers (guild names), never member data.
  const names = guilds
    .filter((g): g is Record<string, unknown> => isObject(g) && Boolean(g["name"]))
    .map((g) => g["name"] as string);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      names.length > 0
        ? `${names.length} guild(s) reachable: ${names.slice(0, 5).join(", ")}`
        : "no guilds reachable",
    evidence: {
      status: resp.status,
      guild_count: names.length,
      guilds_sample: names.slice(0, 25),
    },
  });
}

// --- gated (manual) rungs ----------------------------------------------------

/** Safe curl for the manual gated channel-history read (secret as $KEY). */
function readHistorySafeCurl(): string {
  return (
    "curl -X GET " +
    `'${API_BASE}/channels/CHANNEL_ID/messages?limit=10' ` +
    '-H "Authorization: Bot $KEY"'
  );
}

/** Safe curl for the manual gated channel-send (secret as $KEY). */
function sendMessageSafeCurl(): string {
  return (
    "curl -X POST " +
    `'${API_BASE}/channels/CHANNEL_ID/messages' ` +
    '-H "Authorization: Bot $KEY" ' +
    '-H "Content-Type: application/json" ' +
    `--data '{"content":"vtx-recon authorized probe"}'`
  );
}

/**
 * GATED: `GET /channels/{channel_id}/messages` reads live message content (PII).
 *
 * Wrapped with {@link gated}; MANUAL because the URL needs a `{channel_id}` the
 * engine cannot fill, so it never auto-fires — only returns a safe curl.
 */
export const discordGatedReadHistory = gated(
  "discord.channel.history",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "discord.channel.history",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: reads channel message content (PII); needs a channel_id; " +
        "run the safe curl by hand to exercise the read",
      evidence: { manual: true, safe_curl: readHistorySafeCurl() },
    });
  },
);

/**
 * GATED: `POST /channels/{channel_id}/messages` sends a message — state-changing.
 *
 * Wrapped with {@link gated}; MANUAL because its body needs a `{channel_id}`,
 * so it never auto-fires.
 */
export const discordGatedSendMessage = gated(
  "discord.channel.send",
  async (_consent: Consent): Promise<ProbeResult> => {
    return new ProbeResult({
      name: "discord.channel.send",
      tier: ProbeTier.GATED,
      success: false,
      detail:
        "manual rung: sends a message (state-changing); needs a channel_id; " +
        "run the safe curl by hand to exercise the impact",
      evidence: { manual: true, safe_curl: sendMessageSafeCurl() },
    });
  },
);

/** Attempt the gated history read; report it as blocked when consent is absent. */
async function maybeReadHistory(consent: Consent): Promise<ProbeResult> {
  try {
    return await discordGatedReadHistory(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "discord.channel.history",
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
async function maybeSendMessage(consent: Consent): Promise<ProbeResult> {
  try {
    return await discordGatedSendMessage(consent);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: "discord.channel.send",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated rung blocked: ${exc.reason}`,
        evidence: { manual: true, reason: exc.reason, safe_curl: sendMessageSafeCurl() },
      });
    }
    throw exc;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

register([...DETECTORS], (finding, consent) => discordLadder(finding, consent));
