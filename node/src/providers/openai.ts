/**
 * OpenAI capability ladder — prove depth of access for a leaked API key.
 *
 * A TruffleHog `OpenAI` finding is a secret API key (`sk-...` or the project
 * form `sk-proj-...`). The ladder is deliberately short because OpenAI exposes
 * exactly one safe, read-only identity surface and one obviously billable
 * action:
 *
 *   1. `list-models`     `GET /v1/models` — SAFE. The key authenticates and can
 *      list the models available to it (read-only, idempotent, non-billable).
 *      This is what decides VALID vs DENIED.
 *   2. `chat-completion` `POST /v1/chat/completions` — GATED. A real completion
 *      costs the target money. Wrapped with {@link gated}: the safety boundary
 *      runs *before* any network call, so without BOTH `--prove` and an
 *      authorized scope it throws {@link GatedProbeBlocked} and nothing is sent.
 *
 * The ladder never throws across its public boundary — every failure becomes a
 * {@link ProbeResult}. The raw key is held only transiently for the HTTP call
 * and is never written into evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { redact } from "../redact.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["OpenAI"] as const;

const API_BASE = "https://api.openai.com";
const TIMEOUT_MS = 10_000;

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
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
 * OpenAI ladder: SAFE `list-models` -> GATED `chat-completion`.
 */
export async function openaiLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const models = await openaiListModels(key, fetchImpl);
  rungs.push(models);

  // Ordered: only attempt the gated billable rung if the key authenticated.
  if (models.success) {
    try {
      rungs.push(await openaiChatCompletion(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "openai.chat_completion",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated billable completion blocked: ${exc.reason}`,
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
    provider: "openai",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /v1/models` confirms the key and lists reachable models. */
async function openaiListModels(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "openai.list_models";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v1/models`, {
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
      detail: `key rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as { data?: Array<{ id?: string }> } | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const models = Array.isArray(body.data) ? body.data : [];
  const ids = models.map((m) => m.id).filter((id): id is string => typeof id === "string");
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail: `key authenticates; ${ids.length} models reachable`,
    evidence: {
      status: resp.status,
      key_prefix: redact(key),
      model_count: ids.length,
      sample_models: ids.slice(0, 5),
    },
  });
}

/**
 * GATED: `POST /v1/chat/completions` — a billable completion.
 *
 * Wrapped with {@link gated}: the boundary runs before this body, so without
 * BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 * and no billable request is ever sent. A minimal `max_tokens` keeps any
 * (consented) spend to the smallest possible amount.
 */
export const openaiChatCompletion = gated(
  "openai.chat_completion",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "openai.chat_completion";
    let resp: Response;
    try {
      resp = await httpRequest(`${API_BASE}/v1/chat/completions`, {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          max_tokens: 1,
          messages: [{ role: "user", content: "1" }],
        }),
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
        detail: `billable completion refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: "billable chat completion succeeded (spent the target's credits)",
      evidence: { status: resp.status, billable: true },
    });
  },
);

register([...DETECTORS], (finding, consent) => openaiLadder(finding, consent));
