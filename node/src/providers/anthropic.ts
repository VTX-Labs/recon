/**
 * Anthropic capability ladder — prove depth of access for a leaked API key.
 *
 * A TruffleHog `Anthropic` finding is a secret API key (`sk-ant-...`). The
 * ladder mirrors OpenAI's shape — one safe read-only identity rung, one billable
 * gated rung:
 *
 *   1. `list-models`    `GET /v1/models` — SAFE. The key authenticates and can
 *      list the models available to it (read-only, idempotent, non-billable).
 *      Decides VALID vs DENIED.
 *   2. `create-message` `POST /v1/messages` — GATED. A real message costs the
 *      target money. Wrapped with {@link gated}: the safety boundary runs
 *      *before* any network call, so without BOTH `--prove` and an authorized
 *      scope it throws {@link GatedProbeBlocked} and nothing is sent.
 *
 * The ladder never throws across its public boundary — every failure becomes a
 * {@link ProbeResult}. The raw key is held only transiently and never written
 * into evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { redact } from "../redact.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["Anthropic"] as const;

const API_BASE = "https://api.anthropic.com";
const API_VERSION = "2023-06-01";
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

function verdictFrom(rungs: ProbeResult[]): Verdict {
  if (rungs.some((r) => r.success && r.tier === ProbeTier.GATED && !r.blocked)) {
    return Verdict.PROVEN;
  }
  if (rungs.some((r) => r.success)) {
    return Verdict.VALID;
  }
  return Verdict.DENIED;
}

/** Anthropic ladder: SAFE `list-models` -> GATED `create-message`. */
export async function anthropicLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const models = await anthropicListModels(key, fetchImpl);
  rungs.push(models);

  if (models.success) {
    try {
      rungs.push(await anthropicCreateMessage(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "anthropic.create_message",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated billable message blocked: ${exc.reason}`,
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
    provider: "anthropic",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /v1/models` confirms the key and lists reachable models. */
async function anthropicListModels(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "anthropic.list_models";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v1/models`, {
      headers: { "x-api-key": key, "anthropic-version": API_VERSION },
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
 * GATED: `POST /v1/messages` — a billable message.
 *
 * Wrapped with {@link gated}: the boundary runs before this body, so without
 * BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 * and no billable request is ever sent. A minimal `max_tokens` keeps any
 * (consented) spend to the smallest possible amount.
 */
export const anthropicCreateMessage = gated(
  "anthropic.create_message",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "anthropic.create_message";
    let resp: Response;
    try {
      resp = await httpRequest(`${API_BASE}/v1/messages`, {
        method: "POST",
        headers: {
          "x-api-key": key,
          "anthropic-version": API_VERSION,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "claude-3-5-haiku-latest",
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
        detail: `billable message refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: "billable message creation succeeded (spent the target's credits)",
      evidence: { status: resp.status, billable: true },
    });
  },
);

register([...DETECTORS], (finding, consent) => anthropicLadder(finding, consent));
