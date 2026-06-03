/**
 * Capability ladder for Google AI / Gemini API keys (`AIza...`).
 *
 * A Google AI Studio / Gemini key authenticates via the `x-goog-api-key`
 * header against the Generative Language API
 * (`generativelanguage.googleapis.com`, `v1beta`). This module proves *depth of
 * access* with an ordered ladder of READ-ONLY rungs, then — only behind the
 * safety boundary — offers the gated, impactful rungs that cost the target
 * money, read/write PII, or create state.
 *
 * SAFE rungs (run by default, read-only, non-billable, idempotent):
 *
 *   1. `ListModels`         `GET v1beta/models`         — key authenticates.
 *   2. `ListFiles`          `GET v1beta/files`          — Files API readable.
 *   3. `ListCachedContents` `GET v1beta/cachedContents` — cache readable.
 *   4. `ListCorpora`        `GET v1beta/corpora`        — corpora readable.
 *
 * If a rung returns `403` with an API-key/referer restriction, the safe tier
 * makes ONE more read-only attempt with a spoofed `Referer` header
 * (`ListModels` again) to demonstrate that an HTTP-referer-restricted key can
 * still be exercised from a forged origin. Still a read-only `GET` — it never
 * escalates tier.
 *
 * GATED rungs (UNREACHABLE without BOTH `--prove` and `--i-am-authorized`):
 *
 *   * `GenerateContent`    `POST v1beta/models/...:generateContent` — billable.
 *   * `UploadFile`         `POST .../upload/v1beta/files`           — creates state.
 *   * `MapsBillableProbe`  a billable Google Maps Platform call.
 *   * `FirebaseAnonSignup` Identity Toolkit `accounts:signUp`       — creates state.
 *
 * The public entry point is {@link googleLadder}; it never throws across its
 * boundary — every failure is captured as a {@link ProbeResult} / reflected in
 * the {@link Verdict}.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, isSuccess, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// Generative Language API base. v1beta is where models/files/cachedContents/
// corpora live, per the confirmed API facts.
const GLA_BASE = "https://generativelanguage.googleapis.com/v1beta";
const API_KEY_HEADER = "x-goog-api-key";
// A forged origin used only to demonstrate that an HTTP-referer-restricted key
// is still exercisable. Never a real target domain.
const SPOOFED_REFERER = "https://localhost/";
// A cheap, widely available model for the (gated) generateContent probe.
const GATED_MODEL = "models/gemini-1.5-flash-latest";
const TIMEOUT_MS = 15_000;

function headers(rawKey: string, referer?: string): Record<string, string> {
  const h: Record<string, string> = { [API_KEY_HEADER]: rawKey };
  if (referer !== undefined) {
    h["Referer"] = referer;
  }
  return h;
}

/**
 * True if a 403 looks like an API-key / HTTP-referer restriction. Google
 * returns 403 with an `API_KEY_HTTP_REFERRER_BLOCKED` reason (or text
 * mentioning referer/referrer) when a browser-key restriction rejects the
 * request. We only attempt the read-only referer bypass for those.
 */
function isRefererRestricted(status: number, bodyText: string): boolean {
  if (status !== 403) {
    return false;
  }
  const body = bodyText.toLowerCase();
  return body.includes("referer") || body.includes("referrer") || body.includes("api_key_http");
}

/** Count entries in a Generative Language list response, if shaped so. */
function countItems(payload: unknown): number | null {
  if (payload === null || typeof payload !== "object") {
    return null;
  }
  const obj = payload as Record<string, unknown>;
  for (const key of ["models", "files", "cachedContents", "corpora"]) {
    const value = obj[key];
    if (Array.isArray(value)) {
      return value.length;
    }
  }
  return null;
}

/**
 * Run one read-only `GET` list rung and capture non-secret evidence. Never
 * throws: transport/timeout errors are folded into a failed ProbeResult.
 */
async function safeList(
  name: string,
  path: string,
  rawKey: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const url = `${GLA_BASE}/${path}`;
  let resp: Response;
  try {
    resp = await httpRequest(url, { headers: headers(rawKey), timeoutMs: TIMEOUT_MS, fetchImpl });
  } catch (exc) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `request failed: ${errName(exc)}`,
      evidence: { path, error: errMessage(exc) },
    });
  }

  const evidence: Record<string, unknown> = { path, status: resp.status };
  if (isSuccess(resp)) {
    const payload = await readJson(resp);
    const count = countItems(payload ?? {});
    if (count !== null) {
      evidence["item_count"] = count;
    }
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: true,
      detail: `${name} OK (${resp.status})` + (count !== null ? `, ${count} item(s)` : ""),
      evidence,
    });
  }

  const bodyText = await resp.text().catch(() => "");
  evidence["referer_restricted"] = isRefererRestricted(resp.status, bodyText);
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    detail: `${name} denied (${resp.status})`,
    evidence,
  });
}

/**
 * Read-only attempt to use a referer-restricted key from a forged origin.
 * Re-runs `ListModels` with a spoofed `Referer`. Still a `GET` — SAFE tier.
 */
async function refererBypass(
  rawKey: string,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const url = `${GLA_BASE}/models`;
  let resp: Response;
  try {
    resp = await httpRequest(url, {
      headers: headers(rawKey, SPOOFED_REFERER),
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    return new ProbeResult({
      name: "RefererBypass",
      tier: ProbeTier.SAFE,
      success: false,
      detail: `request failed: ${errName(exc)}`,
      evidence: { spoofed_referer: SPOOFED_REFERER, error: errMessage(exc) },
    });
  }
  const success = isSuccess(resp);
  return new ProbeResult({
    name: "RefererBypass",
    tier: ProbeTier.SAFE,
    success,
    detail: success
      ? "referer restriction bypassed read-only via forged Referer"
      : `referer bypass refused (${resp.status})`,
    evidence: { spoofed_referer: SPOOFED_REFERER, status: resp.status },
  });
}

// --------------------------------------------------------------------------
// GATED rungs. Billable / state-changing / PII-touching and UNREACHABLE unless
// consent is fully granted: the gated() wrapper calls the safety guard before
// the body runs, so no network call is issued otherwise. Defined here for
// completeness and to drive PROVEN tiering, but the safe ladder NEVER invokes
// them — the CLI does, only with --prove + scope.
// --------------------------------------------------------------------------

/** GATED: billable Gemini inference (`generateContent`). */
export const gatedGenerateContent = gated(
  "google.gated_generate_content",
  async (
    _consent: Consent,
    rawKey: string,
    fetchImpl?: FetchLike,
  ): Promise<ProbeResult> => {
    const url = `${GLA_BASE}/${GATED_MODEL}:generateContent`;
    const body = JSON.stringify({ contents: [{ parts: [{ text: "ping" }] }] });
    let resp: Response;
    try {
      resp = await httpRequest(url, {
        method: "POST",
        headers: { ...headers(rawKey), "Content-Type": "application/json" },
        body,
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return new ProbeResult({
        name: "GenerateContent",
        tier: ProbeTier.GATED,
        success: false,
        detail: `request failed: ${errName(exc)}`,
        evidence: { model: GATED_MODEL, error: errMessage(exc) },
      });
    }
    return new ProbeResult({
      name: "GenerateContent",
      tier: ProbeTier.GATED,
      success: isSuccess(resp),
      detail: `generateContent ${isSuccess(resp) ? "succeeded" : "refused"} (${resp.status})`,
      evidence: { model: GATED_MODEL, status: resp.status },
    });
  },
);

/** GATED: creates a resource via the Files API (state change). */
export const gatedUploadFile = gated(
  "google.gated_upload_file",
  async (_consent: Consent, rawKey: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const url = "https://generativelanguage.googleapis.com/upload/v1beta/files";
    let resp: Response;
    try {
      resp = await httpRequest(url, {
        method: "POST",
        headers: headers(rawKey),
        body: new TextEncoder().encode("vtx-recon-authorized-probe"),
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return new ProbeResult({
        name: "UploadFile",
        tier: ProbeTier.GATED,
        success: false,
        detail: `request failed: ${errName(exc)}`,
        evidence: { error: errMessage(exc) },
      });
    }
    return new ProbeResult({
      name: "UploadFile",
      tier: ProbeTier.GATED,
      success: isSuccess(resp),
      detail: `file upload ${isSuccess(resp) ? "succeeded" : "refused"} (${resp.status})`,
      evidence: { status: resp.status },
    });
  },
);

/** GATED: a billable Google Maps Platform call (Geocoding). */
export const gatedMapsBillableProbe = gated(
  "google.gated_maps_billable_probe",
  async (_consent: Consent, rawKey: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const url = "https://maps.googleapis.com/maps/api/geocode/json";
    let resp: Response;
    try {
      resp = await httpRequest(url, {
        params: { address: "1600 Amphitheatre Parkway", key: rawKey },
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return new ProbeResult({
        name: "MapsBillableProbe",
        tier: ProbeTier.GATED,
        success: false,
        detail: `request failed: ${errName(exc)}`,
        evidence: { error: errMessage(exc) },
      });
    }
    let ok = false;
    if (isSuccess(resp)) {
      const payload = (await readJson(resp)) as { status?: unknown } | undefined;
      ok = payload?.status === "OK";
    }
    return new ProbeResult({
      name: "MapsBillableProbe",
      tier: ProbeTier.GATED,
      success: ok,
      detail: `Maps billable call ${ok ? "billed/OK" : "refused"} (${resp.status})`,
      evidence: { status: resp.status },
    });
  },
);

/** GATED: Identity Toolkit anonymous signup (creates an auth user). */
export const gatedFirebaseAnonSignup = gated(
  "google.gated_firebase_anon_signup",
  async (_consent: Consent, rawKey: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp";
    let resp: Response;
    try {
      resp = await httpRequest(url, {
        method: "POST",
        params: { key: rawKey },
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ returnSecureToken: true }),
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return new ProbeResult({
        name: "FirebaseAnonSignup",
        tier: ProbeTier.GATED,
        success: false,
        detail: `request failed: ${errName(exc)}`,
        evidence: { error: errMessage(exc) },
      });
    }
    return new ProbeResult({
      name: "FirebaseAnonSignup",
      tier: ProbeTier.GATED,
      success: isSuccess(resp),
      detail: `anonymous signup ${isSuccess(resp) ? "succeeded" : "refused"} (${resp.status})`,
      evidence: { status: resp.status },
    });
  },
);

// Ordered safe ladder: (rung name, v1beta path). Climbed top to bottom.
const SAFE_RUNGS: ReadonlyArray<readonly [string, string]> = [
  ["ListModels", "models"],
  ["ListFiles", "files"],
  ["ListCachedContents", "cachedContents"],
  ["ListCorpora", "corpora"],
];

/**
 * Gated rungs are NOT part of the safe ladder. Exposed for the CLI/tests to
 * introspect tier without invoking them.
 */
export const GATED_RUNGS = [
  gatedGenerateContent,
  gatedUploadFile,
  gatedMapsBillableProbe,
  gatedFirebaseAnonSignup,
] as const;

/** Derive the impact tier from the rungs that ran. */
function verdictOf(rungs: ProbeResult[]): Verdict {
  if (rungs.some((r) => r.tier === ProbeTier.GATED && r.success)) {
    return Verdict.PROVEN;
  }
  if (rungs.some((r) => r.tier === ProbeTier.SAFE && r.success)) {
    return Verdict.VALID;
  }
  return Verdict.DENIED;
}

/**
 * Climb the Google AI / Gemini capability ladder for a finding.
 *
 * Runs the ordered SAFE rungs unconditionally (after asserting an authorized
 * scope). GATED rungs are *not* called here — they are reachable only via the
 * CLI with full consent and the {@link guard}. Never throws across this
 * boundary: the worst case is a DENIED verdict.
 */
export async function googleLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  // The ladder (even its safe tier) refuses to run without a named scope.
  const scope = consent.requireLadderScope();
  const fetchImpl = options.fetchImpl;

  const rungs: ProbeResult[] = [];
  let refererRestricted = false;
  for (const [name, path] of SAFE_RUNGS) {
    const rung = await safeList(name, path, finding.raw, fetchImpl);
    rungs.push(rung);
    if (!rung.success && rung.evidence["referer_restricted"]) {
      refererRestricted = true;
    }
  }

  // Read-only referer-bypass attempt only if a rung was referer-blocked.
  if (refererRestricted) {
    rungs.push(await refererBypass(finding.raw, fetchImpl));
  }

  return new LadderResult({
    finding,
    provider: "google",
    verdict: verdictOf(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(["GoogleAI", "Google", "Gemini", "GCP"], (finding, consent) =>
  googleLadder(finding, consent),
);

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
}

function errMessage(exc: unknown): string {
  return exc instanceof Error ? exc.message : String(exc);
}
