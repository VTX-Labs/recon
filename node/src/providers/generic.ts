/**
 * Generic, declarative capability ladder for long-tail providers.
 *
 * Most providers do not need bespoke TypeScript. A provider's identity probe
 * is almost always "send the key in a header to one read-only endpoint and
 * look at the status / body". This module turns that pattern into *data* — a
 * {@link ProviderSpec} — so adding OpenAI, Anthropic, SendGrid, Twilio, npm,
 * Discord, etc. is a few lines of declaration, not a new code path. This is the
 * rot-resistant extensibility layer: specs can be shipped in code
 * ({@link BUILTIN_SPECS}) or loaded at runtime ({@link loadSpecs}) without
 * touching the engine.
 *
 * How a spec becomes a ladder
 * ---------------------------
 * {@link runSpecLadder} walks a spec's `rungs` in order:
 *
 *   * **SAFE** rungs (read-only, non-billable, idempotent — e.g. `GET
 *     /v1/models`) run by default and prove *depth of access*. They go through
 *     {@link guard} too, but for a SAFE tier that is a documented no-op.
 *   * **GATED** rungs (billable / PII-reading / state-changing — e.g. an OpenAI
 *     `chat/completions` call) are routed through the same {@link guard}. They
 *     are **structurally unreachable** without BOTH `--prove` and
 *     `--i-am-authorized "<scope>"`: the guard throws *before* any network I/O,
 *     and the runner records a blocked {@link ProbeResult} instead.
 *
 * When a finding has no automated rung (or a rung is declared `manual: true`),
 * the ladder emits a MANUAL {@link ProbeResult} whose `detail` is the exact,
 * copy-pasteable **safe curl** an operator can run by hand. The secret is
 * redacted in stored evidence; the live curl string is built only in memory and
 * the raw value is replaced with a `$KEY` placeholder so nothing secret is ever
 * persisted.
 *
 * Nothing here throws across the public boundary: every entry point returns a
 * {@link LadderResult} / {@link ProbeResult}. A blocked gated rung, a dead key,
 * a network error, and an unknown provider are all *data*, never exceptions.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { redact, redactMapping } from "../redact.js";
import { Consent, GatedProbeBlocked, ProbeTier, guard } from "../safety.js";
import { HttpError, httpRequest, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// Bound every probe so a hung endpoint cannot stall a ladder.
const HTTP_TIMEOUT_MS = 10_000;
// Token under which the literal secret is substituted, so a spec can place the
// key in an arbitrary header (or URL) via the `{key}` placeholder.
const KEY_PLACEHOLDER = "{key}";

/** One declarative rung of a generic capability ladder. */
export class RungSpec {
  readonly name: string;
  readonly method: string;
  readonly url: string;
  readonly tier: ProbeTier;
  readonly headers: Readonly<Record<string, string>>;
  /** Hint that the rung costs the target money. Billable rungs MUST be GATED. */
  readonly billable: boolean;
  /** HTTP status codes that count as success. Empty -> default 2xx. */
  readonly successStatus: readonly number[];
  /** Optional regex; if set, the body must also match for success. */
  readonly successBodyRegex: string | null;
  readonly detail: string;
  /** If true, the rung is never auto-run; the ladder emits the safe curl. */
  readonly manual: boolean;

  constructor(init: {
    name: string;
    method: string;
    url: string;
    tier?: ProbeTier;
    headers?: Record<string, string>;
    billable?: boolean;
    successStatus?: readonly number[];
    successBodyRegex?: string | null;
    detail?: string;
    manual?: boolean;
  }) {
    this.name = init.name;
    this.method = init.method;
    this.url = init.url;
    this.tier = init.tier ?? ProbeTier.SAFE;
    this.headers = Object.freeze({ ...(init.headers ?? {}) });
    this.billable = init.billable ?? false;
    this.successStatus = init.successStatus ?? [];
    this.successBodyRegex = init.successBodyRegex ?? null;
    this.detail = init.detail ?? "";
    this.manual = init.manual ?? false;

    // Enforce in code: a money-spending rung can never be SAFE.
    if (this.billable && this.tier !== ProbeTier.GATED) {
      throw new Error(
        `rung ${JSON.stringify(this.name)} is billable but tier is ${JSON.stringify(this.tier)}; ` +
          "billable probes must be GATED",
      );
    }
    Object.freeze(this);
  }

  /** Decide if a response proves this capability is present. */
  isSuccess(status: number, body: string): boolean {
    if (this.successStatus.length > 0) {
      if (!this.successStatus.includes(status)) {
        return false;
      }
    } else if (!(status >= 200 && status < 300)) {
      return false;
    }
    if (this.successBodyRegex !== null) {
      return new RegExp(this.successBodyRegex).test(body);
    }
    return true;
  }

  /** Header dict with `{key}` replaced by the live secret (in memory). */
  renderHeaders(rawKey: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(this.headers)) {
      out[k] = v.split(KEY_PLACEHOLDER).join(rawKey);
    }
    return out;
  }

  /** URL with `{key}` replaced by the live secret (in memory). */
  renderUrl(rawKey: string): string {
    return this.url.split(KEY_PLACEHOLDER).join(rawKey);
  }

  /**
   * A copy-pasteable curl with the secret replaced by `$KEY`. Never contains
   * the raw value: the placeholder stays `$KEY` wherever `{key}` appears
   * (header *or* URL). Safe to print and to store.
   */
  safeCurl(): string {
    const parts = ["curl", "-sS", "-X", this.method];
    for (const [headerName, headerValue] of Object.entries(this.headers)) {
      const shown = headerValue.split(KEY_PLACEHOLDER).join("$KEY");
      parts.push("-H", shquote(`${headerName}: ${shown}`));
    }
    parts.push(shquote(this.url.split(KEY_PLACEHOLDER).join("$KEY")));
    return parts.join(" ");
  }
}

/** A declarative provider: how to recognise its key and ladder it. */
export class ProviderSpec {
  readonly name: string;
  readonly detectors: readonly string[];
  readonly keyRegex: string | null;
  readonly rungs: readonly RungSpec[];
  readonly docs: string;

  constructor(init: {
    name: string;
    detectors?: readonly string[];
    keyRegex?: string | null;
    rungs?: readonly RungSpec[];
    docs?: string;
  }) {
    this.name = init.name;
    this.detectors = init.detectors ?? [];
    this.keyRegex = init.keyRegex ?? null;
    this.rungs = init.rungs ?? [];
    this.docs = init.docs ?? "";
    Object.freeze(this);
  }

  /** True if `rawKey` looks like this provider's secret. */
  matchesKey(rawKey: string): boolean {
    if (!this.keyRegex) {
      return false;
    }
    return new RegExp(this.keyRegex).test(rawKey);
  }
}

// --------------------------------------------------------------------------
// Built-in specs for the long-tail providers. SAFE identity rungs only by
// default; any billable demonstration is declared GATED + billable so it is
// unreachable without consent, OR left as a MANUAL rung (the safe curl).
// --------------------------------------------------------------------------

// Every provider now ships as a dedicated ladder module (see providers/*.ts),
// so there are no built-in declarative specs. The generic spec runner remains
// available as a runtime extensibility layer: operators can register their own
// providers at runtime via loadSpecs() / registerSpec() without touching the
// engine. An empty BUILTIN_SPECS means the generic ladder is a pure fallback —
// it only fires for detectors an operator wires in themselves.
export const BUILTIN_SPECS: readonly ProviderSpec[] = [];

// --------------------------------------------------------------------------
// Spec registry (separate from the ladder registry in providers/registry).
// --------------------------------------------------------------------------

// Detector name (lowercased) -> spec. Lets the generic ladder find its spec.
const SPECS_BY_DETECTOR = new Map<string, ProviderSpec>();

/** Index `spec` by each of its detector names and return it (last wins). */
export function registerSpec(spec: ProviderSpec): ProviderSpec {
  for (const detector of spec.detectors) {
    SPECS_BY_DETECTOR.set(detector.toLowerCase(), spec);
  }
  return spec;
}

/**
 * Find a spec for a detector name, falling back to key-shape matching. First
 * tries an exact (case-insensitive) detector match; if none and a `rawKey` is
 * supplied, scans specs whose `keyRegex` matches the key shape.
 */
export function specForDetector(detectorName: string, rawKey = ""): ProviderSpec | undefined {
  const spec = SPECS_BY_DETECTOR.get(detectorName.toLowerCase());
  if (spec !== undefined) {
    return spec;
  }
  if (rawKey) {
    for (const candidate of SPECS_BY_DETECTOR.values()) {
      if (candidate.matchesKey(rawKey)) {
        return candidate;
      }
    }
  }
  return undefined;
}

for (const spec of BUILTIN_SPECS) {
  registerSpec(spec);
}

// --------------------------------------------------------------------------
// Declarative spec loading — the runtime extensibility layer.
//
// In Node the idiomatic structured-config format is JSON/JS objects (the
// JSON-equivalent of the Python YAML loader). A malformed rung throws at load
// time (e.g. a billable SAFE rung) — long before any probe runs.
// --------------------------------------------------------------------------

/** A plain-object provider spec (JSON-shaped) accepted by {@link loadSpecs}. */
export interface ProviderSpecInput {
  name: string;
  detectors?: string[];
  key_regex?: string | null;
  docs?: string;
  rungs?: RungSpecInput[];
}

/** A plain-object rung spec (JSON-shaped). */
export interface RungSpecInput {
  name: string;
  method?: string;
  url: string;
  tier?: string;
  headers?: Record<string, string>;
  billable?: boolean;
  success_status?: number[];
  success_body_regex?: string | null;
  detail?: string;
  manual?: boolean;
}

/**
 * Build provider specs from plain objects and (by default) register them.
 *
 * `tier` is `"safe"` or `"gated"` (default safe). Unknown rung keys are
 * ignored so future fields do not break old loaders. Never performs network
 * I/O; only builds (and optionally registers) immutable specs.
 */
export function loadSpecs(
  entries: ProviderSpecInput[],
  options: { register?: boolean } = {},
): ProviderSpec[] {
  const doRegister = options.register ?? true;
  const specs: ProviderSpec[] = [];
  for (const entry of entries) {
    const rungs = (entry.rungs ?? []).map(rungFromInput);
    const spec = new ProviderSpec({
      name: String(entry.name),
      detectors: (entry.detectors ?? []).map(String),
      keyRegex: entry.key_regex ?? null,
      rungs,
      docs: String(entry.docs ?? ""),
    });
    specs.push(spec);
    if (doRegister) {
      registerSpec(spec);
    }
  }
  return specs;
}

function rungFromInput(data: RungSpecInput): RungSpec {
  const tierRaw = String(data.tier ?? "safe").toLowerCase();
  const tier = tierRaw === "gated" ? ProbeTier.GATED : ProbeTier.SAFE;
  return new RungSpec({
    name: String(data.name),
    method: String(data.method ?? "GET").toUpperCase(),
    url: String(data.url),
    tier,
    headers: Object.fromEntries(
      Object.entries(data.headers ?? {}).map(([k, v]) => [String(k), String(v)]),
    ),
    billable: Boolean(data.billable ?? false),
    successStatus: (data.success_status ?? []).map((s) => Number(s)),
    successBodyRegex: data.success_body_regex ?? null,
    detail: String(data.detail ?? ""),
    manual: Boolean(data.manual ?? false),
  });
}

// --------------------------------------------------------------------------
// The runner — turns a spec into ordered ProbeResults, then a Verdict.
// --------------------------------------------------------------------------

/**
 * Run a spec's rungs in order and return one {@link ProbeResult} each.
 *
 * SAFE rungs run by default. GATED rungs go through {@link guard}; if consent
 * is not fully granted the guard throws and we record a *blocked* rung
 * (`blocked=true`, `success=false`) without any network call. MANUAL rungs
 * never call the network — they record the safe curl. Never throws: transport
 * errors and blocks become ProbeResults.
 */
export async function runSpecLadder(
  spec: ProviderSpec,
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  for (const rung of spec.rungs) {
    results.push(await runRung(rung, spec, finding, consent, options.fetchImpl));
  }
  return results;
}

/** Execute (or block, or describe) a single rung. Never throws. */
async function runRung(
  rung: RungSpec,
  spec: ProviderSpec,
  finding: Finding,
  consent: Consent,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const probeName = `${spec.name}.${rung.name}`;

  // Enforce the safety boundary for GATED rungs BEFORE any I/O. For SAFE rungs
  // guard() is a no-op; for GATED it throws without consent.
  try {
    guard(consent, rung.tier, probeName);
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      return new ProbeResult({
        name: rung.name,
        tier: rung.tier,
        success: false,
        blocked: true,
        detail: `GATED rung blocked by safety boundary: ${exc.reason}.`,
        evidence: { safe_curl: rung.safeCurl(), billable: rung.billable },
      });
    }
    throw exc;
  }

  // MANUAL rungs: never auto-run; hand the operator the exact safe curl.
  if (rung.manual) {
    return new ProbeResult({
      name: rung.name,
      tier: rung.tier,
      success: false,
      blocked: false,
      detail: `MANUAL: no safe automated probe; run this by hand: ${rung.safeCurl()}`,
      evidence: { safe_curl: rung.safeCurl(), manual: true },
    });
  }

  return send(rung, finding, fetchImpl);
}

/** Issue the HTTP probe for a (already consent-checked) rung. Never throws. */
async function send(
  rung: RungSpec,
  finding: Finding,
  fetchImpl: FetchLike | undefined,
): Promise<ProbeResult> {
  const headers = rung.renderHeaders(finding.raw);
  const url = rung.renderUrl(finding.raw);
  let response: Response;
  try {
    response = await httpRequest(url, {
      method: rung.method,
      headers,
      timeoutMs: HTTP_TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    // transport / timeout / DNS — never escape.
    return new ProbeResult({
      name: rung.name,
      tier: rung.tier,
      success: false,
      detail: `probe could not reach ${rung.url}: ${errName(exc)}`,
      evidence: { error: errName(exc), safe_curl: rung.safeCurl() },
    });
  }

  const body = (await response.text().catch(() => "")) || "";
  const ok = rung.isSuccess(response.status, body);
  const detail =
    rung.detail || (ok ? "capability confirmed" : `capability refused (HTTP ${response.status})`);
  // Evidence carries only non-secret signal; redactMapping at serialise time is
  // defence-in-depth, and we never store the raw key or full body.
  const evidence: Record<string, unknown> = {
    status_code: response.status,
    key: redact(finding.raw),
    safe_curl: rung.safeCurl(),
    body_snippet: body.slice(0, 200),
  };
  return new ProbeResult({
    name: rung.name,
    tier: rung.tier,
    success: ok,
    detail,
    evidence: redactMapping(evidence),
  });
}

/** Derive the impact tier from the rungs that ran. */
function verdictFromRungs(rungs: ProbeResult[]): Verdict {
  const ran = rungs.filter((r) => !r.blocked && !("manual" in r.evidence));
  if (ran.some((r) => r.tier === ProbeTier.GATED && r.success)) {
    return Verdict.PROVEN;
  }
  if (ran.some((r) => r.tier === ProbeTier.SAFE && r.success)) {
    return Verdict.VALID;
  }
  if (ran.length > 0) {
    return Verdict.DENIED;
  }
  return Verdict.NA;
}

/**
 * Capability ladder for any spec-described provider. Never throws.
 *
 * Refuses to ladder without a named authorized scope (records it in the
 * result), finds the spec for the finding, runs its rungs, and tiers the
 * impact. An unknown provider (no spec) yields a single MANUAL-style note and
 * an `N/A` verdict rather than an error.
 */
export async function genericLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  // The whole ladder — even its safe tier — requires a named scope. This
  // throws ScopeRequired, a deliberate, documented public error.
  const scope = consent.requireLadderScope();

  const spec = specForDetector(finding.detectorName, finding.raw);
  if (spec === undefined) {
    const note = new ProbeResult({
      name: "no-spec",
      tier: ProbeTier.SAFE,
      success: false,
      detail:
        `no generic spec for detector ${JSON.stringify(finding.detectorName)}; ` +
        "add one in BUILTIN_SPECS or via loadSpecs().",
      evidence: { detector: finding.detectorName, manual: true },
    });
    return new LadderResult({
      finding,
      provider: "generic",
      verdict: Verdict.NA,
      rungs: [note],
      authorizedScope: scope,
    });
  }

  const rungs = await runSpecLadder(spec, finding, consent, options);
  return new LadderResult({
    finding,
    provider: spec.name,
    verdict: verdictFromRungs(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** Minimal single-quote shell quoting for the printable safe curl. */
function shquote(value: string): string {
  return "'" + value.split("'").join("'\\''") + "'";
}

// Register the generic ladder for every detector any built-in spec serves, so a
// Finding with one of those detector names routes straight here. New specs
// registered at runtime are reachable via specForDetector(); to also wire a new
// detector into the ladder registry call register([...], genericLadder).
const builtinDetectors = BUILTIN_SPECS.flatMap((spec) => [...spec.detectors]);
register(builtinDetectors, (finding, consent) => genericLadder(finding, consent));

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
}
