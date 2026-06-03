/**
 * Core data model for the find -> verify -> ladder -> tier -> bundle pipeline.
 *
 * Every class here is JSON-serialisable via its `toPublic()` method. Secrets
 * are *never* stored raw on these objects' public view: a {@link Finding}
 * carries only a redacted form plus TruffleHog's own `Redacted` string in its
 * serialised output. The raw secret is held transiently in memory for probing
 * and never written out.
 */

import { redact, redactMapping } from "./redact.js";
import { ProbeTier } from "./safety.js";

/**
 * Impact tier for a credential after capability laddering.
 *
 * - `PROVEN`: a gated probe ran (with consent) and demonstrated real impact —
 *   billable access, PII read, or state change was actually exercised.
 * - `VALID`: the credential authenticates and safe probes proved depth of
 *   access, but no gated/impactful action was exercised.
 * - `DENIED`: the credential is live but every probed capability was refused
 *   (e.g. authenticates yet has no usable scopes).
 * - `NA`: not applicable — the credential could not be verified, or the
 *   provider has no ladder.
 */
export enum Verdict {
  PROVEN = "PROVEN",
  VALID = "VALID",
  DENIED = "DENIED",
  NA = "N/A",
}

/** Serialisable, secret-free view of a {@link Finding}. */
export interface PublicFinding {
  detector_name: string;
  verified: boolean;
  redacted: string;
  extra_data: Record<string, unknown>;
  source: string;
}

/** Serialisable, secret-free view of a {@link ProbeResult}. */
export interface PublicProbeResult {
  name: string;
  tier: string;
  success: boolean;
  blocked: boolean;
  detail: string;
  evidence: Record<string, unknown>;
}

/** Serialisable, secret-free view of a {@link LadderResult}. */
export interface PublicLadderResult {
  provider: string;
  verdict: string;
  authorized_scope: string;
  finding: PublicFinding;
  rungs: PublicProbeResult[];
}

/** Serialisable, secret-free view of an {@link EvidenceBundle}. */
export interface PublicEvidenceBundle {
  tool: string;
  tool_version: string;
  authorized_scope: string;
  created_at: number;
  created_at_iso: string;
  no_state_changed_attestation: boolean;
  results: PublicLadderResult[];
}

/**
 * A single candidate secret, typically from TruffleHog.
 *
 * The raw secret lives only in {@link Finding.raw} (kept in memory for
 * probing) and is excluded from serialisation by {@link Finding.toPublic}. Use
 * {@link Finding.redacted} / {@link Finding.detectorRedacted} anywhere a value
 * is shown.
 */
export class Finding {
  detectorName: string;
  verified: boolean;
  /** Held transiently for probing; never persisted. Excluded from toPublic(). */
  raw: string;
  /** TruffleHog's own redacted form (its "Redacted" field), if provided. */
  detectorRedacted: string;
  /**
   * Extra detector context (e.g. the paired AWS account / region). May itself
   * contain secrets, so it is redacted before serialisation.
   */
  extraData: Record<string, unknown>;
  source: string;

  constructor(init: {
    detectorName: string;
    verified: boolean;
    raw?: string;
    detectorRedacted?: string;
    extraData?: Record<string, unknown>;
    source?: string;
  }) {
    this.detectorName = init.detectorName;
    this.verified = init.verified;
    this.raw = init.raw ?? "";
    this.detectorRedacted = init.detectorRedacted ?? "";
    this.extraData = init.extraData ?? {};
    this.source = init.source ?? "";
  }

  /** Our own prefix+mask of the raw secret (never the raw value). */
  get redacted(): string {
    return this.detectorRedacted || redact(this.raw);
  }

  /** Serialisable view with no raw secret material. */
  toPublic(): PublicFinding {
    return {
      detector_name: this.detectorName,
      verified: this.verified,
      redacted: this.redacted,
      extra_data: redactMapping({ ...this.extraData }),
      source: this.source,
    };
  }
}

/** The outcome of one capability-ladder probe (one rung). */
export class ProbeResult {
  name: string;
  tier: ProbeTier;
  /** True if the probe ran and the capability was confirmed present. */
  success: boolean;
  /** Short human-readable summary, e.g. "token has repo, read:org scopes". */
  detail: string;
  /**
   * Non-secret evidence (status code, returned identity, scope list...).
   * Redacted on serialisation as defence in depth.
   */
  evidence: Record<string, unknown>;
  /**
   * True if this rung was a gated probe that was blocked by the safety
   * boundary (consent not granted). Distinct from a probe that ran and failed.
   */
  blocked: boolean;

  constructor(init: {
    name: string;
    tier: ProbeTier;
    success: boolean;
    detail?: string;
    evidence?: Record<string, unknown>;
    blocked?: boolean;
  }) {
    this.name = init.name;
    this.tier = init.tier;
    this.success = init.success;
    this.detail = init.detail ?? "";
    this.evidence = init.evidence ?? {};
    this.blocked = init.blocked ?? false;
  }

  toPublic(): PublicProbeResult {
    return {
      name: this.name,
      tier: this.tier,
      success: this.success,
      blocked: this.blocked,
      detail: this.detail,
      evidence: redactMapping({ ...this.evidence }),
    };
  }
}

/** All rungs run for a single finding, plus the resulting impact tier. */
export class LadderResult {
  finding: Finding;
  provider: string;
  verdict: Verdict;
  rungs: ProbeResult[];
  /**
   * The authorized scope under which this ladder was run (recorded for the
   * evidence bundle; required by the safety boundary to ladder at all).
   */
  authorizedScope: string;

  constructor(init: {
    finding: Finding;
    provider: string;
    verdict: Verdict;
    rungs?: ProbeResult[];
    authorizedScope?: string;
  }) {
    this.finding = init.finding;
    this.provider = init.provider;
    this.verdict = init.verdict;
    this.rungs = init.rungs ?? [];
    this.authorizedScope = init.authorizedScope ?? "";
  }

  toPublic(): PublicLadderResult {
    return {
      provider: this.provider,
      verdict: this.verdict,
      authorized_scope: this.authorizedScope,
      finding: this.finding.toPublic(),
      rungs: this.rungs.map((r) => r.toPublic()),
    };
  }
}

/**
 * A timestamped, court-ready record of an authorized engagement.
 *
 * Contains only redacted secrets and a "no state changed" attestation that is
 * true unless a gated probe was actually exercised under consent. Render to
 * JSON for machines and Markdown for a human report.
 */
export class EvidenceBundle {
  authorizedScope: string;
  toolVersion: string;
  results: LadderResult[];
  createdAt: number;
  /** Set false only when a PROVEN/gated probe actually changed state. */
  noStateChanged: boolean;

  constructor(init: {
    authorizedScope: string;
    toolVersion: string;
    results?: LadderResult[];
    createdAt?: number;
    noStateChanged?: boolean;
  }) {
    this.authorizedScope = init.authorizedScope;
    this.toolVersion = init.toolVersion;
    this.results = init.results ?? [];
    // Seconds since the epoch, matching the Python `time.time()` semantics.
    this.createdAt = init.createdAt ?? Date.now() / 1000;
    this.noStateChanged = init.noStateChanged ?? true;
  }

  toPublic(): PublicEvidenceBundle {
    return {
      tool: "vtx-recon",
      tool_version: this.toolVersion,
      authorized_scope: this.authorizedScope,
      created_at: this.createdAt,
      created_at_iso: isoUtc(this.createdAt),
      no_state_changed_attestation: this.noStateChanged,
      results: this.results.map((r) => r.toPublic()),
    };
  }
}

/** Format a UNIX timestamp (seconds) as `YYYY-MM-DDTHH:MM:SSZ` (UTC). */
function isoUtc(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}
