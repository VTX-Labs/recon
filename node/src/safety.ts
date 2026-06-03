/**
 * The safety boundary — the most important module in vtx-recon.
 *
 * vtx-recon proves *depth of access* by running ordered, READ-ONLY probes
 * (the "capability ladder"). Some probes, however, are unavoidably dangerous:
 * they cost the target money, read PII, change state, or create resources
 * (e.g. Gemini `generateContent` / file upload, a billable Google Maps call,
 * Firebase anonymous signup, a Stripe account read). Those are "gated".
 *
 * This module enforces — *in code, not just docs* — that a gated probe is
 * **unreachable** unless the operator has supplied BOTH:
 *
 *   1. `--prove`                     -> {@link Consent.prove} is `true`
 *   2. `--i-am-authorized "<scope>"` -> {@link Consent.authorizedScope}
 *                                       is a non-empty string
 *
 * The guarantee is structural: a {@link ProbeTier.GATED} probe that runs
 * without satisfying consent throws {@link GatedProbeBlocked} *before* any
 * network call. There is no flag, env var, or config that can run a gated
 * probe with only one of the two conditions met — both are required, every
 * time, and the authorized scope is recorded into the evidence bundle.
 *
 * Capability laddering as a whole also refuses to run without an authorized
 * scope; see {@link Consent.requireLadderScope}.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

/**
 * How dangerous a probe is.
 *
 * `SAFE` probes are read-only, non-billable, and idempotent: listing models,
 * `GetCallerIdentity`, `auth.test`, reading token scopes. They run by default
 * and the safe tier is structurally unable to reach a gated endpoint.
 *
 * `GATED` probes are billable / PII-reading / state-changing /
 * resource-creating. They are blocked unless consent is fully granted.
 */
export enum ProbeTier {
  SAFE = "safe",
  GATED = "gated",
}

/** Base class for every safety-boundary violation. */
export class SafetyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SafetyError";
  }
}

/**
 * Thrown when capability laddering is attempted with no authorized scope.
 *
 * The capability ladder (even its safe tier) refuses to run unless the
 * operator has named the engagement they are authorized to test, so that
 * name can be written into the evidence bundle.
 */
export class ScopeRequired extends SafetyError {
  constructor(message: string) {
    super(message);
    this.name = "ScopeRequired";
  }
}

/**
 * Thrown when a GATED probe is invoked without full consent.
 *
 * This is the hard boundary. It is thrown *before* the probe body runs, so no
 * billable / state-changing network call is ever made.
 */
export class GatedProbeBlocked extends SafetyError {
  readonly probeName: string;
  readonly reason: string;

  constructor(probeName: string, reason: string) {
    super(
      `Gated probe ${JSON.stringify(probeName)} blocked: ${reason}. ` +
        "Gated probes are billable, PII-reading, state-changing, or " +
        'resource-creating and require BOTH --prove and --i-am-authorized "<scope>".',
    );
    this.name = "GatedProbeBlocked";
    this.probeName = probeName;
    this.reason = reason;
  }
}

/**
 * The operator's authorization, captured once and passed everywhere.
 *
 * Immutable on purpose (frozen at construction): a probe cannot mutate its own
 * consent to escalate its tier mid-run.
 */
export class Consent {
  /**
   * `true` only if `--prove` was passed. Required (but not sufficient) to
   * reach a gated probe.
   */
  readonly prove: boolean;

  /**
   * The exact `--i-am-authorized "<scope>"` string naming the engagement
   * (e.g. a HackerOne program slug or signed statement-of-work id). Recorded
   * verbatim in the evidence bundle. `null` means no scope was supplied.
   */
  readonly authorizedScope: string | null;

  constructor(options: { prove?: boolean; authorizedScope?: string | null } = {}) {
    this.prove = options.prove ?? false;
    this.authorizedScope = options.authorizedScope ?? null;
    Object.freeze(this);
  }

  /** True if a non-empty authorized scope was supplied. */
  get hasScope(): boolean {
    return Boolean(this.authorizedScope && this.authorizedScope.trim());
  }

  /**
   * True only if BOTH gating conditions are satisfied.
   *
   * This is the single source of truth for whether gated probes may run.
   */
  get gatedAllowed(): boolean {
    return this.prove && this.hasScope;
  }

  /** Why gated probes are blocked, or `null` if they're allowed. */
  blockingReason(): string | null {
    if (!this.prove && !this.hasScope) {
      return "neither --prove nor --i-am-authorized was supplied";
    }
    if (!this.prove) {
      return "--prove was not supplied";
    }
    if (!this.hasScope) {
      return "--i-am-authorized <scope> was not supplied";
    }
    return null;
  }

  /**
   * Return the authorized scope, or throw if laddering may not run.
   *
   * Call this at the start of *any* capability ladder (safe or gated): the
   * whole pipeline refuses to ladder without a named, authorized scope so the
   * engagement is always attributable in the evidence bundle.
   */
  requireLadderScope(): string {
    if (!this.hasScope) {
      throw new ScopeRequired(
        "Capability laddering requires an authorized scope. " +
          'Re-run with --i-am-authorized "<engagement scope>".',
      );
    }
    // Narrowed by hasScope; trim to normalise what we record.
    return (this.authorizedScope as string).trim();
  }

  /** A consent that blocks every gated probe (the safe default). */
  static denied(): Consent {
    return new Consent({ prove: false, authorizedScope: null });
  }
}

/**
 * Enforce the safety boundary for a probe about to run.
 *
 * For {@link ProbeTier.SAFE} this is a no-op. For {@link ProbeTier.GATED} it
 * throws {@link GatedProbeBlocked} unless `consent.gatedAllowed` is true. Call
 * this *before* doing any I/O.
 *
 * This is the function form of the boundary; {@link gated} is the higher-order
 * form built on top of it.
 */
export function guard(consent: Consent, tier: ProbeTier, probeName: string): void {
  if (tier === ProbeTier.SAFE) {
    return;
  }
  if (!consent.gatedAllowed) {
    const reason = consent.blockingReason() ?? "consent not granted";
    throw new GatedProbeBlocked(probeName, reason);
  }
}

/**
 * A probe function tagged with its tier, so the registry and tests can assert
 * a probe's tier without invoking it.
 */
export type GatedProbe<A extends unknown[], R> = ((...args: A) => Promise<R>) & {
  readonly vtxTier: ProbeTier;
};

/**
 * Mark an async probe as GATED and enforce consent before it runs.
 *
 * The wrapped probe must accept a {@link Consent} instance as its first
 * positional argument (mirroring the Python decorator, which also accepts
 * `consent=`). Before the wrapped body executes, {@link guard} is called with
 * {@link ProbeTier.GATED}; if consent is not fully granted the call throws
 * {@link GatedProbeBlocked} and the body never runs — so no billable or
 * state-changing request is issued.
 *
 * The returned function is also tagged `vtxTier = ProbeTier.GATED` so the
 * provider registry and tests can assert a probe's tier without invoking it.
 *
 * @param probeName Stable name used in the {@link GatedProbeBlocked} message
 *   (the qualified probe name, e.g. `"google.gated_generate_content"`).
 *
 * @example
 * ```ts
 * const stripeAccountRead = gated(
 *   "stripe.account.read",
 *   async (consent: Consent, token: string) => { ... },
 * );
 * ```
 */
export function gated<A extends unknown[], R>(
  probeName: string,
  fn: (...args: A) => Promise<R>,
): GatedProbe<A, R> {
  const wrapper = async (...args: A): Promise<R> => {
    const consent = extractConsent(args);
    guard(consent, ProbeTier.GATED, probeName);
    return fn(...args);
  };
  // Make the tier introspectable without calling the probe.
  return Object.assign(wrapper, { vtxTier: ProbeTier.GATED }) as GatedProbe<A, R>;
}

/**
 * Find the Consent a gated probe was called with.
 *
 * Scans the positional arguments for the first {@link Consent}. A gated probe
 * with no reachable consent defaults to the *denied* consent, so a misuse
 * fails closed (blocked) rather than open.
 */
function extractConsent(args: readonly unknown[]): Consent {
  for (const arg of args) {
    if (arg instanceof Consent) {
      return arg;
    }
  }
  // Fail closed: no consent visible -> treat as denied, which blocks.
  return Consent.denied();
}
