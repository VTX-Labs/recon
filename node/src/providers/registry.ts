/**
 * Provider registry — per-provider capability ladders plug in here.
 *
 * Each provider module (e.g. `providers/google.ts`, `providers/aws.ts`)
 * defines an async ladder function and registers it for one or more TruffleHog
 * `DetectorName` values via {@link register}. The CLI looks a finding's
 * detector up with {@link getLadder} to decide how to ladder it.
 *
 * A ladder is an async callable:
 *
 * ```ts
 * type Ladder = (finding: Finding, consent: Consent) => Promise<LadderResult>;
 * ```
 *
 * It MUST call `consent.requireLadderScope()` before probing, run its ordered
 * SAFE rungs unconditionally, and reach any GATED rung only through the
 * {@link "./safety"} boundary (the {@link gated} wrapper or {@link guard}).
 */

import type { Consent } from "../safety.js";
import type { Finding, LadderResult } from "../models.js";

/** A provider ladder: (finding, consent) -> LadderResult. */
export type Ladder = (finding: Finding, consent: Consent) => Promise<LadderResult>;

// DetectorName (lowercased) -> ladder. TruffleHog detector names are the keys
// so a Finding routes straight to its provider.
const REGISTRY = new Map<string, Ladder>();

/**
 * Register a ladder for one or more TruffleHog detector names.
 *
 * Detector names are matched case-insensitively. Re-registering a name
 * overwrites the previous ladder (last definition wins).
 */
export function register(detectorNames: string[], ladder: Ladder): Ladder {
  for (const name of detectorNames) {
    REGISTRY.set(name.toLowerCase(), ladder);
  }
  return ladder;
}

/** Return the registered ladder for a detector, or undefined if none exists. */
export function getLadder(detectorName: string): Ladder | undefined {
  return REGISTRY.get(detectorName.toLowerCase());
}

/** Return the detector names that currently have a ladder, sorted. */
export function registeredDetectors(): string[] {
  return [...REGISTRY.keys()].sort();
}

/** Empty the registry. Intended for tests only. */
export function clearRegistry(): void {
  REGISTRY.clear();
}
