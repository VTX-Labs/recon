/**
 * @vtx-labs/recon — programmatic API.
 *
 * Secret intelligence for authorized engagements: find a key, then prove what
 * it can actually *do*. The pipeline is find (TruffleHog) -> verify ->
 * capability ladder -> impact tier (PROVEN / VALID / DENIED / N/A) ->
 * court-ready evidence bundle.
 *
 * vtx-recon is READ-ONLY by default. Every billable, PII-reading,
 * state-changing, or resource-creating probe is "gated" and is structurally
 * unreachable unless the caller passes BOTH `--prove` and
 * `--i-am-authorized "<scope>"`. See {@link "./safety"} for the enforced
 * boundary.
 *
 * AUTHORIZED USE ONLY. Running these probes against systems you are not
 * explicitly authorized to test may violate the US CFAA, the UK Computer
 * Misuse Act, and equivalent laws. See TERMS.md.
 *
 * @example
 * ```ts
 * import { Consent, getLadder, Finding } from "@vtx-labs/recon";
 *
 * const consent = new Consent({ authorizedScope: "bugbounty:acme" });
 * const finding = new Finding({ detectorName: "GoogleAI", verified: true, raw: "AIza..." });
 * const ladder = getLadder(finding.detectorName);
 * if (ladder) {
 *   const result = await ladder(finding, consent);
 *   console.log(result.verdict, result.toPublic());
 * }
 * ```
 */

// Keep in lockstep with the version in package.json.
export const VERSION = "0.2.0";

// --- safety boundary (the core guarantee) -----------------------------------
export {
  Consent,
  GatedProbeBlocked,
  ProbeTier,
  SafetyError,
  ScopeRequired,
  gated,
  guard,
  type GatedProbe,
} from "./safety.js";

// --- redaction ---------------------------------------------------------------
export { redact, redactMapping, SECRET_KEYS } from "./redact.js";

// --- data model --------------------------------------------------------------
export {
  EvidenceBundle,
  Finding,
  LadderResult,
  ProbeResult,
  Verdict,
  type PublicEvidenceBundle,
  type PublicFinding,
  type PublicLadderResult,
  type PublicProbeResult,
} from "./models.js";

// --- TruffleHog integration --------------------------------------------------
export {
  BINARY_NAME,
  TruffleHogError,
  TruffleHogNotFound,
  findBinary,
  parseJsonStream,
  parseTruffleHogRecord,
  runTruffleHog,
  type RunTruffleHogOptions,
  type TruffleHogRecord,
} from "./trufflehog.js";

// --- banner ------------------------------------------------------------------
export { BANNER, TAGLINE, renderBanner, shouldShowBanner } from "./banner.js";

// --- providers + registry ----------------------------------------------------
export {
  type Ladder,
  type FetchLike,
  clearRegistry,
  getLadder,
  register,
  registeredDetectors,
  googleLadder,
  GATED_RUNGS,
  awsLadder,
  signRequest,
  probeCallerIdentity,
  probeAccountAuthorizationDetails,
  githubLadder,
  gatedWriteProbe,
  GITHUB_DETECTORS,
  slackLadder,
  gitlabLadder,
  stripeLadder,
  stripeAccountRead,
  genericLadder,
  runSpecLadder,
  loadSpecs,
  specForDetector,
  registerSpec,
  ProviderSpec,
  RungSpec,
  BUILTIN_SPECS,
  type ProviderSpecInput,
  type RungSpecInput,
} from "./providers/index.js";
