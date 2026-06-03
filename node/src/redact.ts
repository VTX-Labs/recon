/**
 * Secret redaction — used everywhere a credential might be printed or stored.
 *
 * Rule: a raw secret is **never** persisted to disk or emitted in output.
 * Every secret is reduced to a stable `prefix + mask` form that is enough to
 * correlate a finding with a leak report without disclosing the secret itself.
 * The transform is one-way and deterministic.
 */

// How many leading characters of a secret we keep in the clear. Enough to
// recognise a provider prefix (e.g. "sk-", "AKIA", "xoxb-", "ghp_") without
// exposing meaningful entropy.
const DEFAULT_PREFIX = 4;
const MASK_CHAR = "*";
// Cap the rendered mask so a long token does not leak its exact length.
const MAX_MASK = 8;

/**
 * Reduce a secret to `prefix + mask`.
 *
 * @example
 * ```ts
 * redact("sk-live-abcdef1234567890"); // "sk-l********"
 * redact("short");                     // "shor*"
 * redact("");                          // "<empty>"
 * redact(null);                        // "<none>"
 * ```
 *
 * The mask length is clamped ({@link MAX_MASK}) so the output does not reveal
 * the true length of long secrets. Short secrets (at or below `prefix`) are
 * fully masked so no meaningful portion is shown.
 */
export function redact(
  secret: string | Uint8Array | null | undefined,
  prefix: number = DEFAULT_PREFIX,
): string {
  if (secret === null || secret === undefined) {
    return "<none>";
  }
  const text =
    typeof secret === "string" ? secret : new TextDecoder("utf-8").decode(secret);
  if (text === "") {
    return "<empty>";
  }

  const n = text.length;
  if (n <= prefix) {
    // Too short to safely reveal a prefix; mask the whole thing.
    return MASK_CHAR.repeat(n);
  }

  const visible = text.slice(0, prefix);
  const masked = Math.min(n - prefix, MAX_MASK);
  return `${visible}${MASK_CHAR.repeat(masked)}`;
}

/** Default set of (case-insensitive) keys whose values are treated as secrets. */
export const SECRET_KEYS: ReadonlySet<string> = new Set([
  "raw",
  "secret",
  "key",
  "api_key",
  "token",
  "password",
  "client_secret",
  "private_key",
  "aws_secret_access_key",
]);

/**
 * Return a deep copy of `data` with any secret-valued keys redacted.
 *
 * Keys are matched case-insensitively against `secretKeys`. Nested objects and
 * arrays are walked so a secret buried in `ExtraData` is caught too. Use this
 * before serialising anything to an evidence bundle.
 */
export function redactMapping(
  data: Record<string, unknown>,
  options: { secretKeys?: ReadonlySet<string>; prefix?: number } = {},
): Record<string, unknown> {
  const secretKeys = options.secretKeys ?? SECRET_KEYS;
  const prefix = options.prefix ?? DEFAULT_PREFIX;

  const walk = (value: unknown, redactValue: boolean): unknown => {
    if (Array.isArray(value)) {
      return value.map((item) => walk(item, redactValue));
    }
    if (isPlainObject(value)) {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        out[k] = walk(v, secretKeys.has(k.toLowerCase()));
      }
      return out;
    }
    if (redactValue && (typeof value === "string" || value instanceof Uint8Array)) {
      return redact(value, prefix);
    }
    return value;
  };

  return walk(data, false) as Record<string, unknown>;
}

/** True for a JSON-object-like value (not null, array, or class instance). */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}
