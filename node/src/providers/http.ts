/**
 * Tiny HTTP helper built on the Node 18+ built-in `fetch`.
 *
 * Provider ladders never hold a long-lived client; they make individual
 * requests through {@link httpRequest}, which adds a per-request timeout and
 * normalises transport failures into an {@link HttpError} (mirroring the role
 * httpx.HTTPError played in the Python implementation). The underlying
 * `fetch` is injectable so tests pass a stub and NEVER touch the network.
 */

/** The subset of the Fetch API the providers depend on. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * A transport / timeout / DNS failure — never an HTTP status. Providers fold
 * this into a failed {@link import("../models.js").ProbeResult} so a ladder
 * never raises across its public boundary.
 */
export class HttpError extends Error {
  /** The original error's constructor name, e.g. `"AbortError"`, `"TypeError"`. */
  readonly kind: string;

  constructor(kind: string, message: string) {
    super(message);
    this.name = "HttpError";
    this.kind = kind;
  }
}

export interface HttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  /** Raw request body (string or bytes). */
  body?: string | Uint8Array;
  /** Querystring parameters appended to the URL. */
  params?: Record<string, string>;
  /** Milliseconds before the request is aborted. Default 15_000. */
  timeoutMs?: number;
  /**
   * Injectable fetch implementation (defaults to the global `fetch`).
   * Explicitly accepts `undefined` so callers can forward an optional value
   * under `exactOptionalPropertyTypes`.
   */
  fetchImpl?: FetchLike | undefined;
}

/**
 * Issue a single HTTP request with a timeout. Returns the {@link Response} on
 * any HTTP status (including 4xx/5xx); throws {@link HttpError} only for a
 * transport-level failure or timeout.
 */
export async function httpRequest(
  url: string,
  options: HttpRequestOptions = {},
): Promise<Response> {
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  if (typeof fetchImpl !== "function") {
    throw new HttpError(
      "NoFetch",
      "global fetch is unavailable; vtx-recon requires Node >= 18 (or pass fetchImpl).",
    );
  }

  const finalUrl = options.params ? appendParams(url, options.params) : url;
  const timeoutMs = options.timeoutMs ?? 15_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // `string`/`Uint8Array` are valid fetch bodies. We cast through unknown to a
  // NonNullable body type so exactOptionalPropertyTypes is satisfied (we only
  // set `body` when it is defined) and we avoid the DOM-only `BodyInit` name.
  type FetchBody = NonNullable<RequestInit["body"]>;
  const init: RequestInit = {
    method: options.method ?? "GET",
    signal: controller.signal,
    ...(options.headers ? { headers: options.headers } : {}),
    ...(options.body !== undefined ? { body: options.body as unknown as FetchBody } : {}),
  };

  try {
    return await fetchImpl(finalUrl, init);
  } catch (err) {
    const kind = err instanceof Error ? err.constructor.name : "Error";
    const message = err instanceof Error ? err.message : String(err);
    throw new HttpError(kind, message);
  } finally {
    clearTimeout(timer);
  }
}

/** Append querystring params to a URL, preserving any existing query. */
function appendParams(url: string, params: Record<string, string>): string {
  const u = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    u.searchParams.set(key, value);
  }
  return u.toString();
}

/** True for a 2xx status code (httpx's `response.is_success`). */
export function isSuccess(response: Response): boolean {
  return response.status >= 200 && response.status < 300;
}

/** Best-effort JSON parse of a response body; returns undefined on failure. */
export async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}
