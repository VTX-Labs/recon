/**
 * Shared test helpers: build mock fetch implementations and Responses so the
 * provider tests NEVER touch the network or a real API.
 */

import type { FetchLike } from "../src/providers/http.js";

export interface RecordedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

export interface MockResponseInit {
  status?: number;
  json?: unknown;
  text?: string;
  headers?: Record<string, string>;
}

/** Build a Response-like object the http helper understands. */
export function mockResponse(init: MockResponseInit = {}): Response {
  const status = init.status ?? 200;
  const headers = new Headers(init.headers ?? {});
  const bodyText = init.text ?? (init.json !== undefined ? JSON.stringify(init.json) : "");
  return {
    status,
    ok: status >= 200 && status < 300,
    headers,
    async json() {
      if (init.json !== undefined) return init.json;
      return JSON.parse(bodyText);
    },
    async text() {
      return bodyText;
    },
  } as unknown as Response;
}

/**
 * A fetch stub driven by a handler that maps (url, init) -> Response. Records
 * every call so tests can assert exactly which endpoints were hit.
 */
export function mockFetch(
  handler: (call: RecordedCall) => Response | Promise<Response>,
): { fetchImpl: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers;
    if (rawHeaders) {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
    }
    const call: RecordedCall = {
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers,
      body: typeof init?.body === "string" ? init.body : undefined,
    };
    calls.push(call);
    return handler(call);
  };
  return { fetchImpl, calls };
}

/** A fetch stub that throws a transport error (mirrors httpx.ConnectError). */
export function failingFetch(message = "network down"): {
  fetchImpl: FetchLike;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: {},
      body: undefined,
    });
    throw new TypeError(message);
  };
  return { fetchImpl, calls };
}
