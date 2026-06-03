/**
 * Tests for the Fastly capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (token-self -> list-services) to VALID,
 *   using the Fastly-Key header (NOT Bearer);
 * * a dead token (401) yields DENIED and stops after token-self;
 * * the GATED purge-all rung is MANUAL: blocked without consent, and with full
 *   consent it never fires — it renders a safe curl keeping $KEY.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { fastlyLadder, fastlyPurgeAll } from "../src/providers/fastly.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic 32-char [A-Za-z0-9_-] Fastly token. Random padding.
const KEY = "Ab3Df6Gh9Kl2No5Qr8Tu1Wx4Yz0_aB-c";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      fastlyLadder(finding("FastlyPersonalToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Fastly", () => {
  it("valid token climbs the SAFE rungs (token-self -> list-services)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/tokens/self")) {
        return mockResponse({ json: { id: "tok-1", user_id: "usr-9", scope: "global", created_at: "2024-01-01", services: ["svcA"] } });
      }
      if (call.url.endsWith("/service")) {
        return mockResponse({ json: [{ id: "svcA", name: "edge-www" }, { id: "svcB", name: "edge-api" }] });
      }
      return mockResponse({ status: 404 });
    });
    const result = await fastlyLadder(finding("FastlyPersonalToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("fastly");
    expect(result.verdict).toBe(Verdict.VALID);

    const self = result.rungs.find((r) => r.name === "token-self");
    expect(self?.tier).toBe(ProbeTier.SAFE);
    expect(self?.success).toBe(true);
    expect(self?.evidence["id"]).toBe("tok-1");
    expect(self?.evidence["scope"]).toBe("global");

    const services = result.rungs.find((r) => r.name === "list-services");
    expect(services?.evidence["service_count"]).toBe(2);
    expect(services?.evidence["service_names"]).toEqual(["edge-www", "edge-api"]);

    // Fastly authenticates with the Fastly-Key header.
    const selfCall = calls.find((c) => c.url.endsWith("/tokens/self"));
    expect(selfCall?.headers["fastly-key"]).toBe(KEY);
    expect(selfCall?.headers["authorization"]).toBeUndefined();
  });

  it("dead token (401) is DENIED and stops after token-self", async () => {
    let servicesCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/service")) {
        servicesCalled = true;
        return mockResponse({ json: [] });
      }
      return mockResponse({ status: 401, json: { msg: "Provided credentials are missing or invalid" } });
    });
    const result = await fastlyLadder(finding("FastlyPersonalToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["token-self"]);
    expect(servicesCalled).toBe(false);
  });

  it("GATED purge-all is blocked without consent and fires no call", async () => {
    let purgeCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("purge_all")) {
        purgeCalled = true;
        return mockResponse({ json: { status: "ok" } });
      }
      if (call.url.endsWith("/tokens/self")) {
        return mockResponse({ json: { id: "t", scope: "global" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await fastlyLadder(finding("FastlyPersonalToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const purge = result.rungs.find((r) => r.name === "purge-all");
    expect(purge?.tier).toBe(ProbeTier.GATED);
    expect(purge?.blocked).toBe(true);
    expect(purge?.success).toBe(false);
    expect(purge?.evidence["safe_curl"]).toContain("$KEY");
    expect(purgeCalled).toBe(false);
  });

  it("the @gated purge probe refuses without consent", async () => {
    await expect(fastlyPurgeAll(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire)", async () => {
    let purgeCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("purge_all")) {
        purgeCalled = true;
        return mockResponse({ json: { status: "ok" } });
      }
      if (call.url.endsWith("/tokens/self")) {
        return mockResponse({ json: { id: "t", scope: "global" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await fastlyLadder(finding("FastlyPersonalToken", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const purge = result.rungs.find((r) => r.name === "purge-all");
    expect(purge?.blocked).toBe(false);
    expect(purge?.evidence["manual"]).toBe(true);
    expect(purgeCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/tokens/self")) {
        return mockResponse({ json: { id: "t", scope: "global" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await fastlyLadder(finding("FastlyPersonalToken", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Fastly (case-insensitive)", () => {
    expect(getLadder("FastlyPersonalToken")).toBeTypeOf("function");
    expect(getLadder("fastlypersonaltoken")).toBeTypeOf("function");
  });
  it("tags the gated purge GATED", () => {
    expect(fastlyPurgeAll.vtxTier).toBe(ProbeTier.GATED);
  });
});
