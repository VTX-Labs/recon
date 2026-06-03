/**
 * Tests for the Heroku Platform API capability ladder. All HTTP is MOCKED via an
 * injected fetch — these tests NEVER touch a real API.
 *
 * * a valid key climbs two SAFE rungs (account -> list-apps) to VALID, with real
 *   evidence and the heroku versioned Accept header; the GATED config-var dump is
 *   a blocked manual note;
 * * a dead key (401) yields DENIED and stops after account;
 * * the GATED rung fires NO network call without consent and stays a manual
 *   safe-curl ($KEY) with full consent;
 * * the raw key never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { herokuGatedReadConfigVars, herokuLadder } from "../src/providers/heroku.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "12345678-90ab-cdef-1234-567890abcdef";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(herokuLadder(finding("Heroku", KEY), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("Heroku", () => {
  it("valid key climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/account")) {
        return mockResponse({
          json: { id: "acc1", email: "victim@example.com", name: "Victim", two_factor_authentication: false },
        });
      }
      if (call.url.endsWith("/apps")) {
        return mockResponse({ json: [{ name: "app-one" }, { name: "app-two" }] });
      }
      return mockResponse({ status: 404 });
    });

    const result = await herokuLadder(finding("Heroku", KEY), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("heroku");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual(["account", "list-apps", "read-config-vars"]);
    const acct = result.rungs[0];
    expect(acct?.success).toBe(true);
    expect(acct?.evidence["id"]).toBe("acc1");
    expect(acct?.evidence["email"]).toBe("victim@example.com");
    expect(result.rungs[1]?.evidence["app_count"]).toBe(2);
    // Bearer + heroku versioned Accept header on /account.
    const acctCall = calls.find((c) => c.url.endsWith("/account"));
    expect(acctCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    expect(acctCall?.headers["accept"]).toBe("application/vnd.heroku+json; version=3");
    // The gated config-var dump was blocked (no consent) — manual safe-curl.
    const cfg = result.rungs.find((r) => r.name === "read-config-vars");
    expect(cfg?.tier).toBe(ProbeTier.GATED);
    expect(cfg?.blocked).toBe(true);
    expect(String(cfg?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead key is DENIED and stops after account", async () => {
    let appsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/apps")) {
        appsCalled = true;
        return mockResponse({ json: [] });
      }
      return mockResponse({ status: 401, json: { id: "unauthorized" } });
    });
    const result = await herokuLadder(finding("Heroku", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["account"]);
    expect(appsCalled).toBe(false);
  });

  it("the @gated config-var probe refuses without consent", async () => {
    await expect(herokuGatedReadConfigVars(SAFE_CONSENT, KEY)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/account")) {
        return mockResponse({ json: { id: "a", email: "v@example.com" } });
      }
      if (call.url.includes("/config-vars")) {
        throw new Error("gated config-var dump must never auto-fire");
      }
      return mockResponse({ json: [] });
    });
    const result = await herokuLadder(finding("Heroku", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    const cfg = result.rungs.find((r) => r.name === "read-config-vars");
    expect(cfg?.blocked).toBe(false);
    expect(cfg?.success).toBe(false);
    expect(cfg?.evidence["manual"]).toBe(true);
    expect(String(cfg?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw key in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/account")) {
        return mockResponse({ json: { id: "a", email: "v@example.com" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await herokuLadder(finding("Heroku", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Heroku (case-insensitive)", () => {
    expect(getLadder("Heroku")).toBeTypeOf("function");
    expect(getLadder("heroku")).toBeTypeOf("function");
  });
  it("tags the gated config-var probe GATED", () => {
    expect(herokuGatedReadConfigVars.vtxTier).toBe(ProbeTier.GATED);
  });
});
