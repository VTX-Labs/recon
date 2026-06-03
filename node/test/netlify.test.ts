/**
 * Tests for the Netlify capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (user -> list-sites) to VALID, with real
 *   evidence; the GATED env read is a blocked manual note;
 * * a dead token (401) yields DENIED and stops after user;
 * * the GATED rung fires NO network call without consent and stays a manual
 *   safe-curl ($KEY) with full consent;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { netlifyLadder, netlifyReadSiteEnv } from "../src/providers/netlify.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "EXAMPLEFAKEKEYNOTREAL-_000000000000000_ABCD";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(netlifyLadder(finding("Netlify", KEY), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("Netlify", () => {
  it("valid token climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/api/v1/user")) {
        return mockResponse({
          json: { id: "u1", email: "victim@example.com", full_name: "Victim Owner" },
        });
      }
      if (call.url.endsWith("/api/v1/sites")) {
        return mockResponse({
          json: [
            { name: "site-a", custom_domain: "a.example", account_id: "acc1" },
            { name: "site-b", custom_domain: "", account_id: "acc1" },
          ],
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await netlifyLadder(finding("Netlify", KEY), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("netlify");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "netlify.user",
      "netlify.list-sites",
      "netlify.read-site-env",
    ]);
    const user = result.rungs[0];
    expect(user?.success).toBe(true);
    expect(user?.evidence["id"]).toBe("u1");
    expect(user?.evidence["full_name"]).toBe("Victim Owner");
    const sites = result.rungs[1];
    expect(sites?.evidence["site_count"]).toBe(2);
    expect(sites?.evidence["account_ids"]).toEqual(["acc1"]);
    const userCall = calls.find((c) => c.url.endsWith("/api/v1/user"));
    expect(userCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    // The gated env read was blocked (no consent) — manual safe-curl.
    const env = result.rungs.find((r) => r.name === "netlify.read-site-env");
    expect(env?.tier).toBe(ProbeTier.GATED);
    expect(env?.blocked).toBe(true);
    expect(String(env?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead token is DENIED and stops after user", async () => {
    let sitesCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/api/v1/sites")) {
        sitesCalled = true;
        return mockResponse({ json: [] });
      }
      return mockResponse({ status: 401, json: { code: 401, message: "Unauthorized" } });
    });
    const result = await netlifyLadder(finding("Netlify", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["netlify.user"]);
    expect(sitesCalled).toBe(false);
  });

  it("the @gated env read refuses without consent", async () => {
    await expect(netlifyReadSiteEnv(SAFE_CONSENT, KEY)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/api/v1/user")) {
        return mockResponse({ json: { id: "u1", email: "v@example.com" } });
      }
      if (call.url.includes("/env")) {
        throw new Error("gated env read must never auto-fire");
      }
      return mockResponse({ json: [] });
    });
    const result = await netlifyLadder(finding("Netlify", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    const env = result.rungs.find((r) => r.name === "netlify.read-site-env");
    expect(env?.blocked).toBe(false);
    expect(env?.success).toBe(false);
    expect(env?.evidence["manual"]).toBe(true);
    expect(String(env?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/api/v1/user")) {
        return mockResponse({ json: { id: "u1", email: "v@example.com" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await netlifyLadder(finding("Netlify", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Netlify (case-insensitive)", () => {
    expect(getLadder("Netlify")).toBeTypeOf("function");
    expect(getLadder("netlify")).toBeTypeOf("function");
  });
  it("tags the gated env read GATED", () => {
    expect(netlifyReadSiteEnv.vtxTier).toBe(ProbeTier.GATED);
  });
});
