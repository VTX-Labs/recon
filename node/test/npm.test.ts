/**
 * Tests for the npm capability ladder. All HTTP is MOCKED via an injected fetch
 * — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (whoami -> tokens) to VALID, with real
 *   evidence; the GATED publish rung is a blocked manual note;
 * * a dead token (401) yields DENIED and stops after whoami;
 * * the GATED publish rung fires NO network call without consent and stays a
 *   manual safe-curl ($KEY) with full consent;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { npmGatedPublish, npmLadder } from "../src/providers/npm.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const TOKEN = "npm" + "_EXAMPLEFAKEKEYNOTREAL000000000000000";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(npmLadder(finding("NpmToken", TOKEN), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("npm", () => {
  it("valid token climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/-/whoami")) {
        return mockResponse({ json: { username: "victim-dev" } });
      }
      if (call.url.endsWith("/-/npm/v1/tokens")) {
        return mockResponse({
          json: {
            objects: [
              { readonly: false, automation: true },
              { readonly: true, automation: false },
            ],
          },
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await npmLadder(finding("NpmToken", TOKEN), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("npm");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual(["npm.whoami", "npm.tokens", "npm.publish"]);
    const who = result.rungs[0];
    expect(who?.success).toBe(true);
    expect(who?.evidence["username"]).toBe("victim-dev");
    const tokens = result.rungs[1];
    expect(tokens?.evidence["token_count"]).toBe(2);
    expect(tokens?.evidence["automation_count"]).toBe(1);
    expect(tokens?.evidence["readonly_count"]).toBe(1);
    const whoCall = calls.find((c) => c.url.endsWith("/-/whoami"));
    expect(whoCall?.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
    // The gated publish was blocked (no consent) — manual safe-curl.
    const publish = result.rungs.find((r) => r.name === "npm.publish");
    expect(publish?.tier).toBe(ProbeTier.GATED);
    expect(publish?.blocked).toBe(true);
    expect(String(publish?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead token is DENIED and stops after whoami", async () => {
    let tokensCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/-/npm/v1/tokens")) {
        tokensCalled = true;
        return mockResponse({ json: { objects: [] } });
      }
      return mockResponse({ status: 401, json: { error: "Unauthorized" } });
    });
    const result = await npmLadder(finding("NpmToken", TOKEN), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["npm.whoami"]);
    expect(tokensCalled).toBe(false);
  });

  it("the @gated publish probe refuses without consent", async () => {
    await expect(npmGatedPublish(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED publish stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/-/whoami")) {
        return mockResponse({ json: { username: "victim-dev" } });
      }
      if (call.method === "PUT") {
        throw new Error("gated publish must never auto-fire");
      }
      return mockResponse({ json: { objects: [] } });
    });
    const result = await npmLadder(finding("NpmToken", TOKEN), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    const publish = result.rungs.find((r) => r.name === "npm.publish");
    expect(publish?.blocked).toBe(false);
    expect(publish?.success).toBe(false);
    expect(publish?.evidence["manual"]).toBe(true);
    expect(String(publish?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/-/whoami")) {
        return mockResponse({ json: { username: "victim-dev" } });
      }
      return mockResponse({ json: { objects: [] } });
    });
    const result = await npmLadder(finding("NpmToken", TOKEN), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(TOKEN);
  });
});

describe("registration", () => {
  it("registers the npm detectors (case-insensitive)", () => {
    expect(getLadder("NpmToken")).toBeTypeOf("function");
    expect(getLadder("npmtoken")).toBeTypeOf("function");
    expect(getLadder("NPM")).toBeTypeOf("function");
    expect(getLadder("npm")).toBeTypeOf("function");
  });
  it("tags the gated publish probe GATED", () => {
    expect(npmGatedPublish.vtxTier).toBe(ProbeTier.GATED);
  });
});
