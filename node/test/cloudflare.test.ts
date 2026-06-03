/**
 * Tests for the Cloudflare capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs three SAFE rungs (verify -> permissions -> zones) to
 *   VALID, with real evidence; the GATED edit-dns rung is a blocked manual note;
 * * a dead token (non-active / 401) yields DENIED and stops after verify-token;
 * * the GATED edit-dns rung fires NO network call without consent and stays a
 *   manual safe-curl ($KEY) with full consent;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { cloudflareGatedEditDns, cloudflareLadder } from "../src/providers/cloudflare.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "EXAMPLEFAKEKEYNOTREAL000000000000000_ABC";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      cloudflareLadder(finding("CloudflareApiToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Cloudflare", () => {
  it("valid token climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.includes("/user/tokens/verify")) {
        return mockResponse({
          json: { success: true, result: { id: "tok_123", status: "active" } },
        });
      }
      if (call.url.includes("/user/tokens/permission_groups")) {
        return mockResponse({
          json: { success: true, result: [{ name: "DNS Write" }, { name: "Zone Read" }] },
        });
      }
      if (call.url.includes("/zones")) {
        return mockResponse({
          json: { success: true, result: [{ name: "victim.example" }, { name: "two.example" }] },
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await cloudflareLadder(finding("CloudflareApiToken", KEY), SAFE_CONSENT, {
      fetchImpl,
    });

    expect(result.provider).toBe("cloudflare");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "verify-token",
      "token-permissions",
      "list-zones",
      "edit-dns-record",
    ]);
    const verify = result.rungs[0];
    expect(verify?.success).toBe(true);
    expect(verify?.evidence["token_id"]).toBe("tok_123");
    expect(verify?.evidence["token_status"]).toBe("active");
    expect(result.rungs[1]?.evidence["permission_group_count"]).toBe(2);
    expect(result.rungs[2]?.evidence["zone_count"]).toBe(2);
    // The bearer token was carried on verify-token.
    const verifyCall = calls.find((c) => c.url.includes("/user/tokens/verify"));
    expect(verifyCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    // The gated DNS write was blocked (no consent) — manual safe-curl.
    const dns = result.rungs.find((r) => r.name === "edit-dns-record");
    expect(dns?.tier).toBe(ProbeTier.GATED);
    expect(dns?.blocked).toBe(true);
    expect(String(dns?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead token is DENIED and stops after verify-token", async () => {
    let permsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/permission_groups")) {
        permsCalled = true;
        return mockResponse({ json: { success: true, result: [] } });
      }
      return mockResponse({ status: 401, json: { success: false, errors: [{ code: 1000 }] } });
    });
    const result = await cloudflareLadder(finding("CloudflareApiToken", KEY), SAFE_CONSENT, {
      fetchImpl,
    });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["verify-token"]);
    expect(permsCalled).toBe(false);
  });

  it("the @gated edit-dns probe refuses without consent", async () => {
    await expect(cloudflareGatedEditDns(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/user/tokens/verify")) {
        return mockResponse({ json: { success: true, result: { id: "t", status: "active" } } });
      }
      if (call.url.includes("/dns_records")) {
        throw new Error("gated DNS write must never auto-fire");
      }
      return mockResponse({ json: { success: true, result: [] } });
    });
    const result = await cloudflareLadder(finding("CloudflareApiToken", KEY), FULL_CONSENT, {
      fetchImpl,
    });
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    const dns = result.rungs.find((r) => r.name === "edit-dns-record");
    expect(dns?.blocked).toBe(false);
    expect(dns?.success).toBe(false);
    expect(dns?.evidence["manual"]).toBe(true);
    expect(String(dns?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/user/tokens/verify")) {
        return mockResponse({ json: { success: true, result: { id: "t", status: "active" } } });
      }
      return mockResponse({ json: { success: true, result: [] } });
    });
    const result = await cloudflareLadder(finding("CloudflareApiToken", KEY), FULL_CONSENT, {
      fetchImpl,
    });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers the Cloudflare detectors (case-insensitive)", () => {
    expect(getLadder("CloudflareApiToken")).toBeTypeOf("function");
    expect(getLadder("cloudflareapitoken")).toBeTypeOf("function");
    expect(getLadder("CloudflareGlobalApiKey")).toBeTypeOf("function");
    expect(getLadder("CloudflareCaKey")).toBeTypeOf("function");
  });
  it("tags the gated edit-dns probe GATED", () => {
    expect(cloudflareGatedEditDns.vtxTier).toBe(ProbeTier.GATED);
  });
});
