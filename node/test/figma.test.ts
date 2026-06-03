/**
 * Tests for the Figma capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid PAT climbs the SAFE `me` rung (whoami) to VALID, then surfaces the
 *   SAFE/MANUAL list-team-projects safe-curl ($KEY); auth via X-Figma-Token;
 * * a dead token (403) yields DENIED and stops after `me`;
 * * the manual rung makes no live call;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { figmaLadder } from "../src/providers/figma.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "figd" + "_EXAMPLE-FAKE-KEY-NOT-REAL000000000000000";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      figmaLadder(finding("FigmaPersonalAccessToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Figma", () => {
  it("valid token climbs the SAFE me rung and surfaces the manual team rung", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v1/me")) {
        return mockResponse({
          json: { id: "u123", handle: "victim", email: "victim@example.com", img_url: "x" },
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await figmaLadder(finding("FigmaPersonalAccessToken", KEY), SAFE_CONSENT, {
      fetchImpl,
    });

    expect(result.provider).toBe("figma");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual(["me", "list-team-projects"]);
    const me = result.rungs[0];
    expect(me?.tier).toBe(ProbeTier.SAFE);
    expect(me?.success).toBe(true);
    expect(me?.evidence["id"]).toBe("u123");
    expect(me?.evidence["handle"]).toBe("victim");
    // Figma auth uses the X-Figma-Token header, not Authorization.
    const meCall = calls.find((c) => c.url.endsWith("/v1/me"));
    expect(meCall?.headers["x-figma-token"]).toBe(KEY);
    expect(meCall?.headers["authorization"]).toBeUndefined();
    // The deeper rung is manual.
    const team = result.rungs[1];
    expect(team?.success).toBe(false);
    expect(team?.evidence["manual"]).toBe(true);
    expect(String(team?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead token is DENIED and stops after me (no team rung)", async () => {
    let teamCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/teams/")) {
        teamCalled = true;
        return mockResponse({ json: {} });
      }
      return mockResponse({ status: 403, json: { err: "Invalid token" } });
    });
    const result = await figmaLadder(finding("FigmaPersonalAccessToken", KEY), SAFE_CONSENT, {
      fetchImpl,
    });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["me"]);
    expect(teamCalled).toBe(false);
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/me")) {
        return mockResponse({ json: { id: "u1", handle: "v" } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await figmaLadder(finding("FigmaPersonalAccessToken", KEY), SAFE_CONSENT, {
      fetchImpl,
    });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers FigmaPersonalAccessToken (case-insensitive)", () => {
    expect(getLadder("FigmaPersonalAccessToken")).toBeTypeOf("function");
    expect(getLadder("figmapersonalaccesstoken")).toBeTypeOf("function");
  });
});
