/**
 * Tests for the Vercel capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (user -> list-projects) to VALID, with
 *   real evidence; the GATED env-var read is a blocked manual note;
 * * a dead token (403) yields DENIED and stops after user;
 * * the GATED env read fires NO network call without consent and stays a manual
 *   safe-curl ($KEY) with full consent;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { vercelLadder, vercelReadProjectEnv } from "../src/providers/vercel.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "AbCdEf0123456789AbCdEf01";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(vercelLadder(finding("Vercel", KEY), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("Vercel", () => {
  it("valid token climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v2/user")) {
        return mockResponse({
          json: { user: { id: "u1", username: "victim", email: "victim@example.com" } },
        });
      }
      if (call.url.endsWith("/v9/projects")) {
        return mockResponse({
          json: { projects: [{ id: "p1", name: "web" }, { id: "p2", name: "api" }] },
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await vercelLadder(finding("Vercel", KEY), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("vercel");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual(["user", "list-projects", "read-project-env"]);
    const user = result.rungs[0];
    expect(user?.success).toBe(true);
    expect(user?.evidence["id"]).toBe("u1");
    expect(user?.evidence["username"]).toBe("victim");
    const projects = result.rungs[1];
    expect(projects?.evidence["project_count"]).toBe(2);
    expect(projects?.evidence["projects_sample"]).toEqual(["web", "api"]);
    const userCall = calls.find((c) => c.url.endsWith("/v2/user"));
    expect(userCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    // The gated env read was blocked (no consent) — manual safe-curl.
    const env = result.rungs.find((r) => r.name === "read-project-env");
    expect(env?.tier).toBe(ProbeTier.GATED);
    expect(env?.blocked).toBe(true);
    expect(String(env?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead token is DENIED and stops after user", async () => {
    let projectsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v9/projects")) {
        projectsCalled = true;
        return mockResponse({ json: { projects: [] } });
      }
      return mockResponse({ status: 403, json: { error: { code: "forbidden" } } });
    });
    const result = await vercelLadder(finding("Vercel", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["user"]);
    expect(projectsCalled).toBe(false);
  });

  it("the @gated env read refuses without consent", async () => {
    await expect(vercelReadProjectEnv(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v2/user")) {
        return mockResponse({ json: { user: { id: "u1", username: "victim" } } });
      }
      if (call.url.includes("/env")) {
        throw new Error("gated env read must never auto-fire");
      }
      return mockResponse({ json: { projects: [{ id: "p1", name: "web" }] } });
    });
    const result = await vercelLadder(finding("Vercel", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    const env = result.rungs.find((r) => r.name === "read-project-env");
    expect(env?.blocked).toBe(false);
    expect(env?.success).toBe(false);
    expect(env?.evidence["manual"]).toBe(true);
    expect(String(env?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v2/user")) {
        return mockResponse({ json: { user: { id: "u1", username: "victim" } } });
      }
      return mockResponse({ json: { projects: [{ id: "p1", name: "web" }] } });
    });
    const result = await vercelLadder(finding("Vercel", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Vercel (case-insensitive)", () => {
    expect(getLadder("Vercel")).toBeTypeOf("function");
    expect(getLadder("vercel")).toBeTypeOf("function");
  });
  it("tags the gated env read GATED", () => {
    expect(vercelReadProjectEnv.vtxTier).toBe(ProbeTier.GATED);
  });
});
