/**
 * Tests for the GitLab capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (identity -> token scopes) to VALID;
 * * a dead token yields DENIED and stops after the identity rung.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { gitlabLadder } from "../src/providers/gitlab.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      gitlabLadder(finding("GitLab", "glpat-abc"), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("GitLab", () => {
  it("valid token climbs two SAFE rungs", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/api/v4/user")) {
        return mockResponse({ json: { id: 7, username: "victim", is_admin: false } });
      }
      if (call.url.endsWith("/personal_access_tokens/self")) {
        return mockResponse({ json: { active: true, scopes: ["api", "read_repository"] } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await gitlabLadder(finding("GitLab", "glpat-valid"), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("gitlab");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual(["gitlab.user", "gitlab.token.scopes"]);
    expect(result.rungs.every((r) => r.tier === ProbeTier.SAFE && r.success)).toBe(true);
    expect(result.rungs[1]?.evidence["scopes"]).toEqual(["api", "read_repository"]);
  });

  it("dead token is DENIED and stops early", async () => {
    let scopesCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/personal_access_tokens/self")) {
        scopesCalled = true;
        return mockResponse({ json: { scopes: [] } });
      }
      return mockResponse({ status: 401, json: { message: "401 Unauthorized" } });
    });
    const result = await gitlabLadder(finding("GitLab", "glpat-dead"), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["gitlab.user"]);
    expect(scopesCalled).toBe(false);
  });
});

describe("registration", () => {
  it("registers GitLab (case-insensitive)", () => {
    expect(getLadder("GitLab")).toBeTypeOf("function");
    expect(getLadder("gitlab")).toBeTypeOf("function");
  });
});
