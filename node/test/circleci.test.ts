/**
 * Tests for the CircleCI capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (whoami -> list-collaborations) to VALID,
 *   using the Circle-Token header;
 * * a dead token (401) yields DENIED and stops after whoami;
 * * the GATED-tier trigger-pipeline rung is MANUAL (never wrapped in gated()): it
 *   is always blocked, fires no call, and surfaces a safe-curl keeping $KEY.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { circleciLadder } from "../src/providers/circleci.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic modern CircleCI PAT shape: CCIPAT_ + random padding.
const KEY = "CCIPAT" + "_EXAMPLEFAKEKEYNOTREAL0" + "_" + "deadbeef".repeat(5);

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      circleciLadder(finding("CircleCI", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("CircleCI", () => {
  it("valid token climbs the SAFE rungs (whoami -> list-collaborations)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/api/v2/me")) {
        return mockResponse({ json: { id: "u-123", login: "victim", name: "Victim Dev" } });
      }
      if (call.url.endsWith("/api/v2/me/collaborations")) {
        return mockResponse({ json: [{ slug: "gh/acme" }, { slug: "gh/widgets" }] });
      }
      return mockResponse({ status: 404 });
    });
    const result = await circleciLadder(finding("CircleCI", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("circleci");
    expect(result.verdict).toBe(Verdict.VALID);

    const whoami = result.rungs.find((r) => r.name === "circleci.whoami");
    expect(whoami?.tier).toBe(ProbeTier.SAFE);
    expect(whoami?.success).toBe(true);
    expect(whoami?.evidence["login"]).toBe("victim");

    const collabs = result.rungs.find((r) => r.name === "circleci.list-collaborations");
    expect(collabs?.evidence["collaboration_count"]).toBe(2);
    expect(collabs?.evidence["slugs"]).toEqual(["gh/acme", "gh/widgets"]);

    // CircleCI uses the Circle-Token header, not Bearer.
    const meCall = calls.find((c) => c.url.endsWith("/api/v2/me"));
    expect(meCall?.headers["circle-token"]).toBe(KEY);
  });

  it("dead token (401) is DENIED and stops after whoami", async () => {
    let collabsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/api/v2/me/collaborations")) {
        collabsCalled = true;
        return mockResponse({ json: [] });
      }
      return mockResponse({ status: 401, json: { message: "You must log in first." } });
    });
    const result = await circleciLadder(finding("CircleCI", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["circleci.whoami"]);
    expect(collabsCalled).toBe(false);
  });

  it("trigger-pipeline is always a MANUAL blocked GATED rung, firing no call", async () => {
    let pipelineCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/pipeline")) {
        pipelineCalled = true;
        return mockResponse({ json: { id: "pipe-LEAK" } });
      }
      if (call.url.endsWith("/api/v2/me")) {
        return mockResponse({ json: { id: "u1", login: "v" } });
      }
      return mockResponse({ json: [] });
    });
    // Even with FULL consent the manual rung never auto-fires.
    const result = await circleciLadder(finding("CircleCI", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const trigger = result.rungs.find((r) => r.name === "circleci.trigger-pipeline");
    expect(trigger?.tier).toBe(ProbeTier.GATED);
    expect(trigger?.blocked).toBe(true);
    expect(trigger?.success).toBe(false);
    expect(trigger?.evidence["safe_curl"]).toContain("$KEY");
    expect(trigger?.evidence["billable"]).toBe(true);
    expect(pipelineCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/api/v2/me")) {
        return mockResponse({ json: { id: "u1", login: "v" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await circleciLadder(finding("CircleCI", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers CircleCI detectors (case-insensitive)", () => {
    expect(getLadder("Circle")).toBeTypeOf("function");
    expect(getLadder("CircleCI")).toBeTypeOf("function");
    expect(getLadder("circleci")).toBeTypeOf("function");
  });
});
