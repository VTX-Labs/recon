/**
 * Tests for the PagerDuty capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid key climbs two SAFE rungs (abilities -> list-users) to VALID using
 *   the `Authorization: Token token={key}` header;
 * * a dead key (401) yields DENIED and stops after abilities;
 * * the GATED create-incident rung is MANUAL: blocked without consent, and with
 *   full consent it never fires — it renders a safe curl keeping $KEY.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { pagerdutyLadder, pagerdutyGatedCreateIncident } from "../src/providers/pagerduty.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic PagerDuty REST API key (20 chars). Random padding, NOT a real key.
const KEY = "y_NbAkKc66ryYTWUXYEu";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      pagerdutyLadder(finding("PagerDutyApiKey", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("PagerDuty", () => {
  it("valid key climbs the SAFE rungs (abilities -> list-users)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/abilities")) {
        return mockResponse({ json: { abilities: ["sso", "advanced_reports", "teams"] } });
      }
      if (call.url.includes("/users")) {
        return mockResponse({ json: { users: [{ id: "PUSER1", role: "admin" }], more: false } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await pagerdutyLadder(finding("PagerDutyApiKey", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("pagerduty");
    expect(result.verdict).toBe(Verdict.VALID);

    const abilities = result.rungs.find((r) => r.name === "abilities");
    expect(abilities?.tier).toBe(ProbeTier.SAFE);
    expect(abilities?.success).toBe(true);
    expect(abilities?.evidence["ability_count"]).toBe(3);

    const users = result.rungs.find((r) => r.name === "list-users");
    expect(users?.evidence["first_user_id"]).toBe("PUSER1");
    expect(users?.evidence["first_user_role"]).toBe("admin");

    // PagerDuty uses the Token token= header form + versioned Accept.
    const abCall = calls.find((c) => c.url.endsWith("/abilities"));
    expect(abCall?.headers["authorization"]).toBe(`Token token=${KEY}`);
    expect(abCall?.headers["accept"]).toBe("application/vnd.pagerduty+json;version=2");
  });

  it("dead key (401) is DENIED and stops after abilities", async () => {
    let usersCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/users")) {
        usersCalled = true;
        return mockResponse({ json: { users: [] } });
      }
      return mockResponse({ status: 401, json: { error: { message: "Unauthorized" } } });
    });
    const result = await pagerdutyLadder(finding("PagerDutyApiKey", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["abilities"]);
    expect(usersCalled).toBe(false);
  });

  it("GATED create-incident is blocked without consent and fires no POST", async () => {
    let incidentCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/incidents")) {
        incidentCalled = true;
        return mockResponse({ status: 201, json: { incident: { id: "PINC1" } } });
      }
      if (call.url.endsWith("/abilities")) {
        return mockResponse({ json: { abilities: ["sso"] } });
      }
      return mockResponse({ json: { users: [], more: false } });
    });
    const result = await pagerdutyLadder(finding("PagerDutyApiKey", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const incident = result.rungs.find((r) => r.name === "create-incident");
    expect(incident?.tier).toBe(ProbeTier.GATED);
    expect(incident?.blocked).toBe(true);
    expect(incident?.success).toBe(false);
    expect(incident?.evidence["safe_curl"]).toContain("$KEY");
    expect(incidentCalled).toBe(false);
  });

  it("the @gated create-incident probe refuses without consent", async () => {
    await expect(pagerdutyGatedCreateIncident(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    let incidentCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/incidents")) {
        incidentCalled = true;
        return mockResponse({ status: 201, json: { incident: { id: "PINC1" } } });
      }
      if (call.url.endsWith("/abilities")) {
        return mockResponse({ json: { abilities: ["sso"] } });
      }
      return mockResponse({ json: { users: [], more: false } });
    });
    const result = await pagerdutyLadder(finding("PagerDutyApiKey", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual rung never succeeds
    const incident = result.rungs.find((r) => r.name === "create-incident");
    expect(incident?.blocked).toBe(false);
    expect(incident?.evidence["manual"]).toBe(true);
    expect(incidentCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/abilities")) {
        return mockResponse({ json: { abilities: ["sso"] } });
      }
      return mockResponse({ json: { users: [], more: false } });
    });
    const result = await pagerdutyLadder(finding("PagerDutyApiKey", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers PagerDuty (case-insensitive)", () => {
    expect(getLadder("PagerDutyApiKey")).toBeTypeOf("function");
    expect(getLadder("pagerdutyapikey")).toBeTypeOf("function");
  });
  it("tags the gated create-incident GATED", () => {
    expect(pagerdutyGatedCreateIncident.vtxTier).toBe(ProbeTier.GATED);
  });
});
