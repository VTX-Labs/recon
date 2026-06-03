/**
 * Tests for the Asana capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (users-me -> list-workspaces) to VALID;
 * * a dead token (401) yields DENIED and stops after users-me;
 * * the GATED list-workspace-users rung is MANUAL: blocked without consent,
 *   rendered as a safe-curl (secret kept as $KEY) with full consent, never fired.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { asanaLadder, asanaGatedListWorkspaceUsers } from "../src/providers/asana.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic Asana PAT shape: digits/slug, random padding.
const KEY = "0/0000000000000000:00000000000000000000000000000000";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      asanaLadder(finding("AsanaPersonalAccessToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Asana", () => {
  it("valid token climbs the SAFE rungs (users-me -> list-workspaces)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/users/me")) {
        return mockResponse({
          json: { data: { gid: "111", name: "Victim Owner", email: "owner@victim.example", workspaces: [{ gid: "W1" }] } },
        });
      }
      if (call.url.endsWith("/workspaces")) {
        return mockResponse({ json: { data: [{ gid: "W1", name: "Acme Org" }, { gid: "W2", name: "Side Project" }] } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await asanaLadder(finding("AsanaPersonalAccessToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("asana");
    expect(result.verdict).toBe(Verdict.VALID);

    const me = result.rungs.find((r) => r.name === "users-me");
    expect(me?.tier).toBe(ProbeTier.SAFE);
    expect(me?.success).toBe(true);
    expect(me?.evidence["gid"]).toBe("111");
    expect(me?.evidence["workspace_count"]).toBe(1);

    const ws = result.rungs.find((r) => r.name === "list-workspaces");
    expect(ws?.evidence["workspace_count"]).toBe(2);

    const meCall = calls.find((c) => c.url.endsWith("/users/me"));
    expect(meCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
  });

  it("dead token (401) is DENIED and stops after users-me", async () => {
    let wsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/workspaces")) {
        wsCalled = true;
        return mockResponse({ json: { data: [] } });
      }
      return mockResponse({ status: 401, json: { errors: [{ message: "Not Authorized" }] } });
    });
    const result = await asanaLadder(finding("AsanaPersonalAccessToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["users-me"]);
    expect(wsCalled).toBe(false);
  });

  it("GATED list-workspace-users is blocked without consent and fires no call", async () => {
    let usersCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/users?workspace=")) {
        usersCalled = true;
        return mockResponse({ json: { data: [{ email: "leak@victim.example" }] } });
      }
      if (call.url.endsWith("/users/me")) {
        return mockResponse({ json: { data: { gid: "1", workspaces: [] } } });
      }
      return mockResponse({ json: { data: [] } });
    });
    const result = await asanaLadder(finding("AsanaPersonalAccessToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const rung = result.rungs.find((r) => r.name === "list-workspace-users");
    expect(rung?.tier).toBe(ProbeTier.GATED);
    expect(rung?.blocked).toBe(true);
    expect(rung?.success).toBe(false);
    expect(rung?.evidence["safe_curl"]).toContain("$KEY");
    expect(usersCalled).toBe(false);
  });

  it("the @gated PII probe refuses without consent", async () => {
    await expect(asanaGatedListWorkspaceUsers(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire)", async () => {
    let usersCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/users?workspace=")) {
        usersCalled = true;
        return mockResponse({ json: { data: [] } });
      }
      if (call.url.endsWith("/users/me")) {
        return mockResponse({ json: { data: { gid: "1", workspaces: [] } } });
      }
      return mockResponse({ json: { data: [] } });
    });
    const result = await asanaLadder(finding("AsanaPersonalAccessToken", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const rung = result.rungs.find((r) => r.name === "list-workspace-users");
    expect(rung?.blocked).toBe(false);
    expect(rung?.evidence["manual"]).toBe(true);
    expect(usersCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/users/me")) {
        return mockResponse({ json: { data: { gid: "1", workspaces: [] } } });
      }
      return mockResponse({ json: { data: [] } });
    });
    const result = await asanaLadder(finding("AsanaPersonalAccessToken", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Asana detectors (case-insensitive)", () => {
    expect(getLadder("AsanaPersonalAccessToken")).toBeTypeOf("function");
    expect(getLadder("AsanaOauth")).toBeTypeOf("function");
    expect(getLadder("asanaoauth")).toBeTypeOf("function");
  });
  it("tags the gated probe GATED", () => {
    expect(asanaGatedListWorkspaceUsers.vtxTier).toBe(ProbeTier.GATED);
  });
});
