/**
 * Tests for the Linear capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * Linear is GraphQL: every rung POSTs to one endpoint and authenticates with the
 * raw key in `Authorization` WITHOUT a `Bearer ` prefix. A 200 with a top-level
 * `errors` array is a failure. We assert:
 *
 * * a valid key climbs two SAFE rungs (viewer -> organization) to VALID; the
 *   GATED user-PII enumeration is blocked without consent and fires no call;
 * * a dead key (200 + errors) yields DENIED and stops after viewer;
 * * with full consent the GATED rung actually runs -> PROVEN, PII summarised;
 * * the raw key never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { linearLadder, linearListOrgUsers } from "../src/providers/linear.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "lin_api" + "_EXAMPLEFAKEKEYNOTREAL0000000000000000000";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

// Route a GraphQL POST by inspecting the query in the request body.
const queryIncludes = (body: string | undefined, needle: string) =>
  typeof body === "string" && body.includes(needle);

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(linearLadder(finding("LinearAPI", KEY), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("Linear", () => {
  it("valid key climbs the SAFE rungs; GATED user read blocked without consent", async () => {
    let usersCalled = false;
    const { fetchImpl, calls } = mockFetch((call) => {
      if (queryIncludes(call.body, "users {")) {
        usersCalled = true;
        return mockResponse({ json: { data: { users: { nodes: [{ name: "x" }] } } } });
      }
      if (queryIncludes(call.body, "viewer")) {
        return mockResponse({
          json: { data: { viewer: { id: "v1", name: "Victim", email: "victim@example.com" } } },
        });
      }
      if (queryIncludes(call.body, "organization")) {
        return mockResponse({
          json: { data: { organization: { id: "o1", name: "Acme", urlKey: "acme", userCount: 42 } } },
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await linearLadder(finding("LinearAPI", KEY), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("linear");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "viewer-identity",
      "organization",
      "list-org-users",
    ]);
    const viewer = result.rungs[0];
    expect(viewer?.success).toBe(true);
    expect(viewer?.evidence["viewer_id"]).toBe("v1");
    expect(result.rungs[1]?.evidence["user_count"]).toBe(42);
    // Linear auth header is the raw key, NO Bearer prefix.
    const viewerCall = calls.find((c) => queryIncludes(c.body, "viewer"));
    expect(viewerCall?.method).toBe("POST");
    expect(viewerCall?.headers["authorization"]).toBe(KEY);
    // The gated user-PII enumeration was blocked and never fired.
    const users = result.rungs.find((r) => r.name === "list-org-users");
    expect(users?.tier).toBe(ProbeTier.GATED);
    expect(users?.blocked).toBe(true);
    expect(usersCalled).toBe(false);
  });

  it("dead key (200 + errors) is DENIED and stops after viewer", async () => {
    let orgCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (queryIncludes(call.body, "organization")) {
        orgCalled = true;
        return mockResponse({ json: { data: { organization: {} } } });
      }
      return mockResponse({ json: { errors: [{ message: "Authentication required" }] } });
    });
    const result = await linearLadder(finding("LinearAPI", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["viewer-identity"]);
    expect(orgCalled).toBe(false);
  });

  it("the @gated user enumeration refuses without consent and makes no call", async () => {
    let called = false;
    const { fetchImpl } = mockFetch(() => {
      called = true;
      return mockResponse({ json: { data: { users: { nodes: [] } } } });
    });
    await expect(linearListOrgUsers(SAFE_CONSENT, KEY, fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    expect(called).toBe(false);
  });

  it("with full consent the GATED user read runs -> PROVEN, PII summarised", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (queryIncludes(call.body, "users {")) {
        return mockResponse({
          json: {
            data: {
              users: {
                nodes: [
                  { name: "Alice", email: "alice@example.com" },
                  { name: "Bob", email: "bob@example.com" },
                ],
              },
            },
          },
        });
      }
      if (queryIncludes(call.body, "viewer")) {
        return mockResponse({ json: { data: { viewer: { id: "v1", name: "V" } } } });
      }
      return mockResponse({ json: { data: { organization: { id: "o1", userCount: 2 } } } });
    });
    const result = await linearLadder(finding("LinearAPI", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.PROVEN);
    const users = result.rungs.find((r) => r.name === "list-org-users");
    expect(users?.success).toBe(true);
    expect(users?.blocked).toBe(false);
    expect(users?.evidence["user_count"]).toBe(2);
    expect(users?.evidence["names_sample"]).toEqual(["Alice", "Bob"]);
  });

  it("never leaks the raw key in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (queryIncludes(call.body, "users {")) {
        return mockResponse({ json: { data: { users: { nodes: [] } } } });
      }
      if (queryIncludes(call.body, "viewer")) {
        return mockResponse({ json: { data: { viewer: { id: "v1" } } } });
      }
      return mockResponse({ json: { data: { organization: { id: "o1" } } } });
    });
    const result = await linearLadder(finding("LinearAPI", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers LinearAPI (case-insensitive)", () => {
    expect(getLadder("LinearAPI")).toBeTypeOf("function");
    expect(getLadder("linearapi")).toBeTypeOf("function");
  });
  it("tags the gated user enumeration GATED", () => {
    expect(linearListOrgUsers.vtxTier).toBe(ProbeTier.GATED);
  });
});
