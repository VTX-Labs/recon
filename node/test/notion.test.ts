/**
 * Tests for the Notion capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs its one SAFE rung (bot-user) to VALID;
 * * a dead token (401) yields DENIED and stops after bot-user;
 * * the two GATED rungs (list-users, search-shared-content) are blocked without
 *   consent (no call), and with FULL consent they fire real reads -> PROVEN with
 *   member PII and shared content summarised, not dumped.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import {
  notionLadder,
  notionListUsers,
  notionSearchSharedContent,
} from "../src/providers/notion.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic secret_<43+> shape. Random padding, NOT a real credential.
const KEY = "secret" + "_EXAMPLEFAKEKEYNOTREAL0000000000000000000000";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      notionLadder(finding("Notion", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Notion", () => {
  it("valid token climbs the SAFE bot-user rung to VALID", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v1/users/me")) {
        return mockResponse({
          json: { id: "bot1", name: "Acme Bot", type: "bot", bot: { owner: { type: "workspace" }, workspace_name: "Acme HQ" } },
        });
      }
      return mockResponse({ status: 404 });
    });
    const result = await notionLadder(finding("Notion", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("notion");
    expect(result.verdict).toBe(Verdict.VALID);

    const bot = result.rungs.find((r) => r.name === "bot-user");
    expect(bot?.tier).toBe(ProbeTier.SAFE);
    expect(bot?.success).toBe(true);
    expect(bot?.evidence["bot_id"]).toBe("bot1");
    expect(bot?.evidence["owner_type"]).toBe("workspace");
    expect(bot?.evidence["workspace_name"]).toBe("Acme HQ");

    // The two GATED rungs are blocked (no consent) but recorded.
    const users = result.rungs.find((r) => r.name === "list-users");
    const search = result.rungs.find((r) => r.name === "search-shared-content");
    for (const rung of [users, search]) {
      expect(rung?.tier).toBe(ProbeTier.GATED);
      expect(rung?.blocked).toBe(true);
    }

    const meCall = calls.find((c) => c.url.endsWith("/v1/users/me"));
    expect(meCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    expect(meCall?.headers["notion-version"]).toBe("2022-06-28");
  });

  it("dead token (401) is DENIED and stops after bot-user", async () => {
    let usersCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/users")) {
        usersCalled = true;
        return mockResponse({ json: { results: [] } });
      }
      return mockResponse({ status: 401, json: { object: "error", code: "unauthorized" } });
    });
    const result = await notionLadder(finding("Notion", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["bot-user"]);
    expect(usersCalled).toBe(false);
  });

  it("GATED rungs are blocked without consent and fire no call", async () => {
    let gatedCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/users") || call.url.endsWith("/v1/search")) {
        gatedCalled = true;
        return mockResponse({ json: { results: [] } });
      }
      if (call.url.endsWith("/v1/users/me")) {
        return mockResponse({ json: { id: "b1", bot: {} } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await notionLadder(finding("Notion", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    expect(gatedCalled).toBe(false);
  });

  it("the @gated probes refuse without consent and make no call", async () => {
    let called = false;
    const { fetchImpl } = mockFetch(() => {
      called = true;
      return mockResponse({ json: { results: [] } });
    });
    await expect(notionListUsers(SAFE_CONSENT, KEY, fetchImpl)).rejects.toBeInstanceOf(GatedProbeBlocked);
    await expect(notionSearchSharedContent(SAFE_CONSENT, KEY, fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    expect(called).toBe(false);
  });

  it("full consent reaches the gated rungs -> PROVEN, PII/content summarised", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/users/me")) {
        return mockResponse({ json: { id: "b1", name: "Bot", bot: { owner: { type: "workspace" } } } });
      }
      if (call.url.endsWith("/v1/users")) {
        return mockResponse({
          json: {
            results: [
              { id: "u1", name: "Alice", type: "person", person: { email: "alice@victim.example" } },
              { id: "u2", name: "Acme Bot", type: "bot" },
            ],
          },
        });
      }
      if (call.url.endsWith("/v1/search")) {
        return mockResponse({
          json: { results: [{ object: "page" }, { object: "database" }], has_more: true },
        });
      }
      return mockResponse({ status: 404 });
    });
    const result = await notionLadder(finding("Notion", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.PROVEN);

    const users = result.rungs.find((r) => r.name === "list-users");
    expect(users?.success).toBe(true);
    expect(users?.blocked).toBe(false);
    expect(users?.evidence["user_count"]).toBe(2);
    expect(users?.evidence["person_count"]).toBe(1);
    // Member emails are never recorded.
    expect(JSON.stringify(users?.evidence)).not.toContain("alice@victim.example");

    const search = result.rungs.find((r) => r.name === "search-shared-content");
    expect(search?.success).toBe(true);
    expect(search?.evidence["sample_count"]).toBe(2);
    expect(search?.evidence["object_types"]).toEqual(["database", "page"]);
    expect(search?.evidence["has_more"]).toBe(true);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/users/me")) {
        return mockResponse({ json: { id: "b1", bot: {} } });
      }
      return mockResponse({ json: { results: [] } });
    });
    const result = await notionLadder(finding("Notion", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Notion (case-insensitive)", () => {
    expect(getLadder("Notion")).toBeTypeOf("function");
    expect(getLadder("notion")).toBeTypeOf("function");
  });
  it("tags the gated rungs GATED", () => {
    expect(notionListUsers.vtxTier).toBe(ProbeTier.GATED);
    expect(notionSearchSharedContent.vtxTier).toBe(ProbeTier.GATED);
  });
});
