/**
 * Tests for the Slack capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs its SAFE rungs (auth.test -> conversations -> users ->
 *   files) to VALID, with real JSON evidence (team, channel/member/file counts);
 * * a dead token yields DENIED and stops after auth.test;
 * * the GATED history/post rungs are structurally blocked without consent —
 *   recorded as `blocked`, manual safe-curl surfaced, and fire NO network call.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import {
  slackGatedPostMessage,
  slackGatedReadHistory,
  slackLadder,
} from "../src/providers/slack.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(slackLadder(finding("Slack", "xoxb-abc"), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("Slack", () => {
  it("valid token climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.includes("/auth.test")) {
        return mockResponse({
          json: { ok: true, team: "Acme", team_id: "T123", user: "leaky-bot", user_id: "U456" },
        });
      }
      if (call.url.includes("/conversations.list")) {
        return mockResponse({ json: { ok: true, channels: [{ id: "C1" }, { id: "C2" }] } });
      }
      if (call.url.includes("/users.list")) {
        return mockResponse({ json: { ok: true, members: [{ id: "U1" }, { id: "U2" }, { id: "U3" }] } });
      }
      if (call.url.includes("/files.list")) {
        return mockResponse({ json: { ok: true, files: [{ id: "F1" }] } });
      }
      return mockResponse({ json: { ok: false, error: "unexpected" } });
    });

    const result = await slackLadder(finding("Slack", "xoxb-valid"), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("slack");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.authorizedScope).toBe("acme h1 program #4242");
    expect(result.rungs.map((r) => r.name)).toEqual([
      "slack.auth.test",
      "slack.conversations.list",
      "slack.users.list",
      "slack.files.list",
      "slack.conversations.history",
      "slack.chat.postMessage",
    ]);
    const auth = result.rungs[0];
    expect(auth?.evidence["team_id"]).toBe("T123");
    expect(auth?.evidence["user_id"]).toBe("U456");
    expect(result.rungs[1]?.evidence["channel_count"]).toBe(2);
    expect(result.rungs[2]?.evidence["member_count"]).toBe(3);
    expect(result.rungs[3]?.evidence["file_count"]).toBe(1);
    // The bearer token was carried on auth.test.
    const authCall = calls.find((c) => c.url.includes("/auth.test"));
    expect(authCall?.headers["authorization"]).toBe("Bearer xoxb-valid");
  });

  it("dead token is DENIED and stops after auth.test", async () => {
    let channelsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/conversations.list")) {
        channelsCalled = true;
        return mockResponse({ json: { ok: true, channels: [] } });
      }
      return mockResponse({ json: { ok: false, error: "invalid_auth" } });
    });
    const result = await slackLadder(finding("Slack", "xoxb-dead"), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["slack.auth.test"]);
    expect(result.rungs[0]?.detail).toContain("invalid_auth");
    expect(channelsCalled).toBe(false);
  });

  it("GATED history + post rungs are blocked without consent and fire no call", async () => {
    let gatedCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/conversations.history") || call.url.includes("/chat.postMessage")) {
        gatedCalled = true;
        return mockResponse({ json: { ok: true } });
      }
      if (call.url.includes("/auth.test")) {
        return mockResponse({ json: { ok: true, team: "Acme", user: "bot" } });
      }
      return mockResponse({ json: { ok: true, channels: [], members: [], files: [] } });
    });
    const result = await slackLadder(finding("Slack", "xoxb-valid"), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // safe ok + gated blocked
    const history = result.rungs.find((r) => r.name === "slack.conversations.history");
    const post = result.rungs.find((r) => r.name === "slack.chat.postMessage");
    for (const rung of [history, post]) {
      expect(rung?.tier).toBe(ProbeTier.GATED);
      expect(rung?.blocked).toBe(true);
      expect(rung?.success).toBe(false);
      expect(rung?.evidence["manual"]).toBe(true);
      expect(rung?.evidence["safe_curl"]).toContain("$KEY");
    }
    expect(gatedCalled).toBe(false); // hard guarantee: no PII/send request issued
  });

  it("the @gated history/post probes refuse without consent (manual, no call)", async () => {
    await expect(slackGatedReadHistory(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
    await expect(slackGatedPostMessage(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rungs stay MANUAL (no auto-fire, no PROVEN)", async () => {
    let gatedCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/conversations.history") || call.url.includes("/chat.postMessage")) {
        gatedCalled = true;
        return mockResponse({ json: { ok: true } });
      }
      if (call.url.includes("/auth.test")) {
        return mockResponse({ json: { ok: true, team: "Acme", user: "bot" } });
      }
      return mockResponse({ json: { ok: true, channels: [], members: [], files: [] } });
    });
    const result = await slackLadder(finding("Slack", "xoxb-valid"), FULL_CONSENT, { fetchImpl });
    // Manual rungs never report success, so the verdict stays VALID, not PROVEN.
    expect(result.verdict).toBe(Verdict.VALID);
    const history = result.rungs.find((r) => r.name === "slack.conversations.history");
    expect(history?.blocked).toBe(false);
    expect(history?.evidence["manual"]).toBe(true);
    expect(gatedCalled).toBe(false);
  });
});

describe("registration", () => {
  it("registers Slack + SlackWebhook (case-insensitive)", () => {
    expect(getLadder("Slack")).toBeTypeOf("function");
    expect(getLadder("slack")).toBeTypeOf("function");
    expect(getLadder("SlackWebhook")).toBeTypeOf("function");
  });
  it("tags the gated slack probes GATED", () => {
    expect(slackGatedReadHistory.vtxTier).toBe(ProbeTier.GATED);
    expect(slackGatedPostMessage.vtxTier).toBe(ProbeTier.GATED);
  });
});
