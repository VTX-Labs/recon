/**
 * Tests for the Discord capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid bot token climbs two SAFE rungs (users/@me -> guilds) to VALID, with
 *   real evidence; the two GATED rungs (channel history/send) are blocked manual
 *   notes;
 * * a dead token (401) yields DENIED and stops after users/@me;
 * * the GATED rungs fire NO network call without consent and stay manual
 *   safe-curls ($KEY) with full consent;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import {
  discordGatedReadHistory,
  discordGatedSendMessage,
  discordLadder,
} from "../src/providers/discord.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const TOKEN = "EXAMPLE" + "FAKEKEYNOTREAL00" + "." + "EXAMPL" + "." + "EXAMPLEFAKEKEYNOTREAL000000000000";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      discordLadder(finding("DiscordBotToken", TOKEN), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Discord", () => {
  it("valid token climbs the SAFE rungs with real evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/users/@me")) {
        return mockResponse({ json: { id: "999", username: "leaky-bot", bot: true } });
      }
      if (call.url.includes("/users/@me/guilds")) {
        return mockResponse({ json: [{ name: "Victim Guild" }, { name: "Two" }] });
      }
      return mockResponse({ status: 404 });
    });

    const result = await discordLadder(finding("DiscordBotToken", TOKEN), SAFE_CONSENT, {
      fetchImpl,
    });

    expect(result.provider).toBe("discord");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "discord.users.me",
      "discord.guilds",
      "discord.channel.history",
      "discord.channel.send",
    ]);
    const me = result.rungs[0];
    expect(me?.success).toBe(true);
    expect(me?.evidence["id"]).toBe("999");
    expect(me?.evidence["username"]).toBe("leaky-bot");
    expect(result.rungs[1]?.evidence["guild_count"]).toBe(2);
    // The Bot scheme (not Bearer) was carried on users/@me.
    const meCall = calls.find((c) => c.url.endsWith("/users/@me"));
    expect(meCall?.headers["authorization"]).toBe(`Bot ${TOKEN}`);
    // Both gated rungs were blocked (no consent).
    for (const name of ["discord.channel.history", "discord.channel.send"]) {
      const rung = result.rungs.find((r) => r.name === name);
      expect(rung?.tier).toBe(ProbeTier.GATED);
      expect(rung?.blocked).toBe(true);
      expect(String(rung?.evidence["safe_curl"])).toContain("$KEY");
    }
  });

  it("dead token is DENIED and stops after users/@me", async () => {
    let guildsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/guilds")) {
        guildsCalled = true;
        return mockResponse({ json: [] });
      }
      return mockResponse({ status: 401, json: { message: "401: Unauthorized" } });
    });
    const result = await discordLadder(finding("DiscordBotToken", TOKEN), SAFE_CONSENT, {
      fetchImpl,
    });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["discord.users.me"]);
    expect(guildsCalled).toBe(false);
  });

  it("the @gated channel probes refuse without consent", async () => {
    await expect(discordGatedReadHistory(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
    await expect(discordGatedSendMessage(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rungs stay MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/users/@me")) {
        return mockResponse({ json: { id: "1", username: "bot" } });
      }
      if (call.url.includes("/channels/")) {
        throw new Error("gated channel rung must never auto-fire");
      }
      return mockResponse({ json: [] });
    });
    const result = await discordLadder(finding("DiscordBotToken", TOKEN), FULL_CONSENT, {
      fetchImpl,
    });
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    for (const name of ["discord.channel.history", "discord.channel.send"]) {
      const rung = result.rungs.find((r) => r.name === name);
      expect(rung?.blocked).toBe(false);
      expect(rung?.success).toBe(false);
      expect(rung?.evidence["manual"]).toBe(true);
      expect(String(rung?.evidence["safe_curl"])).toContain("$KEY");
    }
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/users/@me")) {
        return mockResponse({ json: { id: "1", username: "bot" } });
      }
      return mockResponse({ json: [] });
    });
    const result = await discordLadder(finding("DiscordBotToken", TOKEN), FULL_CONSENT, {
      fetchImpl,
    });
    expect(JSON.stringify(result.toPublic())).not.toContain(TOKEN);
  });
});

describe("registration", () => {
  it("registers the Discord detectors (case-insensitive)", () => {
    expect(getLadder("DiscordBotToken")).toBeTypeOf("function");
    expect(getLadder("discordbottoken")).toBeTypeOf("function");
    expect(getLadder("Discord")).toBeTypeOf("function");
    expect(getLadder("DiscordWebhook")).toBeTypeOf("function");
  });
  it("tags the gated discord probes GATED", () => {
    expect(discordGatedReadHistory.vtxTier).toBe(ProbeTier.GATED);
    expect(discordGatedSendMessage.vtxTier).toBe(ProbeTier.GATED);
  });
});
