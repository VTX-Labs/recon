/**
 * Tests for the Pusher Channels capability ladder. All HTTP is MOCKED via an
 * injected fetch — these tests NEVER touch a real API.
 *
 * The Pusher ladder takes no fetchImpl: every REST call needs the paired app
 * SECRET to HMAC-sign plus the {cluster}/{app_id} the engine cannot fill, so
 * EVERY rung is MANUAL and makes NO live call. We assert:
 *
 * * the two SAFE rungs render as manual safe-curls ($KEY) and verdict is DENIED;
 * * the GATED trigger-event rung is blocked without consent (no call, $KEY curl)
 *   and stays a manual safe-curl with full consent (no PROVEN);
 * * the raw key never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { pusherLadder, pusherTriggerEvent } from "../src/providers/pusher.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import "../src/providers/index.js";

const KEY = "a1b2c3d4e5f6a7b8c9d0";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      pusherLadder(finding("PusherChannelKey", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Pusher", () => {
  it("renders all rungs as manual safe-curls and makes no live call -> DENIED", async () => {
    const result = await pusherLadder(finding("PusherChannelKey", KEY), SAFE_CONSENT);

    expect(result.provider).toBe("pusher");
    expect(result.authorizedScope).toBe("acme h1 program #4242");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "list-channels",
      "channel-info",
      "trigger-event",
    ]);
    for (const rung of result.rungs) {
      expect(rung.success).toBe(false);
      expect(rung.evidence["manual"]).toBe(true);
      const curl = String(rung.evidence["safe_curl"]);
      expect(curl).toContain("$KEY");
      expect(curl).not.toContain(KEY);
    }
  });

  it("GATED trigger-event is blocked without consent (no call, manual safe-curl)", async () => {
    const result = await pusherLadder(finding("PusherChannelKey", KEY), SAFE_CONSENT);
    const trigger = result.rungs.find((r) => r.name === "trigger-event");
    expect(trigger?.tier).toBe(ProbeTier.GATED);
    expect(trigger?.blocked).toBe(true);
    expect(trigger?.success).toBe(false);
    expect(trigger?.evidence["manual"]).toBe(true);
    expect(String(trigger?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("the @gated trigger-event probe refuses without consent", async () => {
    await expect(pusherTriggerEvent(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const result = await pusherLadder(finding("PusherChannelKey", KEY), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    const trigger = result.rungs.find((r) => r.name === "trigger-event");
    expect(trigger?.blocked).toBe(false);
    expect(trigger?.success).toBe(false);
    expect(trigger?.evidence["manual"]).toBe(true);
    expect(String(trigger?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw key in the public view", async () => {
    const result = await pusherLadder(finding("PusherChannelKey", KEY), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers PusherChannelKey (case-insensitive)", () => {
    expect(getLadder("PusherChannelKey")).toBeTypeOf("function");
    expect(getLadder("pusherchannelkey")).toBeTypeOf("function");
  });
  it("tags the gated trigger-event probe GATED", () => {
    expect(pusherTriggerEvent.vtxTier).toBe(ProbeTier.GATED);
  });
});
