/**
 * Tests for the Postmark Server API capability ladder. All HTTP is MOCKED via an
 * injected fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (get-server -> delivery-stats) to VALID
 *   using the `X-Postmark-Server-Token` header;
 * * a dead token (401) yields DENIED and stops after get-server;
 * * the GATED send-email rung is MANUAL: blocked without consent, and with full
 *   consent it never fires — it renders a safe curl keeping $KEY.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { postmarkLadder, postmarkSendEmailGated } from "../src/providers/postmark.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic Postmark server token (UUID). Random padding, NOT a real credential.
const KEY = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      postmarkLadder(finding("Postmark", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Postmark", () => {
  it("valid token climbs the SAFE rungs (get-server -> delivery-stats)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/server")) {
        return mockResponse({ json: { ID: 9001, Name: "Transactional", Color: "blue", DeliveryType: "Live" } });
      }
      if (call.url.endsWith("/deliverystats")) {
        return mockResponse({ json: { InactiveMails: 3, Bounces: [{ Type: "HardBounce", Count: 2 }] } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await postmarkLadder(finding("Postmark", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("postmark");
    expect(result.verdict).toBe(Verdict.VALID);

    const server = result.rungs.find((r) => r.name === "get-server");
    expect(server?.tier).toBe(ProbeTier.SAFE);
    expect(server?.success).toBe(true);
    expect(server?.evidence["id"]).toBe(9001);
    expect(server?.evidence["name"]).toBe("Transactional");

    const stats = result.rungs.find((r) => r.name === "delivery-stats");
    expect(stats?.evidence["inactive_mails"]).toBe(3);
    expect(stats?.evidence["bounce_type_count"]).toBe(1);

    const serverCall = calls.find((c) => c.url.endsWith("/server"));
    expect(serverCall?.headers["x-postmark-server-token"]).toBe(KEY);
  });

  it("dead token (401) is DENIED and stops after get-server", async () => {
    let statsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/deliverystats")) {
        statsCalled = true;
        return mockResponse({ json: { InactiveMails: 0, Bounces: [] } });
      }
      return mockResponse({ status: 401, json: { ErrorCode: 10, Message: "No account token or server token." } });
    });
    const result = await postmarkLadder(finding("Postmark", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["get-server"]);
    expect(statsCalled).toBe(false);
  });

  it("GATED send-email is blocked without consent and fires no POST", async () => {
    let sendCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/email")) {
        sendCalled = true;
        return mockResponse({ json: { MessageID: "leak" } });
      }
      if (call.url.endsWith("/server")) {
        return mockResponse({ json: { ID: 1, Name: "S" } });
      }
      return mockResponse({ json: { InactiveMails: 0, Bounces: [] } });
    });
    const result = await postmarkLadder(finding("Postmark", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const send = result.rungs.find((r) => r.name === "send-email");
    expect(send?.tier).toBe(ProbeTier.GATED);
    expect(send?.blocked).toBe(true);
    expect(send?.success).toBe(false);
    expect(send?.evidence["safe_curl"]).toContain("$KEY");
    expect(sendCalled).toBe(false);
  });

  it("the @gated send probe refuses without consent", async () => {
    await expect(postmarkSendEmailGated(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire)", async () => {
    let sendCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/email")) {
        sendCalled = true;
        return mockResponse({ json: { MessageID: "leak" } });
      }
      if (call.url.endsWith("/server")) {
        return mockResponse({ json: { ID: 1, Name: "S" } });
      }
      return mockResponse({ json: { InactiveMails: 0, Bounces: [] } });
    });
    const result = await postmarkLadder(finding("Postmark", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const send = result.rungs.find((r) => r.name === "send-email");
    expect(send?.blocked).toBe(false);
    expect(send?.evidence["manual"]).toBe(true);
    expect(sendCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/server")) {
        return mockResponse({ json: { ID: 1, Name: "S" } });
      }
      return mockResponse({ json: { InactiveMails: 0, Bounces: [] } });
    });
    const result = await postmarkLadder(finding("Postmark", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Postmark (case-insensitive)", () => {
    expect(getLadder("Postmark")).toBeTypeOf("function");
    expect(getLadder("postmark")).toBeTypeOf("function");
  });
  it("tags the gated send GATED", () => {
    expect(postmarkSendEmailGated.vtxTier).toBe(ProbeTier.GATED);
  });
});
