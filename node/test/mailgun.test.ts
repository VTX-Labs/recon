/**
 * Tests for the Mailgun capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * Mailgun has no whoami: list-domains is the identity AND depth proof.
 *
 * * a valid key climbs two SAFE rungs (list-domains -> list-domain-keys) to VALID
 *   using HTTP Basic auth (`Authorization: Basic {key}`);
 * * a dead key (401) yields DENIED and stops after list-domains;
 * * the GATED send-message rung is MANUAL: blocked without consent, and with full
 *   consent it never fires — it renders a safe curl keeping $KEY.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { mailgunLadder, mailgunGatedSendMessage } from "../src/providers/mailgun.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic legacy key shape: key-<32 hex>. Random padding, NOT a real credential.
const KEY = "key" + "-" + "deadbeef".repeat(4);

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      mailgunLadder(finding("Mailgun", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Mailgun", () => {
  it("valid key climbs the SAFE rungs (list-domains -> list-domain-keys)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.includes("/v4/domains")) {
        return mockResponse({ json: { items: [{ name: "mg.victim.example" }, { name: "mail.victim.example" }], total_count: 2 } });
      }
      if (call.url.includes("/v1/dkim/keys")) {
        return mockResponse({ json: { items: [{ signing_domain: "mg.victim.example" }] } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await mailgunLadder(finding("Mailgun", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("mailgun");
    expect(result.verdict).toBe(Verdict.VALID);

    const domains = result.rungs.find((r) => r.name === "list-domains");
    expect(domains?.tier).toBe(ProbeTier.SAFE);
    expect(domains?.success).toBe(true);
    expect(domains?.evidence["domain_count"]).toBe(2);
    expect(domains?.evidence["domains_sample"]).toEqual(["mg.victim.example", "mail.victim.example"]);

    const keys = result.rungs.find((r) => r.name === "list-domain-keys");
    expect(keys?.evidence["dkim_key_count"]).toBe(1);

    // Mailgun uses HTTP Basic auth carrying the key.
    const domCall = calls.find((c) => c.url.includes("/v4/domains"));
    expect(domCall?.headers["authorization"]).toBe(`Basic ${KEY}`);
  });

  it("dead key (401) is DENIED and stops after list-domains", async () => {
    let keysCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v1/dkim/keys")) {
        keysCalled = true;
        return mockResponse({ json: { items: [] } });
      }
      return mockResponse({ status: 401, json: { message: "Invalid private key" } });
    });
    const result = await mailgunLadder(finding("Mailgun", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["list-domains"]);
    expect(keysCalled).toBe(false);
  });

  it("GATED send-message is blocked without consent and fires no call", async () => {
    let sendCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/messages")) {
        sendCalled = true;
        return mockResponse({ json: { id: "<leak@mg>" } });
      }
      if (call.url.includes("/v4/domains")) {
        return mockResponse({ json: { items: [{ name: "mg.victim.example" }] } });
      }
      return mockResponse({ json: { items: [] } });
    });
    const result = await mailgunLadder(finding("Mailgun", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const send = result.rungs.find((r) => r.name === "send-message");
    expect(send?.tier).toBe(ProbeTier.GATED);
    expect(send?.blocked).toBe(true);
    expect(send?.success).toBe(false);
    expect(send?.evidence["safe_curl"]).toContain("$KEY");
    expect(sendCalled).toBe(false);
  });

  it("the @gated send probe refuses without consent", async () => {
    await expect(mailgunGatedSendMessage(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire)", async () => {
    let sendCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/messages")) {
        sendCalled = true;
        return mockResponse({ json: { id: "<leak@mg>" } });
      }
      if (call.url.includes("/v4/domains")) {
        return mockResponse({ json: { items: [{ name: "mg.victim.example" }] } });
      }
      return mockResponse({ json: { items: [] } });
    });
    const result = await mailgunLadder(finding("Mailgun", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const send = result.rungs.find((r) => r.name === "send-message");
    expect(send?.blocked).toBe(false);
    expect(send?.evidence["manual"]).toBe(true);
    expect(sendCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v4/domains")) {
        return mockResponse({ json: { items: [{ name: "mg.victim.example" }] } });
      }
      return mockResponse({ json: { items: [] } });
    });
    const result = await mailgunLadder(finding("Mailgun", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Mailgun (case-insensitive)", () => {
    expect(getLadder("Mailgun")).toBeTypeOf("function");
    expect(getLadder("mailgun")).toBeTypeOf("function");
  });
  it("tags the gated send GATED", () => {
    expect(mailgunGatedSendMessage.vtxTier).toBe(ProbeTier.GATED);
  });
});
