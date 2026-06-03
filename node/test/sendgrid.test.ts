/**
 * Tests for the SendGrid capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid key climbs the SAFE `scopes` rung to VALID, with real scope evidence;
 *   the GATED send-mail rung is blocked without consent and fires no call;
 * * a dead key (401) yields DENIED and never reaches send-mail;
 * * with full consent the GATED send-mail rung actually runs (202) -> PROVEN;
 * * the raw key never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { sendgridLadder, sendgridSendMail } from "../src/providers/sendgrid.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "SG" + ".EXAMPLEFAKEKEYNOTREAL0" + "." + "EXAMPLEFAKEKEYNOTREAL00000000000000000000000";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(sendgridLadder(finding("SendGrid", KEY), Consent.denied())).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });
});

describe("SendGrid", () => {
  it("valid key reads scopes -> VALID; GATED send-mail blocked without consent", async () => {
    let sendCalled = false;
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.includes("/v3/mail/send")) {
        sendCalled = true;
        return mockResponse({ status: 202 });
      }
      if (call.url.includes("/v3/scopes")) {
        return mockResponse({ json: { scopes: ["mail.send", "mail.batch.read"] } });
      }
      return mockResponse({ status: 404 });
    });

    const result = await sendgridLadder(finding("SendGrid", KEY), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("sendgrid");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual(["sendgrid.scopes", "sendgrid.send_mail"]);
    const scopes = result.rungs[0];
    expect(scopes?.tier).toBe(ProbeTier.SAFE);
    expect(scopes?.success).toBe(true);
    expect(scopes?.evidence["scope_count"]).toBe(2);
    expect(scopes?.evidence["can_send_mail"]).toBe(true);
    const scopeCall = calls.find((c) => c.url.includes("/v3/scopes"));
    expect(scopeCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    // The gated send was blocked and never fired.
    const send = result.rungs.find((r) => r.name === "sendgrid.send_mail");
    expect(send?.tier).toBe(ProbeTier.GATED);
    expect(send?.blocked).toBe(true);
    expect(sendCalled).toBe(false);
  });

  it("dead key is DENIED and never reaches send-mail", async () => {
    let sendCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v3/mail/send")) {
        sendCalled = true;
        return mockResponse({ status: 202 });
      }
      return mockResponse({ status: 401, json: { errors: [{ message: "unauthorized" }] } });
    });
    const result = await sendgridLadder(finding("SendGrid", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["sendgrid.scopes"]);
    expect(sendCalled).toBe(false);
  });

  it("the @gated send-mail refuses without consent and makes no call", async () => {
    let called = false;
    const { fetchImpl } = mockFetch(() => {
      called = true;
      return mockResponse({ status: 202 });
    });
    await expect(sendgridSendMail(SAFE_CONSENT, KEY, fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    expect(called).toBe(false);
  });

  it("with full consent the GATED send-mail runs (202) -> PROVEN", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v3/mail/send")) {
        return mockResponse({ status: 202 });
      }
      return mockResponse({ json: { scopes: ["mail.send"] } });
    });
    const result = await sendgridLadder(finding("SendGrid", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.PROVEN);
    const send = result.rungs.find((r) => r.name === "sendgrid.send_mail");
    expect(send?.success).toBe(true);
    expect(send?.blocked).toBe(false);
    expect(send?.evidence["state_changed"]).toBe(true);
  });

  it("never leaks the raw key in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v3/mail/send")) {
        return mockResponse({ status: 202 });
      }
      return mockResponse({ json: { scopes: ["mail.send"] } });
    });
    const result = await sendgridLadder(finding("SendGrid", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers SendGrid (case-insensitive)", () => {
    expect(getLadder("SendGrid")).toBeTypeOf("function");
    expect(getLadder("sendgrid")).toBeTypeOf("function");
    expect(getLadder("Sendgrid")).toBeTypeOf("function");
  });
  it("tags the gated send-mail probe GATED", () => {
    expect(sendgridSendMail.vtxTier).toBe(ProbeTier.GATED);
  });
});
