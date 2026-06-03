/**
 * Tests for the PayPal capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * A PayPal credential is a client_id:client_secret pair and every live call
 * needs a minted bearer token, so EVERY rung is MANUAL: the ladder makes NO live
 * call. We assert:
 *
 * * the two SAFE rungs render as manual safe-curls ($KEY) and verdict is DENIED;
 * * the GATED create-payout rung is blocked without consent (no call, $KEY curl)
 *   and stays a manual safe-curl with full consent (no PROVEN);
 * * the raw secret never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { paypalGatedCreatePayout, paypalLadder } from "../src/providers/paypal.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SECRET = "EXAMPLEFAKEKEYNOTREALclientid" + ":" + "EXAMPLEFAKEKEYNOTREAL" + "clientsecret";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      paypalLadder(finding("PaypalOauth", SECRET), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("PayPal", () => {
  it("renders all rungs as manual safe-curls and makes no live call -> DENIED", async () => {
    let called = false;
    const { fetchImpl, calls } = mockFetch(() => {
      called = true;
      return mockResponse({ json: { access_token: "leak" } });
    });
    const result = await paypalLadder(finding("PaypalOauth", SECRET), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("paypal");
    expect(result.authorizedScope).toBe("acme h1 program #4242");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["oauth2-token", "userinfo", "create-payout"]);
    for (const rung of result.rungs) {
      expect(rung.success).toBe(false);
      expect(rung.evidence["manual"]).toBe(true);
      const curl = String(rung.evidence["safe_curl"]);
      expect(curl).toContain("$KEY");
      expect(curl).not.toContain(SECRET);
    }
    expect(called).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("GATED create-payout is blocked without consent (no call, manual safe-curl)", async () => {
    const result = await paypalLadder(finding("PaypalOauth", SECRET), SAFE_CONSENT);
    const payout = result.rungs.find((r) => r.name === "create-payout");
    expect(payout?.tier).toBe(ProbeTier.GATED);
    expect(payout?.blocked).toBe(true);
    expect(payout?.success).toBe(false);
    expect(payout?.evidence["manual"]).toBe(true);
    expect(String(payout?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("the @gated create-payout probe refuses without consent", async () => {
    await expect(paypalGatedCreatePayout(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const result = await paypalLadder(finding("PaypalOauth", SECRET), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    const payout = result.rungs.find((r) => r.name === "create-payout");
    expect(payout?.blocked).toBe(false);
    expect(payout?.success).toBe(false);
    expect(payout?.evidence["manual"]).toBe(true);
    expect(String(payout?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw secret in the public view", async () => {
    const result = await paypalLadder(finding("PaypalOauth", SECRET), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(SECRET);
  });
});

describe("registration", () => {
  it("registers PaypalOauth (case-insensitive)", () => {
    expect(getLadder("PaypalOauth")).toBeTypeOf("function");
    expect(getLadder("paypaloauth")).toBeTypeOf("function");
  });
  it("tags the gated create-payout probe GATED", () => {
    expect(paypalGatedCreatePayout.vtxTier).toBe(ProbeTier.GATED);
  });
});
