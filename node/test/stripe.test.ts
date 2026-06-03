/**
 * Tests for the Stripe capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid key climbs its SAFE rungs (auth -> products -> balance txns) to
 *   VALID; a restricted-key 403 on a scope probe still counts as reachable;
 * * a dead key yields DENIED and skips every gated rung;
 * * the GATED account/charges reads are structurally blocked without consent —
 *   recorded `blocked`, firing NO network call;
 * * with full consent the gated reads run -> PROVEN, PII summarised not dumped.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { getLadder } from "../src/providers/registry.js";
import {
  stripeAccountRead,
  stripeChargesList,
  stripeLadder,
} from "../src/providers/stripe.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      stripeLadder(finding("Stripe", "sk_live_x"), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Stripe", () => {
  it("valid key climbs the SAFE rungs (403 scope probe still reachable)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v1/balance_transactions")) {
        return mockResponse({ json: { object: "list", data: [{ id: "txn_1" }] } });
      }
      if (call.url.includes("/v1/balance")) {
        return mockResponse({ json: { object: "balance" } });
      }
      if (call.url.includes("/v1/products")) {
        // Restricted key: forbidden on products, but still a live key.
        return mockResponse({ status: 403, json: { error: { message: "no permission" } } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await stripeLadder(finding("Stripe", "sk_live_x"), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("stripe");
    expect(result.verdict).toBe(Verdict.VALID);
    const safeRungs = result.rungs.filter((r) => r.tier === ProbeTier.SAFE);
    expect(safeRungs.map((r) => r.name)).toEqual([
      "stripe.auth_check",
      "stripe.products.list",
      "stripe.balance_transactions",
    ]);
    expect(safeRungs.every((r) => r.success)).toBe(true);
    const products = result.rungs.find((r) => r.name === "stripe.products.list");
    expect(products?.evidence["readable"]).toBe(false); // 403 -> reachable, not readable
    const txns = result.rungs.find((r) => r.name === "stripe.balance_transactions");
    expect(txns?.evidence["readable"]).toBe(true);
    expect(txns?.evidence["sample_count"]).toBe(1);
  });

  it("GATED account + charges reads are blocked without consent and make no call", async () => {
    let accountCalled = false;
    let chargesCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v1/account")) {
        accountCalled = true;
        return mockResponse({ json: { id: "acct_LEAK" } });
      }
      if (call.url.includes("/v1/charges")) {
        chargesCalled = true;
        return mockResponse({ json: { data: [{ id: "ch_LEAK" }] } });
      }
      return mockResponse({ json: { object: "balance", data: [] } });
    });
    const result = await stripeLadder(finding("Stripe", "sk_live_x"), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // safe ok + gated blocked
    const account = result.rungs.find((r) => r.name === "stripe.account.read");
    const charges = result.rungs.find((r) => r.name === "stripe.charges.list");
    for (const rung of [account, charges]) {
      expect(rung?.tier).toBe(ProbeTier.GATED);
      expect(rung?.blocked).toBe(true);
      expect(rung?.success).toBe(false);
    }
    expect(accountCalled).toBe(false); // hard guarantee: no PII request issued
    expect(chargesCalled).toBe(false);
  });

  it("the @gated probes themselves refuse without consent and make no call", async () => {
    let called = false;
    const { fetchImpl } = mockFetch(() => {
      called = true;
      return mockResponse({ json: { id: "acct_LEAK" } });
    });
    await expect(stripeAccountRead(SAFE_CONSENT, "sk_live_x", fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    await expect(stripeChargesList(SAFE_CONSENT, "sk_live_x", fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    expect(called).toBe(false);
  });

  it("full consent reaches the gated rungs -> PROVEN, PII summarised not dumped", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v1/account")) {
        return mockResponse({
          json: {
            id: "acct_123",
            country: "US",
            business_type: "company",
            charges_enabled: true,
            email: "owner@victim.example",
          },
        });
      }
      if (call.url.includes("/v1/charges")) {
        return mockResponse({
          json: {
            data: [
              {
                id: "ch_1",
                receipt_email: "buyer@victim.example",
                billing_details: { name: "Jane Buyer" },
              },
            ],
          },
        });
      }
      if (call.url.includes("/v1/products")) {
        return mockResponse({ json: { data: [] } });
      }
      return mockResponse({ json: { object: "balance", data: [] } });
    });
    const result = await stripeLadder(finding("Stripe", "sk_live_x"), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.PROVEN);
    const account = result.rungs.find((r) => r.name === "stripe.account.read");
    expect(account?.success).toBe(true);
    expect(account?.blocked).toBe(false);
    expect(account?.evidence["account_id"]).toBe("acct_123");
    expect("email" in (account?.evidence ?? {})).toBe(false);
    expect(account?.evidence["pii_fields_present"]).toContain("email");
    const charges = result.rungs.find((r) => r.name === "stripe.charges.list");
    expect(charges?.success).toBe(true);
    expect(charges?.evidence["charge_count"]).toBe(1);
    expect(charges?.evidence["pii_fields_present"]).toContain("receipt_email");
    expect("receipt_email" in (charges?.evidence ?? {})).toBe(false);
  });

  it("dead key is DENIED and skips every gated rung", async () => {
    let accountCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/v1/account")) {
        accountCalled = true;
        return mockResponse({ json: { id: "acct_LEAK" } });
      }
      return mockResponse({ status: 401, json: { error: { message: "Invalid API Key" } } });
    });
    const result = await stripeLadder(finding("Stripe", "sk_live_dead"), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs).toHaveLength(1);
    expect(accountCalled).toBe(false);
  });
});

describe("registration", () => {
  it("registers each Stripe detector (case-insensitive)", () => {
    expect(getLadder("Stripe")).toBeTypeOf("function");
    expect(getLadder("stripe")).toBeTypeOf("function");
    expect(getLadder("StripeAccessToken")).toBeTypeOf("function");
  });
  it("tags the gated stripe reads GATED", () => {
    expect(stripeAccountRead.vtxTier).toBe(ProbeTier.GATED);
    expect(stripeChargesList.vtxTier).toBe(ProbeTier.GATED);
  });
});
