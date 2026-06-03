/**
 * Tests for the Shopify capability ladder.
 *
 * Shopify is FULLY MANUAL: every endpoint lives on `https://{shop}.myshopify.com`
 * and the shop domain is not in the raw token, so NO live call is ever made.
 *
 * * laddering without scope rejects with ScopeRequired;
 * * the two SAFE rungs render manual safe-curls (secret kept as $KEY);
 * * the GATED list-customers rung is blocked without consent and stays MANUAL
 *   with full consent — no rung ever succeeds, so the verdict is DENIED;
 * * no network call is ever made.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { shopifyLadder, shopifyGatedListCustomers } from "../src/providers/shopify.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic Admin API token shape: shpat_<32 hex>. Random padding.
const KEY = "shpat" + "_" + "deadbeef".repeat(4);

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      shopifyLadder(finding("ShopifyToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Shopify (fully manual)", () => {
  it("renders SAFE manual rungs + a blocked GATED rung; verdict DENIED", async () => {
    const result = await shopifyLadder(finding("ShopifyToken", KEY), SAFE_CONSENT);
    expect(result.provider).toBe("shopify");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "access-scopes",
      "shop-info",
      "list-customers",
    ]);

    const scopes = result.rungs.find((r) => r.name === "access-scopes");
    const info = result.rungs.find((r) => r.name === "shop-info");
    for (const rung of [scopes, info]) {
      expect(rung?.tier).toBe(ProbeTier.SAFE);
      expect(rung?.success).toBe(false);
      expect(rung?.evidence["manual"]).toBe(true);
      expect(rung?.evidence["safe_curl"]).toContain("$KEY");
      expect(rung?.evidence["safe_curl"]).not.toContain(KEY);
    }

    const customers = result.rungs.find((r) => r.name === "list-customers");
    expect(customers?.tier).toBe(ProbeTier.GATED);
    expect(customers?.blocked).toBe(true);
    expect(customers?.success).toBe(false);
    expect(customers?.evidence["safe_curl"]).toContain("$KEY");
  });

  it("the @gated customer-PII probe refuses without consent", async () => {
    await expect(shopifyGatedListCustomers(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (not blocked, still DENIED)", async () => {
    const result = await shopifyLadder(finding("ShopifyToken", KEY), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    const customers = result.rungs.find((r) => r.name === "list-customers");
    expect(customers?.blocked).toBe(false);
    expect(customers?.evidence["manual"]).toBe(true);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const result = await shopifyLadder(finding("ShopifyToken", KEY), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Shopify detectors (case-insensitive)", () => {
    expect(getLadder("ShopifyToken")).toBeTypeOf("function");
    expect(getLadder("Shopify")).toBeTypeOf("function");
    expect(getLadder("shopifytoken")).toBeTypeOf("function");
  });
  it("tags the gated customer read GATED", () => {
    expect(shopifyGatedListCustomers.vtxTier).toBe(ProbeTier.GATED);
  });
});
