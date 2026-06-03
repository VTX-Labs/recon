/**
 * Tests for the Algolia capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * Algolia auth also needs the Application ID (not in the 32-hex key), so EVERY
 * rung is MANUAL: the ladder makes NO live call. We assert:
 *
 * * the SAFE rungs render as manual safe-curls ($KEY, $APP_ID), make no call,
 *   and the verdict is DENIED (nothing can succeed automatically);
 * * the GATED clear-index rung is blocked without consent (no call), and stays
 *   a manual safe-curl even with full consent (no auto-fire, no PROVEN);
 * * the raw key never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { algoliaClearIndex, algoliaLadder } from "../src/providers/algolia.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "deadbeefdeadbeefdeadbeefdeadbeef";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      algoliaLadder(finding("AlgoliaAdminKey", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Algolia", () => {
  it("renders all SAFE rungs as manual safe-curls and makes no live call", async () => {
    let called = false;
    const { fetchImpl, calls } = mockFetch(() => {
      called = true;
      return mockResponse({ json: { acl: ["addObject"] } });
    });
    const result = await algoliaLadder(finding("AlgoliaAdminKey", KEY), SAFE_CONSENT, { fetchImpl });

    expect(result.provider).toBe("algolia");
    expect(result.authorizedScope).toBe("acme h1 program #4242");
    // All rungs manual -> nothing succeeds -> DENIED.
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "get-own-key-acl",
      "list-all-keys",
      "list-indices",
      "clear-index",
    ]);
    const safe = result.rungs.filter((r) => r.tier === ProbeTier.SAFE);
    expect(safe).toHaveLength(3);
    for (const rung of safe) {
      expect(rung.success).toBe(false);
      expect(rung.evidence["manual"]).toBe(true);
      const curl = String(rung.evidence["safe_curl"]);
      expect(curl).toContain("$KEY");
      expect(curl).toContain("$APP_ID");
      expect(curl).not.toContain(KEY);
    }
    expect(called).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("GATED clear-index is blocked without consent (no call, manual safe-curl)", async () => {
    const result = await algoliaLadder(finding("AlgoliaAdminKey", KEY), SAFE_CONSENT);
    const clear = result.rungs.find((r) => r.name === "clear-index");
    expect(clear?.tier).toBe(ProbeTier.GATED);
    expect(clear?.blocked).toBe(true);
    expect(clear?.success).toBe(false);
    expect(clear?.evidence["manual"]).toBe(true);
    expect(String(clear?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("the @gated clear-index probe refuses without consent", async () => {
    await expect(algoliaClearIndex(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const result = await algoliaLadder(finding("AlgoliaAdminKey", KEY), FULL_CONSENT);
    // Manual rungs never report success, so the verdict stays DENIED.
    expect(result.verdict).toBe(Verdict.DENIED);
    const clear = result.rungs.find((r) => r.name === "clear-index");
    expect(clear?.blocked).toBe(false);
    expect(clear?.success).toBe(false);
    expect(clear?.evidence["manual"]).toBe(true);
    expect(String(clear?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw key in the public view", async () => {
    const result = await algoliaLadder(finding("AlgoliaAdminKey", KEY), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers AlgoliaAdminKey (case-insensitive)", () => {
    expect(getLadder("AlgoliaAdminKey")).toBeTypeOf("function");
    expect(getLadder("algoliaadminkey")).toBeTypeOf("function");
  });
  it("tags the gated clear-index probe GATED", () => {
    expect(algoliaClearIndex.vtxTier).toBe(ProbeTier.GATED);
  });
});
