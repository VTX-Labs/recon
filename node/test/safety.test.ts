/**
 * The safety boundary is the most important guarantee in vtx-recon, so it gets
 * the most thorough test: a GATED probe must be unreachable unless BOTH
 * --prove and --i-am-authorized were supplied, and the block must happen before
 * any probe body runs (fail-closed).
 */

import { describe, expect, it } from "vitest";
import {
  Consent,
  GatedProbeBlocked,
  ProbeTier,
  ScopeRequired,
  gated,
  guard,
} from "../src/safety.js";

describe("guard", () => {
  it("is a no-op for SAFE regardless of consent", () => {
    expect(() => guard(Consent.denied(), ProbeTier.SAFE, "list_models")).not.toThrow();
  });

  it.each([
    Consent.denied(),
    new Consent({ prove: true, authorizedScope: null }), // prove only
    new Consent({ prove: true, authorizedScope: "   " }), // blank scope
    new Consent({ prove: false, authorizedScope: "program-x" }), // scope only
  ])("blocks GATED without full consent (%#)", (consent: Consent) => {
    expect(() => guard(consent, ProbeTier.GATED, "stripe_account_read")).toThrow(GatedProbeBlocked);
  });

  it("allows GATED with full consent", () => {
    const consent = new Consent({ prove: true, authorizedScope: "bugbounty:acme" });
    expect(consent.gatedAllowed).toBe(true);
    expect(() => guard(consent, ProbeTier.GATED, "gemini_generate")).not.toThrow();
  });
});

describe("gated()", () => {
  it("blocks before the body runs and runs it with full consent", async () => {
    let ran = false;
    const dangerous = gated("dangerous", async (_consent: Consent) => {
      ran = true; // must never execute when blocked
      return "did something billable";
    });

    // The wrapper tags the tier without invoking the probe.
    expect(dangerous.vtxTier).toBe(ProbeTier.GATED);

    await expect(dangerous(Consent.denied())).rejects.toBeInstanceOf(GatedProbeBlocked);
    expect(ran).toBe(false);

    const out = await dangerous(new Consent({ prove: true, authorizedScope: "acme" }));
    expect(out).toBe("did something billable");
    expect(ran).toBe(true);
  });

  it("fails closed when no Consent is visible in the arguments", async () => {
    const dangerous = gated("dangerous", async (value: number) => value);
    // No Consent reachable -> treated as denied -> blocked.
    await expect(dangerous(1)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });
});

describe("Consent.requireLadderScope", () => {
  it("throws ScopeRequired with no scope and returns the normalised scope otherwise", () => {
    expect(() => Consent.denied().requireLadderScope()).toThrow(ScopeRequired);
    expect(() =>
      new Consent({ prove: true, authorizedScope: null }).requireLadderScope(),
    ).toThrow(ScopeRequired);
    expect(new Consent({ authorizedScope: "  acme  " }).requireLadderScope()).toBe("acme");
  });
});

describe("Consent", () => {
  it("is immutable (frozen)", () => {
    const consent = new Consent({ prove: true, authorizedScope: "acme" });
    expect(() => {
      // @ts-expect-error testing runtime immutability
      consent.prove = false;
    }).toThrow();
    expect(consent.prove).toBe(true);
  });

  it("reports a blocking reason unless fully consented", () => {
    expect(Consent.denied().blockingReason()).not.toBeNull();
    expect(new Consent({ prove: true }).blockingReason()).not.toBeNull();
    expect(new Consent({ authorizedScope: "x" }).blockingReason()).not.toBeNull();
    expect(new Consent({ prove: true, authorizedScope: "x" }).blockingReason()).toBeNull();
  });
});
