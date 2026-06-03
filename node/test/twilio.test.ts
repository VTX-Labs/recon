/**
 * Tests for the Twilio capability ladder.
 *
 * Twilio is FULLY MANUAL: the finding carries only the Account SID (`AC...`),
 * which is half of the HTTP-basic credential — the paired AuthToken is not
 * present — so NO authenticated request can be issued. Every rung is a manual
 * safe-curl note.
 *
 * Per the source, the SID (a public-ish identifier, not the AuthToken) is inlined
 * into the curls while the real secret is kept as the `$TWILIO_AUTH_TOKEN` shell
 * variable. We assert that contract: no rung fires, and the AuthToken placeholder
 * (never a real token) is what every curl carries.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { twilioLadder, twilioGatedBalance } from "../src/providers/twilio.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic Account SID shape: AC + 32 hex. This is the identifier, not a secret.
const SID = "AC" + "deadbeef".repeat(4);

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      twilioLadder(finding("Twilio", SID), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Twilio (fully manual)", () => {
  it("renders SAFE manual rungs + a blocked GATED balance rung; verdict DENIED", async () => {
    const result = await twilioLadder(finding("Twilio", SID), SAFE_CONSENT);
    expect(result.provider).toBe("twilio");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "twilio.account.fetch",
      "twilio.phone_numbers",
      "twilio.balance",
    ]);

    for (const name of ["twilio.account.fetch", "twilio.phone_numbers"]) {
      const rung = result.rungs.find((r) => r.name === name);
      expect(rung?.tier).toBe(ProbeTier.SAFE);
      expect(rung?.success).toBe(false);
      expect(rung?.evidence["manual"]).toBe(true);
      // The AuthToken (the real secret) is never inlined — only the placeholder.
      expect(rung?.evidence["safe_curl"]).toContain("$TWILIO_AUTH_TOKEN");
    }

    const balance = result.rungs.find((r) => r.name === "twilio.balance");
    expect(balance?.tier).toBe(ProbeTier.GATED);
    expect(balance?.blocked).toBe(true);
    expect(balance?.success).toBe(false);
    expect(balance?.evidence["safe_curl"]).toContain("$TWILIO_AUTH_TOKEN");
  });

  it("the @gated balance probe refuses without consent", async () => {
    await expect(twilioGatedBalance(SAFE_CONSENT, SID)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED balance rung stays MANUAL (not blocked, still DENIED)", async () => {
    const result = await twilioLadder(finding("Twilio", SID), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    const balance = result.rungs.find((r) => r.name === "twilio.balance");
    expect(balance?.blocked).toBe(false);
    expect(balance?.evidence["manual"]).toBe(true);
    expect(balance?.evidence["safe_curl"]).toContain("$TWILIO_AUTH_TOKEN");
  });
});

describe("secret redaction", () => {
  it("never serialises the paired AuthToken (the real secret stays a placeholder)", async () => {
    const result = await twilioLadder(finding("Twilio", SID), FULL_CONSENT);
    const json = JSON.stringify(result.toPublic());
    // The AuthToken is never present; only the safe shell-variable placeholder is.
    expect(json).toContain("$TWILIO_AUTH_TOKEN");
  });
});

describe("registration", () => {
  it("registers Twilio (case-insensitive)", () => {
    expect(getLadder("Twilio")).toBeTypeOf("function");
    expect(getLadder("twilio")).toBeTypeOf("function");
  });
  it("tags the gated balance GATED", () => {
    expect(twilioGatedBalance.vtxTier).toBe(ProbeTier.GATED);
  });
});
