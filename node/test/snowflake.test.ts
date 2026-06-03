/**
 * Tests for the Snowflake capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * The Snowflake ladder takes no fetchImpl: every call needs a KEYPAIR_JWT (not in
 * the raw credential) plus the {account} host, so EVERY rung is MANUAL and makes
 * NO live call. The safe-curls keep the secret as a `$JWT` placeholder. We assert:
 *
 * * the two SAFE rungs render as manual safe-curls and verdict is DENIED;
 * * the GATED exfil rung is blocked without consent (no call) and stays a manual
 *   safe-curl with full consent (no PROVEN);
 * * the raw credential never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { snowflakeExfilTableData, snowflakeLadder } from "../src/providers/snowflake.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import "../src/providers/index.js";

const CREDENTIAL = "account=xy12345 user=VICTIM " + "password=" + "EXAMPLE_FAKE_PASSWORD_NOT_REAL";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      snowflakeLadder(finding("Snowflake", CREDENTIAL), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Snowflake", () => {
  it("renders all rungs as manual safe-curls and makes no live call -> DENIED", async () => {
    const result = await snowflakeLadder(finding("Snowflake", CREDENTIAL), SAFE_CONSENT);

    expect(result.provider).toBe("snowflake");
    expect(result.authorizedScope).toBe("acme h1 program #4242");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "whoami-current-user",
      "list-databases",
      "exfil-table-data",
    ]);
    for (const rung of result.rungs) {
      expect(rung.success).toBe(false);
      expect(rung.evidence["manual"]).toBe(true);
      const curl = String(rung.evidence["safe_curl"]);
      expect(curl).toContain("$JWT");
      expect(curl).not.toContain(CREDENTIAL);
    }
  });

  it("GATED exfil rung is blocked without consent (no call, manual safe-curl)", async () => {
    const result = await snowflakeLadder(finding("Snowflake", CREDENTIAL), SAFE_CONSENT);
    const exfil = result.rungs.find((r) => r.name === "exfil-table-data");
    expect(exfil?.tier).toBe(ProbeTier.GATED);
    expect(exfil?.blocked).toBe(true);
    expect(exfil?.success).toBe(false);
    expect(exfil?.evidence["manual"]).toBe(true);
    expect(exfil?.evidence["billable"]).toBe(true);
    expect(String(exfil?.evidence["safe_curl"])).toContain("$JWT");
  });

  it("the @gated exfil probe refuses without consent", async () => {
    await expect(snowflakeExfilTableData(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const result = await snowflakeLadder(finding("Snowflake", CREDENTIAL), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    const exfil = result.rungs.find((r) => r.name === "exfil-table-data");
    expect(exfil?.blocked).toBe(false);
    expect(exfil?.success).toBe(false);
    expect(exfil?.evidence["manual"]).toBe(true);
    expect(String(exfil?.evidence["safe_curl"])).toContain("$JWT");
  });

  it("never leaks the raw credential in the public view", async () => {
    const result = await snowflakeLadder(finding("Snowflake", CREDENTIAL), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(CREDENTIAL);
  });
});

describe("registration", () => {
  it("registers Snowflake (case-insensitive)", () => {
    expect(getLadder("Snowflake")).toBeTypeOf("function");
    expect(getLadder("snowflake")).toBeTypeOf("function");
  });
  it("tags the gated exfil probe GATED", () => {
    expect(snowflakeExfilTableData.vtxTier).toBe(ProbeTier.GATED);
  });
});
