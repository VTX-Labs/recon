/**
 * Tests for the Azure Storage SAS capability ladder. All HTTP is MOCKED via an
 * injected fetch — these tests NEVER touch a real API.
 *
 * The Azure ladder takes no fetchImpl: every rung is MANUAL (the storage
 * ACCOUNT/CONTAINER and the AD tenant/client are not in the raw SAS), so it
 * makes NO live call. We assert:
 *
 * * the two SAFE rungs render as manual safe-curls ($KEY) and verdict is DENIED;
 * * the GATED list-blobs rung is blocked without consent (no call, $KEY curl),
 *   and stays a manual safe-curl with full consent (no PROVEN);
 * * the raw SAS never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { azureLadder } from "../src/providers/azure.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import "../src/providers/index.js";

const SAS = "sp=racwl&st=2024-01-01T00:00:00Z&se=2025-01-01T00:00:00Z&" + "sig=" + "AbCdEf123Deadbeef%3D";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      azureLadder(finding("AzureSasToken", SAS), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Azure", () => {
  it("renders all rungs as manual safe-curls and makes no live call -> DENIED", async () => {
    const result = await azureLadder(finding("AzureSasToken", SAS), SAFE_CONSENT);

    expect(result.provider).toBe("azure");
    expect(result.authorizedScope).toBe("acme h1 program #4242");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "sas-resource-probe",
      "list-blobs",
      "service-principal-token",
    ]);
    for (const rung of result.rungs) {
      expect(rung.success).toBe(false);
      expect(rung.evidence["manual"]).toBe(true);
      const curl = String(rung.evidence["safe_curl"]);
      expect(curl).toContain("$KEY");
      expect(curl).not.toContain(SAS);
    }
  });

  it("GATED list-blobs is blocked without consent (no call, manual safe-curl)", async () => {
    const result = await azureLadder(finding("AzureSasToken", SAS), SAFE_CONSENT);
    const listBlobs = result.rungs.find((r) => r.name === "list-blobs");
    expect(listBlobs?.tier).toBe(ProbeTier.GATED);
    expect(listBlobs?.blocked).toBe(true);
    expect(listBlobs?.success).toBe(false);
    expect(listBlobs?.evidence["manual"]).toBe(true);
    expect(String(listBlobs?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const result = await azureLadder(finding("AzureStorage", SAS), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    const listBlobs = result.rungs.find((r) => r.name === "list-blobs");
    expect(listBlobs?.blocked).toBe(false);
    expect(listBlobs?.success).toBe(false);
    expect(listBlobs?.evidence["manual"]).toBe(true);
    expect(String(listBlobs?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw SAS in the public view", async () => {
    const result = await azureLadder(finding("AzureSasToken", SAS), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(SAS);
  });
});

describe("registration", () => {
  it("registers AzureSasToken + AzureStorage (case-insensitive)", () => {
    expect(getLadder("AzureSasToken")).toBeTypeOf("function");
    expect(getLadder("azuresastoken")).toBeTypeOf("function");
    expect(getLadder("AzureStorage")).toBeTypeOf("function");
  });
});
