/**
 * Tests for the Airtable capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid PAT climbs two SAFE rungs (whoami -> list-bases) to VALID;
 * * a dead PAT (401) yields DENIED and stops after whoami;
 * * the GATED record read is MANUAL: it never fires a live call, blocked without
 *   consent and rendered as a safe-curl (secret kept as $KEY) with full consent.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { airtableLadder, airtableListBaseRecords } from "../src/providers/airtable.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic shape: pat<14>.<64 hex>. Random padding, NOT a real credential.
const KEY = "pat" + "EXAMPLEFAKEKEY" + "." + "deadbeef".repeat(8);

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      airtableLadder(finding("AirtablePersonalAccessToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Airtable", () => {
  it("valid PAT climbs the SAFE rungs (whoami -> list-bases) with evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v0/meta/whoami")) {
        return mockResponse({ json: { id: "usr123", email: "owner@victim.example", scopes: ["data.records:read", "schema.bases:read"] } });
      }
      if (call.url.endsWith("/v0/meta/bases")) {
        return mockResponse({
          json: {
            bases: [
              { id: "appONE", name: "Customers", permissionLevel: "create" },
              { id: "appTWO", name: "Inventory", permissionLevel: "read" },
            ],
          },
        });
      }
      return mockResponse({ status: 404 });
    });
    const result = await airtableLadder(finding("AirtablePersonalAccessToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("airtable");
    expect(result.verdict).toBe(Verdict.VALID);

    const whoami = result.rungs.find((r) => r.name === "airtable.whoami");
    expect(whoami?.tier).toBe(ProbeTier.SAFE);
    expect(whoami?.success).toBe(true);
    expect(whoami?.evidence["user_id"]).toBe("usr123");
    expect(whoami?.evidence["scopes"]).toEqual(["data.records:read", "schema.bases:read"]);

    const bases = result.rungs.find((r) => r.name === "airtable.list-bases");
    expect(bases?.success).toBe(true);
    expect(bases?.evidence["base_count"]).toBe(2);
    expect(bases?.evidence["base_names"]).toEqual(["Customers", "Inventory"]);

    // The bearer token was carried on whoami against the right host.
    const whoamiCall = calls.find((c) => c.url.endsWith("/v0/meta/whoami"));
    expect(whoamiCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
  });

  it("dead PAT (401) is DENIED and stops after whoami", async () => {
    let basesCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v0/meta/bases")) {
        basesCalled = true;
        return mockResponse({ json: { bases: [] } });
      }
      return mockResponse({ status: 401, json: { error: "AUTHENTICATION_REQUIRED" } });
    });
    const result = await airtableLadder(finding("AirtablePersonalAccessToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["airtable.whoami"]);
    expect(basesCalled).toBe(false);
  });

  it("GATED record read is blocked without consent and fires no call", async () => {
    let recordsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/BASE_ID/") || call.url.includes("maxRecords")) {
        recordsCalled = true;
        return mockResponse({ json: { records: [{ id: "recLEAK" }] } });
      }
      if (call.url.endsWith("/v0/meta/whoami")) {
        return mockResponse({ json: { id: "usr1", scopes: [] } });
      }
      return mockResponse({ json: { bases: [] } });
    });
    const result = await airtableLadder(finding("AirtablePersonalAccessToken", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // safe ok + gated blocked
    const records = result.rungs.find((r) => r.name === "airtable.list-base-records");
    expect(records?.tier).toBe(ProbeTier.GATED);
    expect(records?.blocked).toBe(true);
    expect(records?.success).toBe(false);
    expect(records?.evidence["safe_curl"]).toContain("$KEY");
    expect(recordsCalled).toBe(false);
  });

  it("the @gated record read refuses without consent (no call)", async () => {
    await expect(airtableListBaseRecords(SAFE_CONSENT, KEY)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    let recordsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("maxRecords")) {
        recordsCalled = true;
        return mockResponse({ json: { records: [] } });
      }
      if (call.url.endsWith("/v0/meta/whoami")) {
        return mockResponse({ json: { id: "usr1", scopes: [] } });
      }
      return mockResponse({ json: { bases: [] } });
    });
    const result = await airtableLadder(finding("AirtablePersonalAccessToken", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual rung never succeeds
    const records = result.rungs.find((r) => r.name === "airtable.list-base-records");
    expect(records?.blocked).toBe(false);
    expect(records?.evidence["manual"]).toBe(true);
    expect(records?.evidence["safe_curl"]).toContain("$KEY");
    expect(recordsCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v0/meta/whoami")) {
        return mockResponse({ json: { id: "usr1", scopes: [] } });
      }
      return mockResponse({ json: { bases: [] } });
    });
    const result = await airtableLadder(finding("AirtablePersonalAccessToken", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Airtable (case-insensitive)", () => {
    expect(getLadder("AirtablePersonalAccessToken")).toBeTypeOf("function");
    expect(getLadder("airtablepersonalaccesstoken")).toBeTypeOf("function");
  });
  it("tags the gated record read GATED", () => {
    expect(airtableListBaseRecords.vtxTier).toBe(ProbeTier.GATED);
  });
});
