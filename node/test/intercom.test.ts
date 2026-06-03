/**
 * Tests for the Intercom capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (me -> list-admins) to VALID;
 * * a dead token (401) yields DENIED and stops after me;
 * * the GATED list-contacts PII read is blocked without consent (no call), and
 *   with FULL consent it fires a real read -> PROVEN with PII summarised.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { intercomLadder, intercomListContacts } from "../src/providers/intercom.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic dXXX... Intercom token. Random padding, NOT a real credential.
const KEY = "dG9r" + "OkVYQU1QTEVfRkFLRV9LRVlfTk9UX1JFQUwwMA==";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      intercomLadder(finding("Intercom", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Intercom", () => {
  it("valid token climbs the SAFE rungs (me -> list-admins)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/me")) {
        return mockResponse({
          json: { id: "admin1", email: "owner@victim.example", name: "Owner", app: { id_code: "acme", name: "Acme Inc" } },
        });
      }
      if (call.url.endsWith("/admins")) {
        return mockResponse({ json: { admins: [{ email: "a@victim.example" }, { email: "b@victim.example" }] } });
      }
      return mockResponse({ status: 404 });
    });
    const result = await intercomLadder(finding("Intercom", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("intercom");
    expect(result.verdict).toBe(Verdict.VALID);

    const me = result.rungs.find((r) => r.name === "intercom.me");
    expect(me?.tier).toBe(ProbeTier.SAFE);
    expect(me?.success).toBe(true);
    expect(me?.evidence["admin_id"]).toBe("admin1");
    expect(me?.evidence["app_name"]).toBe("Acme Inc");

    const admins = result.rungs.find((r) => r.name === "intercom.list-admins");
    expect(admins?.evidence["admin_count"]).toBe(2);

    // Bearer auth + pinned API version are carried.
    const meCall = calls.find((c) => c.url.endsWith("/me"));
    expect(meCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    expect(meCall?.headers["intercom-version"]).toBe("2.11");
  });

  it("dead token (401) is DENIED and stops after me", async () => {
    let adminsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/admins")) {
        adminsCalled = true;
        return mockResponse({ json: { admins: [] } });
      }
      return mockResponse({ status: 401, json: { type: "error.list", errors: [{ code: "unauthorized" }] } });
    });
    const result = await intercomLadder(finding("Intercom", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["intercom.me"]);
    expect(adminsCalled).toBe(false);
  });

  it("GATED list-contacts is blocked without consent and fires no call", async () => {
    let contactsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/contacts")) {
        contactsCalled = true;
        return mockResponse({ json: { data: [{ name: "Leak", email: "leak@victim.example" }], total_count: 1 } });
      }
      if (call.url.endsWith("/me")) {
        return mockResponse({ json: { id: "a1", app: {} } });
      }
      return mockResponse({ json: { admins: [] } });
    });
    const result = await intercomLadder(finding("Intercom", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // safe ok + gated blocked
    const contacts = result.rungs.find((r) => r.name === "intercom.list-contacts");
    expect(contacts?.tier).toBe(ProbeTier.GATED);
    expect(contacts?.blocked).toBe(true);
    expect(contacts?.success).toBe(false);
    expect(contactsCalled).toBe(false); // hard guarantee: no PII request issued
  });

  it("the @gated contacts probe refuses without consent and makes no call", async () => {
    let called = false;
    const { fetchImpl } = mockFetch(() => {
      called = true;
      return mockResponse({ json: { data: [] } });
    });
    await expect(intercomListContacts(SAFE_CONSENT, KEY, fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    expect(called).toBe(false);
  });

  it("full consent reaches the gated contacts read -> PROVEN, PII summarised", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/contacts")) {
        return mockResponse({
          json: {
            total_count: 4200,
            data: [
              { name: "Jane Buyer", email: "jane@victim.example", phone: "+15551234567", location: { city: "NYC" } },
            ],
          },
        });
      }
      if (call.url.endsWith("/me")) {
        return mockResponse({ json: { id: "a1", app: { name: "Acme" } } });
      }
      return mockResponse({ json: { admins: [] } });
    });
    const result = await intercomLadder(finding("Intercom", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.PROVEN);
    const contacts = result.rungs.find((r) => r.name === "intercom.list-contacts");
    expect(contacts?.success).toBe(true);
    expect(contacts?.blocked).toBe(false);
    expect(contacts?.evidence["total_count"]).toBe(4200);
    expect(contacts?.evidence["sample_count"]).toBe(1);
    expect(contacts?.evidence["pii_fields_present"]).toEqual(["email", "location", "name", "phone"]);
    // Raw PII values are never dumped into evidence.
    expect("email" in (contacts?.evidence ?? {})).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/me")) {
        return mockResponse({ json: { id: "a1", app: {} } });
      }
      if (call.url.includes("/contacts")) {
        return mockResponse({ json: { data: [], total_count: 0 } });
      }
      return mockResponse({ json: { admins: [] } });
    });
    const result = await intercomLadder(finding("Intercom", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Intercom (case-insensitive)", () => {
    expect(getLadder("Intercom")).toBeTypeOf("function");
    expect(getLadder("intercom")).toBeTypeOf("function");
  });
  it("tags the gated contacts read GATED", () => {
    expect(intercomListContacts.vtxTier).toBe(ProbeTier.GATED);
  });
});
