/**
 * Tests for the DigitalOcean capability ladder. All HTTP is MOCKED via an
 * injected fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (account -> list-droplets) to VALID;
 * * a dead token (401) yields DENIED and stops after account;
 * * the GATED create-droplet rung is MANUAL: blocked without consent, and even
 *   with full consent it never fires a billable POST — it renders a safe curl.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { digitaloceanLadder, doCreateDropletGated } from "../src/providers/digitalocean.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic shape: dop_v1_ + 64 hex. Random padding, NOT a real credential.
const KEY = "dop" + "_v1_" + "deadbeef".repeat(8);

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      digitaloceanLadder(finding("DigitalOceanV2", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("DigitalOcean", () => {
  it("valid token climbs the SAFE rungs (account -> list-droplets)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v2/account")) {
        return mockResponse({
          json: { account: { email: "owner@victim.example", uuid: "uuid-1", status: "active", droplet_limit: 25 } },
        });
      }
      if (call.url.endsWith("/v2/droplets")) {
        return mockResponse({
          json: { droplets: [{ name: "web-1", region: { slug: "nyc3" } }, { name: "db-1", region: { slug: "sfo3" } }] },
        });
      }
      return mockResponse({ status: 404 });
    });
    const result = await digitaloceanLadder(finding("DigitalOceanV2", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("digitalocean");
    expect(result.verdict).toBe(Verdict.VALID);

    const account = result.rungs.find((r) => r.name === "account");
    expect(account?.tier).toBe(ProbeTier.SAFE);
    expect(account?.success).toBe(true);
    expect(account?.evidence["email"]).toBe("owner@victim.example");
    expect(account?.evidence["uuid"]).toBe("uuid-1");

    const droplets = result.rungs.find((r) => r.name === "list-droplets");
    expect(droplets?.evidence["droplet_count"]).toBe(2);
    expect(droplets?.evidence["regions"]).toEqual(["nyc3", "sfo3"]);

    const accountCall = calls.find((c) => c.url.endsWith("/v2/account"));
    expect(accountCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
  });

  it("dead token (401) is DENIED and stops after account", async () => {
    let dropletsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v2/droplets")) {
        dropletsCalled = true;
        return mockResponse({ json: { droplets: [] } });
      }
      return mockResponse({ status: 401, json: { id: "unauthorized", message: "Unable to authenticate you" } });
    });
    const result = await digitaloceanLadder(finding("DigitalOceanV2", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["account"]);
    expect(dropletsCalled).toBe(false);
  });

  it("GATED create-droplet is blocked without consent and fires no POST", async () => {
    let createCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.method === "POST") {
        createCalled = true;
        return mockResponse({ status: 202, json: { droplet: { id: 999 } } });
      }
      if (call.url.endsWith("/v2/account")) {
        return mockResponse({ json: { account: { email: "o@v.example", status: "active" } } });
      }
      return mockResponse({ json: { droplets: [] } });
    });
    const result = await digitaloceanLadder(finding("DigitalOceanV2", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const create = result.rungs.find((r) => r.name === "create-droplet");
    expect(create?.tier).toBe(ProbeTier.GATED);
    expect(create?.blocked).toBe(true);
    expect(create?.success).toBe(false);
    expect(createCalled).toBe(false);
  });

  it("the @gated creation refuses without consent (no POST)", async () => {
    await expect(doCreateDropletGated(SAFE_CONSENT, KEY)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    let createCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.method === "POST") {
        createCalled = true;
        return mockResponse({ status: 202, json: { droplet: { id: 999 } } });
      }
      if (call.url.endsWith("/v2/account")) {
        return mockResponse({ json: { account: { email: "o@v.example", status: "active" } } });
      }
      return mockResponse({ json: { droplets: [] } });
    });
    const result = await digitaloceanLadder(finding("DigitalOceanV2", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID); // manual rung never succeeds -> not PROVEN
    const create = result.rungs.find((r) => r.name === "create-droplet");
    expect(create?.blocked).toBe(false);
    expect(create?.evidence["manual"]).toBe(true);
    expect(createCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v2/account")) {
        return mockResponse({ json: { account: { email: "o@v.example", status: "active" } } });
      }
      return mockResponse({ json: { droplets: [] } });
    });
    const result = await digitaloceanLadder(finding("DigitalOceanV2", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers DigitalOcean detectors (case-insensitive)", () => {
    expect(getLadder("DigitalOceanV2")).toBeTypeOf("function");
    expect(getLadder("DigitalOceanToken")).toBeTypeOf("function");
    expect(getLadder("digitaloceanv2")).toBeTypeOf("function");
  });
  it("tags the gated creation GATED", () => {
    expect(doCreateDropletGated.vtxTier).toBe(ProbeTier.GATED);
  });
});
