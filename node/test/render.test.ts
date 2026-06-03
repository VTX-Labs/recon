/**
 * Tests for the Render capability ladder. All HTTP is MOCKED via an injected
 * fetch — these tests NEVER touch a real API.
 *
 * * a valid key climbs two SAFE rungs (list-owners -> list-services) to VALID
 *   using `Authorization: Bearer {key}`;
 * * a dead key (401) yields DENIED and stops after list-owners;
 * * the GATED read-env-vars rung is MANUAL: blocked without consent, and with
 *   full consent it never fires — it renders a safe curl keeping $KEY.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { renderLadder, renderGatedReadEnvVars } from "../src/providers/render.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic Render key shape: rnd_ + random string. NOT a real credential.
const KEY = "rnd" + "_EXAMPLEFAKEKEYNOTREAL000000000000000";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      renderLadder(finding("Render", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Render", () => {
  it("valid key climbs the SAFE rungs (list-owners -> list-services)", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v1/owners")) {
        return mockResponse({
          json: [{ owner: { id: "own-1", name: "Acme Workspace", email: "owner@victim.example", type: "team" } }],
        });
      }
      if (call.url.endsWith("/v1/services")) {
        return mockResponse({
          json: [
            { service: { id: "srv-1", name: "api", type: "web_service" } },
            { service: { id: "srv-2", name: "worker", type: "background_worker" } },
          ],
        });
      }
      return mockResponse({ status: 404 });
    });
    const result = await renderLadder(finding("Render", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.provider).toBe("render");
    expect(result.verdict).toBe(Verdict.VALID);

    const owners = result.rungs.find((r) => r.name === "list-owners");
    expect(owners?.tier).toBe(ProbeTier.SAFE);
    expect(owners?.success).toBe(true);
    expect(owners?.evidence["owner_count"]).toBe(1);
    expect(owners?.evidence["owner_names"]).toEqual(["Acme Workspace"]);

    const services = result.rungs.find((r) => r.name === "list-services");
    expect(services?.evidence["service_count"]).toBe(2);
    expect(services?.evidence["service_types"]).toEqual(["background_worker", "web_service"]);

    const ownersCall = calls.find((c) => c.url.endsWith("/v1/owners"));
    expect(ownersCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
  });

  it("dead key (401) is DENIED and stops after list-owners", async () => {
    let servicesCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/services")) {
        servicesCalled = true;
        return mockResponse({ json: [] });
      }
      return mockResponse({ status: 401, json: { message: "unauthorized" } });
    });
    const result = await renderLadder(finding("Render", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["list-owners"]);
    expect(servicesCalled).toBe(false);
  });

  it("GATED read-env-vars is blocked without consent and fires no call", async () => {
    let envCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/env-vars")) {
        envCalled = true;
        return mockResponse({ json: [{ key: "DATABASE_URL", value: "leak" }] });
      }
      if (call.url.endsWith("/v1/owners")) {
        return mockResponse({ json: [{ owner: { id: "o1", name: "W" } }] });
      }
      return mockResponse({ json: [] });
    });
    const result = await renderLadder(finding("Render", KEY), SAFE_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const env = result.rungs.find((r) => r.name === "read-env-vars");
    expect(env?.tier).toBe(ProbeTier.GATED);
    expect(env?.blocked).toBe(true);
    expect(env?.success).toBe(false);
    expect(env?.evidence["safe_curl"]).toContain("$KEY");
    expect(envCalled).toBe(false);
  });

  it("the @gated env-vars probe refuses without consent", async () => {
    await expect(renderGatedReadEnvVars(SAFE_CONSENT, KEY)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire)", async () => {
    let envCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes("/env-vars")) {
        envCalled = true;
        return mockResponse({ json: [] });
      }
      if (call.url.endsWith("/v1/owners")) {
        return mockResponse({ json: [{ owner: { id: "o1", name: "W" } }] });
      }
      return mockResponse({ json: [] });
    });
    const result = await renderLadder(finding("Render", KEY), FULL_CONSENT, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    const env = result.rungs.find((r) => r.name === "read-env-vars");
    expect(env?.blocked).toBe(false);
    expect(env?.evidence["manual"]).toBe(true);
    expect(envCalled).toBe(false);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/v1/owners")) {
        return mockResponse({ json: [{ owner: { id: "o1", name: "W" } }] });
      }
      return mockResponse({ json: [] });
    });
    const result = await renderLadder(finding("Render", KEY), FULL_CONSENT, { fetchImpl });
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Render (case-insensitive)", () => {
    expect(getLadder("Render")).toBeTypeOf("function");
    expect(getLadder("render")).toBeTypeOf("function");
  });
  it("tags the gated env-vars read GATED", () => {
    expect(renderGatedReadEnvVars.vtxTier).toBe(ProbeTier.GATED);
  });
});
