/**
 * Tests for the generic declarative capability ladder. Every HTTP call is
 * served by an injected fetch stub — NO real API is ever contacted.
 *
 * Every shipped provider now has a dedicated ladder module, so BUILTIN_SPECS is
 * empty and the generic runner is a pure *runtime extensibility* layer. These
 * tests therefore register their own throwaway spec (`examplecorp`) and exercise
 * the runner against it:
 *
 *   * a valid key climbing its SAFE rungs                  -> VALID
 *   * a dead key (auth refused on every rung)              -> DENIED
 *   * a GATED rung blocked without consent (no network)    -> blocked rung
 *   * a GATED rung exercised WITH consent                  -> PROVEN
 *   * a MANUAL rung never calling the network              -> safe curl only
 *   * an unknown detector                                  -> N/A
 *   * scope is required to ladder at all
 *   * secrets are redacted; safe curl never leaks the key
 *   * a billable SAFE rung is rejected at spec-build time
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import {
  BUILTIN_SPECS,
  ProviderSpec,
  RungSpec,
  genericLadder,
  loadSpecs,
  registerSpec,
  specForDetector,
} from "../src/providers/generic.js";
import { clearRegistry, getLadder, register } from "../src/providers/registry.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse, type RecordedCall } from "./helpers.js";

const SCOPE = "h1-program: example (SOW-123)";
// A throwaway provider whose secret shape is `ec_<alphanum>`.
const FAKE_KEY = "ec_" + "A1b2C3d4E5f6G7h8I9j0";
const HOST = "api.example.test";

/**
 * A self-contained spec that exercises every runner path: a SAFE identity rung,
 * a GATED billable rung, and a MANUAL rung. Registered fresh for each test so
 * the generic ladder routes `ExampleCorpToken` here.
 */
function exampleSpec(): ProviderSpec {
  return new ProviderSpec({
    name: "examplecorp",
    detectors: ["ExampleCorpToken"],
    keyRegex: "^ec_[A-Za-z0-9]+",
    docs: "throwaway provider for generic-runner tests",
    rungs: [
      new RungSpec({
        name: "whoami",
        method: "GET",
        url: `https://${HOST}/v1/me`,
        tier: ProbeTier.SAFE,
        headers: { Authorization: "Bearer {key}" },
        successStatus: [200],
        detail: "identity probe (read-only)",
      }),
      new RungSpec({
        name: "charge",
        method: "POST",
        url: `https://${HOST}/v1/charge`,
        tier: ProbeTier.GATED,
        headers: { Authorization: "Bearer {key}", "Content-Type": "application/json" },
        billable: true,
        detail: "GATED: a billable charge.",
      }),
    ],
  });
}

beforeEach(() => {
  clearRegistry();
  const spec = registerSpec(exampleSpec());
  // Route the spec's detector to the generic ladder, mirroring how generic.ts
  // wires BUILTIN_SPECS detectors at import time.
  register([...spec.detectors], (finding, consent) => genericLadder(finding, consent));
});

afterEach(() => {
  clearRegistry();
});

const finding = (detector = "ExampleCorpToken", raw = FAKE_KEY) =>
  new Finding({ detectorName: detector, verified: true, raw });

const path = (url: string) => new URL(url).pathname;

describe("valid key", () => {
  it("climbs the SAFE rung to VALID (and never touches the gated endpoint)", async () => {
    const seen: RecordedCall[] = [];
    const { fetchImpl } = mockFetch((call) => {
      seen.push(call);
      expect(new URL(call.url).host).toBe(HOST);
      expect(path(call.url)).toBe("/v1/me");
      expect(call.headers["authorization"]).toBe(`Bearer ${FAKE_KEY}`);
      return mockResponse({ json: { id: "user_1" } });
    });

    const consent = new Consent({ authorizedScope: SCOPE }); // no --prove
    const result = await genericLadder(finding(), consent, { fetchImpl });

    expect(seen.map((c) => path(c.url))).toEqual(["/v1/me"]);
    expect(result.provider).toBe("examplecorp");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.authorizedScope).toBe(SCOPE);

    const safe = result.rungs.find((r) => r.name === "whoami");
    expect(safe?.success).toBe(true);
    expect(safe?.blocked).toBe(false);
    expect(safe?.tier).toBe(ProbeTier.SAFE);
  });
});

describe("dead key", () => {
  it("is DENIED", async () => {
    const { fetchImpl } = mockFetch(() => mockResponse({ status: 401, json: { error: "invalid" } }));
    const consent = new Consent({ authorizedScope: SCOPE });
    const result = await genericLadder(finding(), consent, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    const safe = result.rungs.find((r) => r.name === "whoami");
    expect(safe?.success).toBe(false);
    expect(safe?.evidence["status_code"]).toBe(401);
  });
});

describe("gated rung", () => {
  it("is blocked without consent and makes NO network call", async () => {
    let gatedHits = 0;
    const { fetchImpl } = mockFetch((call) => {
      if (path(call.url) === "/v1/charge") gatedHits += 1;
      return mockResponse({ json: { id: "user_1" } });
    });
    const consent = new Consent({ prove: false, authorizedScope: SCOPE });
    const result = await genericLadder(finding(), consent, { fetchImpl });

    expect(gatedHits).toBe(0);
    const gated = result.rungs.find((r) => r.name === "charge");
    expect(gated?.tier).toBe(ProbeTier.GATED);
    expect(gated?.blocked).toBe(true);
    expect(gated?.success).toBe(false);
    expect(String(gated?.evidence["safe_curl"])).toContain("$KEY");
    expect(String(gated?.evidence["safe_curl"])).not.toContain(FAKE_KEY);
    expect(result.verdict).toBe(Verdict.VALID);
  });

  it("--prove without scope cannot even start the ladder", async () => {
    const consent = new Consent({ prove: true, authorizedScope: null });
    await expect(genericLadder(finding(), consent)).rejects.toBeInstanceOf(ScopeRequired);
  });

  it("is exercised with full consent -> PROVEN", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (path(call.url) === "/v1/me") return mockResponse({ json: { id: "user_1" } });
      if (path(call.url) === "/v1/charge") {
        expect(call.method).toBe("POST");
        return mockResponse({ json: { charged: true } });
      }
      return mockResponse({ status: 404 });
    });
    const consent = new Consent({ prove: true, authorizedScope: SCOPE });
    const result = await genericLadder(finding(), consent, { fetchImpl });
    const gated = result.rungs.find((r) => r.name === "charge");
    expect(gated?.blocked).toBe(false);
    expect(gated?.success).toBe(true);
    expect(result.verdict).toBe(Verdict.PROVEN);
  });
});

describe("manual rung", () => {
  it("emits the safe curl without any network call", async () => {
    // Register a spec whose only rung is MANUAL.
    clearRegistry();
    const spec = registerSpec(
      new ProviderSpec({
        name: "manualcorp",
        detectors: ["ManualCorpToken"],
        keyRegex: "^mc_[A-Za-z0-9]+",
        rungs: [
          new RungSpec({
            name: "account-fetch",
            method: "GET",
            url: `https://${HOST}/v1/account/{key}`,
            tier: ProbeTier.SAFE,
            manual: true,
            detail: "MANUAL: needs a paired secret.",
          }),
        ],
      }),
    );
    register([...spec.detectors], (f, c) => genericLadder(f, c));

    let calls = 0;
    const { fetchImpl } = mockFetch(() => {
      calls += 1;
      return mockResponse({});
    });
    const raw = "mc_" + "0".repeat(20);
    const consent = new Consent({ authorizedScope: SCOPE });
    const result = await genericLadder(finding("ManualCorpToken", raw), consent, { fetchImpl });

    expect(calls).toBe(0);
    expect(result.provider).toBe("manualcorp");
    const manual = result.rungs[0];
    expect(manual?.evidence["manual"]).toBe(true);
    expect(manual?.detail).toContain("curl");
    expect(String(manual?.evidence["safe_curl"])).not.toContain(raw);
    expect(String(manual?.evidence["safe_curl"])).toContain("$KEY");
  });
});

describe("unknown detector", () => {
  it("is N/A with a helpful note, no exception", async () => {
    const consent = new Consent({ authorizedScope: SCOPE });
    const result = await genericLadder(finding("TotallyUnknownDetector", "whatever-value"), consent);
    expect(result.verdict).toBe(Verdict.NA);
    expect(result.provider).toBe("generic");
    expect(result.rungs[0]?.name).toBe("no-spec");
  });
});

describe("scope, redaction, transport", () => {
  it("requires a scope to ladder at all", async () => {
    await expect(genericLadder(finding(), new Consent())).rejects.toBeInstanceOf(ScopeRequired);
  });

  it("redacts the secret in stored evidence", async () => {
    const { fetchImpl } = mockFetch(() => mockResponse({ json: { id: "user_1" } }));
    const consent = new Consent({ authorizedScope: SCOPE });
    const result = await genericLadder(finding(), consent, { fetchImpl });
    const blob = JSON.stringify(result.toPublic());
    expect(blob).not.toContain(FAKE_KEY);
    const safe = result.rungs.find((r) => r.name === "whoami");
    expect(String(safe?.evidence["key"]).startsWith("ec_")).toBe(true);
    expect(String(safe?.evidence["key"])).toContain("*");
  });

  it("captures a transport error as a ProbeResult", async () => {
    const { fetchImpl } = mockFetch(() => {
      throw new TypeError("boom");
    });
    const consent = new Consent({ authorizedScope: SCOPE });
    const result = await genericLadder(finding(), consent, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    const safe = result.rungs.find((r) => r.name === "whoami");
    expect(safe?.success).toBe(false);
    expect(safe?.evidence["error"]).toBe("TypeError");
  });
});

describe("declarative spec layer", () => {
  it("ships no built-in specs (every provider is now a dedicated module)", () => {
    expect(BUILTIN_SPECS).toHaveLength(0);
  });

  it("routes a registered spec's detector to the generic ladder", () => {
    expect(getLadder("ExampleCorpToken")).toBeTypeOf("function");
  });

  it("falls back to key-shape matching", () => {
    const spec = specForDetector("MysteryDetector", FAKE_KEY);
    expect(spec?.name).toBe("examplecorp");
  });

  it("never lets the safe curl contain the raw key (but render does in memory)", () => {
    const rung = specForDetector("ExampleCorpToken")?.rungs.find((r) => r.name === "whoami");
    const curl = rung!.safeCurl();
    expect(curl).toContain("$KEY");
    expect(curl).not.toContain(FAKE_KEY);
    expect(rung!.renderHeaders(FAKE_KEY)["Authorization"]).toBe(`Bearer ${FAKE_KEY}`);
  });

  it("rejects a billable SAFE rung at build time", () => {
    expect(
      () =>
        new RungSpec({
          name: "oops",
          method: "POST",
          url: "https://example.test/charge",
          tier: ProbeTier.SAFE,
          billable: true,
        }),
    ).toThrow(/billable/);
  });

  it("loads structured specs and registers them, rejecting a billable SAFE rung", () => {
    const specs = loadSpecs([
      {
        name: "examplecorp2",
        detectors: ["ExampleCorp2Token"],
        key_regex: "^ec2_[A-Za-z0-9]+",
        docs: "demo",
        rungs: [
          {
            name: "whoami",
            method: "GET",
            url: "https://api.example.test/v1/me",
            tier: "safe",
            headers: { Authorization: "Bearer {key}" },
            success_status: [200],
            detail: "identity probe",
          },
          {
            name: "charge",
            method: "POST",
            url: "https://api.example.test/v1/charge",
            tier: "gated",
            billable: true,
            headers: { Authorization: "Bearer {key}" },
          },
        ],
      },
    ]);
    expect(specs).toHaveLength(1);
    expect(specs[0]?.rungs[0]?.tier).toBe(ProbeTier.SAFE);
    expect(specs[0]?.rungs[1]?.tier).toBe(ProbeTier.GATED);
    expect(specs[0]?.rungs[1]?.billable).toBe(true);
    expect(specForDetector("ExampleCorp2Token")).toBe(specs[0]);

    expect(() =>
      loadSpecs(
        [
          {
            name: "badcorp",
            detectors: ["BadCorp"],
            rungs: [
              { name: "charge", method: "POST", url: "https://api.bad.test/charge", tier: "safe", billable: true },
            ],
          },
        ],
        { register: false },
      ),
    ).toThrow(/billable/);
  });
});
