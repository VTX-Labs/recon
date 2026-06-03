/**
 * Tests for the Google AI / Gemini capability ladder. ALL HTTP is mocked via an
 * injected fetch — no real Google API is ever contacted, and no real key is
 * used.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { getLadder } from "../src/providers/registry.js";
import {
  GATED_RUNGS,
  gatedGenerateContent,
  googleLadder,
} from "../src/providers/google.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { failingFetch, mockFetch, mockResponse } from "./helpers.js";
// Importing the providers index wires the registry (register side-effects).
import "../src/providers/index.js";

const GLA = "https://generativelanguage.googleapis.com/v1beta";
const FAKE_KEY = "AIza" + "FAKE0000000000000000000000000000000";
const SCOPE = "h1:example-program";

const finding = () => new Finding({ detectorName: "GoogleAI", verified: true, raw: FAKE_KEY });
const consentSafe = () => new Consent({ prove: false, authorizedScope: SCOPE });
const consentFull = () => new Consent({ prove: true, authorizedScope: SCOPE });

describe("registry wiring", () => {
  it("registers the ladder for the google detectors", () => {
    for (const detector of ["GoogleAI", "google", "Gemini", "GCP"]) {
      expect(getLadder(detector)).toBeTypeOf("function");
    }
  });
});

describe("valid key", () => {
  it("climbs all four safe rungs to VALID", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.startsWith(`${GLA}/models`)) {
        return mockResponse({ json: { models: [{ name: "models/x" }] } });
      }
      if (call.url.startsWith(`${GLA}/files`)) return mockResponse({ json: { files: [] } });
      if (call.url.startsWith(`${GLA}/cachedContents`)) {
        return mockResponse({ json: { cachedContents: [] } });
      }
      if (call.url.startsWith(`${GLA}/corpora`)) {
        return mockResponse({ json: { corpora: [{ name: "corpora/a" }] } });
      }
      return mockResponse({ status: 404 });
    });

    const result = await googleLadder(finding(), consentSafe(), { fetchImpl });

    expect(result.provider).toBe("google");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.authorizedScope).toBe(SCOPE);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "ListModels",
      "ListFiles",
      "ListCachedContents",
      "ListCorpora",
    ]);
    expect(result.rungs.every((r) => r.tier === ProbeTier.SAFE)).toBe(true);
    expect(result.rungs.every((r) => r.success)).toBe(true);
    // The x-goog-api-key header carried the raw key on the first call.
    expect(calls[0]?.headers["x-goog-api-key"]).toBe(FAKE_KEY);
    expect(result.rungs[0]?.evidence["item_count"]).toBe(1);
  });

  it("redacts the secret on serialisation", async () => {
    const { fetchImpl } = mockFetch(() => mockResponse({ json: { models: [] } }));
    const result = await googleLadder(finding(), consentSafe(), { fetchImpl });
    const blob = JSON.stringify(result.toPublic());
    expect(blob).not.toContain(FAKE_KEY);
    expect(result.toPublic().finding.redacted.startsWith("AIza")).toBe(true);
    expect(result.toPublic().finding.redacted).not.toBe(FAKE_KEY);
  });
});

describe("dead key", () => {
  it("is DENIED when every rung is rejected", async () => {
    const { fetchImpl } = mockFetch(() =>
      mockResponse({ status: 400, json: { error: { code: 400, message: "API key not valid" } } }),
    );
    const result = await googleLadder(finding(), consentSafe(), { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.every((r) => !r.success)).toBe(true);
    expect(result.rungs.map((r) => r.name)).not.toContain("RefererBypass");
  });

  it("does not throw on a network error and is DENIED", async () => {
    const { fetchImpl } = failingFetch("boom");
    const result = await googleLadder(finding(), consentSafe(), { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.every((r) => !r.success)).toBe(true);
  });
});

describe("referer-restricted bypass", () => {
  it("re-GETs with a forged Referer and succeeds (still read-only)", async () => {
    let modelsHits = 0;
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.startsWith(`${GLA}/models`)) {
        modelsHits += 1;
        if (modelsHits === 1) {
          return mockResponse({
            status: 403,
            json: { error: { status: "PERMISSION_DENIED", message: "API_KEY_HTTP_REFERRER_BLOCKED" } },
          });
        }
        return mockResponse({ json: { models: [{ name: "models/x" }] } });
      }
      return mockResponse({ status: 403, json: {} });
    });

    const result = await googleLadder(finding(), consentSafe(), { fetchImpl });
    const names = result.rungs.map((r) => r.name);
    expect(names).toContain("RefererBypass");
    const bypass = result.rungs.find((r) => r.name === "RefererBypass");
    expect(bypass?.tier).toBe(ProbeTier.SAFE);
    expect(bypass?.success).toBe(true);
    expect(calls[calls.length - 1]?.headers["referer"]).toBeDefined();
    expect(result.verdict).toBe(Verdict.VALID);
  });
});

describe("gated rungs", () => {
  it("are tagged GATED", () => {
    for (const probe of GATED_RUNGS) {
      expect(probe.vtxTier).toBe(ProbeTier.GATED);
    }
  });

  it("are blocked without consent and issue NO billable call", async () => {
    const { fetchImpl, calls } = mockFetch(() => mockResponse({ json: {} }));
    await expect(gatedGenerateContent(consentSafe(), FAKE_KEY, fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    await expect(gatedGenerateContent(Consent.denied(), FAKE_KEY, fetchImpl)).rejects.toBeInstanceOf(
      GatedProbeBlocked,
    );
    expect(calls).toHaveLength(0); // structural: no network call ever issued
  });

  it("run with full consent", async () => {
    const { fetchImpl, calls } = mockFetch(() =>
      mockResponse({ json: { candidates: [{ content: {} }] } }),
    );
    const rung = await gatedGenerateContent(consentFull(), FAKE_KEY, fetchImpl);
    expect(calls).toHaveLength(1);
    expect(rung.tier).toBe(ProbeTier.GATED);
    expect(rung.success).toBe(true);
  });

  it("are never reached by the safe ladder, even with full consent", async () => {
    let gatedHits = 0;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.includes(":generateContent") || call.url.includes("/upload/") || call.url.includes("identitytoolkit")) {
        gatedHits += 1;
      }
      return mockResponse({ json: { models: [] } });
    });
    const result = await googleLadder(finding(), consentFull(), { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.every((r) => r.tier === ProbeTier.SAFE)).toBe(true);
    expect(gatedHits).toBe(0);
  });
});

describe("scope gate", () => {
  it("refuses to ladder without an authorized scope (even with --prove)", async () => {
    await expect(
      googleLadder(finding(), new Consent({ prove: true, authorizedScope: null })),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});
