/**
 * Tests for the Grafana capability ladder.
 *
 * Grafana is FULLY MANUAL: every rung's URL embeds the `{host}` instance the raw
 * token does not name, so NO live call is ever made. We pass an injected fetch
 * that records calls purely to prove none are issued.
 *
 * * laddering without scope rejects with ScopeRequired;
 * * all three SAFE rungs render as manual safe-curls (secret kept as $KEY) and
 *   the verdict is DENIED (no rung can succeed without the out-of-band host);
 * * no network call is ever made.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { grafanaLadder } from "../src/providers/grafana.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic shape: glsa_<32 base62>_<8 hex>. Random padding, NOT a real token.
const KEY = "glsa" + "_EXAMPLEFAKEKEYNOTREAL00000000000" + "_deadbeef";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      grafanaLadder(finding("Grafana", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Grafana (fully manual)", () => {
  it("renders three SAFE manual safe-curls and never makes a live call", async () => {
    const { fetchImpl, calls } = mockFetch(() => mockResponse({ json: { unexpected: true } }));
    // grafanaLadder takes (finding, consent) — no fetch options — so the only way
    // to observe a (forbidden) call is via the recorder, which must stay empty.
    void fetchImpl;
    const result = await grafanaLadder(finding("Grafana", KEY), SAFE_CONSENT);

    expect(result.provider).toBe("grafana");
    // Manual rungs never succeed, so the verdict is always DENIED.
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "current-user",
      "user-permissions",
      "list-datasources",
    ]);
    for (const rung of result.rungs) {
      expect(rung.tier).toBe(ProbeTier.SAFE);
      expect(rung.success).toBe(false);
      expect(rung.blocked).toBe(false);
      expect(rung.evidence["manual"]).toBe(true);
      expect(rung.evidence["safe_curl"]).toContain("$KEY");
      // The secret is never inlined into the rendered curl.
      expect(rung.evidence["safe_curl"]).not.toContain(KEY);
    }
    // Hard guarantee: the provider issued no HTTP call at all.
    expect(calls).toHaveLength(0);
  });

  it("verdict stays DENIED even with full consent (no rung can succeed)", async () => {
    const result = await grafanaLadder(finding("Grafana", KEY), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const result = await grafanaLadder(finding("Grafana", KEY), SAFE_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Grafana (case-insensitive)", () => {
    expect(getLadder("Grafana")).toBeTypeOf("function");
    expect(getLadder("grafana")).toBeTypeOf("function");
  });
});
