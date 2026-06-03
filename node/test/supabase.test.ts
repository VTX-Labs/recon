/**
 * Tests for the Supabase capability ladder.
 *
 * Supabase is FULLY MANUAL: every impact endpoint lives on the project's own
 * `{ref}.supabase.co` subdomain, which is not in the raw JWT, so NO live call is
 * ever made.
 *
 * * laddering without scope rejects with ScopeRequired;
 * * the SAFE OpenAPI rung renders a manual safe-curl (secret kept as $KEY);
 * * the two GATED rungs (list-table-rows, list-auth-users) are blocked without
 *   consent and stay MANUAL with full consent — verdict is DENIED throughout;
 * * no network call is ever made.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import {
  supabaseLadder,
  supabaseListAuthUsers,
  supabaseListTableRows,
} from "../src/providers/supabase.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import "../src/providers/index.js";

const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

// Realistic three-segment service_role JWT. Padding is random, NOT real.
const KEY =
  "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJ" + "yb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ." +
  "EXAMPLEFAKEKEYNOTREAL000000000000000000000000000";

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      supabaseLadder(finding("Supabase", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Supabase (fully manual)", () => {
  it("renders a SAFE manual rung + two blocked GATED rungs; verdict DENIED", async () => {
    const result = await supabaseLadder(finding("Supabase", KEY), SAFE_CONSENT);
    expect(result.provider).toBe("supabase");
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "rest-root-openapi",
      "list-table-rows",
      "list-auth-users",
    ]);

    const openapi = result.rungs.find((r) => r.name === "rest-root-openapi");
    expect(openapi?.tier).toBe(ProbeTier.SAFE);
    expect(openapi?.success).toBe(false);
    expect(openapi?.evidence["manual"]).toBe(true);
    expect(openapi?.evidence["safe_curl"]).toContain("$KEY");
    expect(openapi?.evidence["safe_curl"]).not.toContain(KEY);

    for (const name of ["list-table-rows", "list-auth-users"]) {
      const rung = result.rungs.find((r) => r.name === name);
      expect(rung?.tier).toBe(ProbeTier.GATED);
      expect(rung?.blocked).toBe(true);
      expect(rung?.success).toBe(false);
      expect(rung?.evidence["safe_curl"]).toContain("$KEY");
    }
  });

  it("the @gated PII probes refuse without consent", async () => {
    await expect(supabaseListTableRows(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
    await expect(supabaseListAuthUsers(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rungs stay MANUAL (not blocked, still DENIED)", async () => {
    const result = await supabaseLadder(finding("Supabase", KEY), FULL_CONSENT);
    expect(result.verdict).toBe(Verdict.DENIED);
    for (const name of ["list-table-rows", "list-auth-users"]) {
      const rung = result.rungs.find((r) => r.name === name);
      expect(rung?.blocked).toBe(false);
      expect(rung?.evidence["manual"]).toBe(true);
    }
  });
});

describe("secret redaction", () => {
  it("never serialises the raw key in toPublic()", async () => {
    const result = await supabaseLadder(finding("Supabase", KEY), FULL_CONSENT);
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers Supabase (case-insensitive)", () => {
    expect(getLadder("Supabase")).toBeTypeOf("function");
    expect(getLadder("supabase")).toBeTypeOf("function");
  });
  it("tags the gated rungs GATED", () => {
    expect(supabaseListTableRows.vtxTier).toBe(ProbeTier.GATED);
    expect(supabaseListAuthUsers.vtxTier).toBe(ProbeTier.GATED);
  });
});
