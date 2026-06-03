/**
 * Tests for the HCP Terraform / Terraform Cloud capability ladder. All HTTP is
 * MOCKED via an injected fetch — these tests NEVER touch a real API.
 *
 * * a valid token climbs two SAFE rungs (account-details -> list-organizations)
 *   to VALID, parsing the JSON:API shape; the GATED create-run is a blocked
 *   manual note;
 * * a dead token (401) yields DENIED and stops after account-details;
 * * the GATED create-run fires NO network call without consent and stays a manual
 *   safe-curl ($KEY) with full consent;
 * * the raw token never appears in the public view.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { terraformcloudCreateRun, terraformcloudLadder } from "../src/providers/terraform-cloud.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const KEY = "EXAMPLEFAKEKEY" + ".atlasv1." + "EXAMPLEFAKEKEYNOTREAL00000000000000000000000000000000000000000";
const SAFE_CONSENT = new Consent({ prove: false, authorizedScope: "acme h1 program #4242" });
const FULL_CONSENT = new Consent({ prove: true, authorizedScope: "acme h1 program #4242" });

const finding = (detector: string, raw: string) =>
  new Finding({ detectorName: detector, verified: true, raw });

describe("scope precondition", () => {
  it("refuses to ladder without an authorized scope", async () => {
    await expect(
      terraformcloudLadder(finding("TerraformCloudPersonalToken", KEY), Consent.denied()),
    ).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("Terraform Cloud", () => {
  it("valid token climbs the SAFE rungs with real JSON:API evidence", async () => {
    const { fetchImpl, calls } = mockFetch((call) => {
      if (call.url.endsWith("/account/details")) {
        return mockResponse({
          json: {
            data: {
              id: "user-123",
              type: "users",
              attributes: { username: "victim", email: "victim@example.com" },
            },
          },
        });
      }
      if (call.url.endsWith("/organizations")) {
        return mockResponse({
          json: { data: [{ id: "acme-corp", type: "organizations" }, { id: "side-org" }] },
        });
      }
      return mockResponse({ status: 404 });
    });

    const result = await terraformcloudLadder(
      finding("TerraformCloudPersonalToken", KEY),
      SAFE_CONSENT,
      { fetchImpl },
    );

    expect(result.provider).toBe("terraform-cloud");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs.map((r) => r.name)).toEqual([
      "account-details",
      "list-organizations",
      "create-run",
    ]);
    const acct = result.rungs[0];
    expect(acct?.success).toBe(true);
    expect(acct?.evidence["id"]).toBe("user-123");
    expect(acct?.evidence["username"]).toBe("victim");
    const orgs = result.rungs[1];
    expect(orgs?.evidence["organization_count"]).toBe(2);
    expect(orgs?.evidence["organizations_sample"]).toEqual(["acme-corp", "side-org"]);
    const acctCall = calls.find((c) => c.url.endsWith("/account/details"));
    expect(acctCall?.headers["authorization"]).toBe(`Bearer ${KEY}`);
    // The gated create-run was blocked (no consent) — manual safe-curl.
    const run = result.rungs.find((r) => r.name === "create-run");
    expect(run?.tier).toBe(ProbeTier.GATED);
    expect(run?.blocked).toBe(true);
    expect(String(run?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("dead token is DENIED and stops after account-details", async () => {
    let orgsCalled = false;
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/organizations")) {
        orgsCalled = true;
        return mockResponse({ json: { data: [] } });
      }
      return mockResponse({ status: 401, json: { errors: [{ status: "401" }] } });
    });
    const result = await terraformcloudLadder(
      finding("TerraformCloudPersonalToken", KEY),
      SAFE_CONSENT,
      { fetchImpl },
    );
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["account-details"]);
    expect(orgsCalled).toBe(false);
  });

  it("the @gated create-run probe refuses without consent", async () => {
    await expect(terraformcloudCreateRun(SAFE_CONSENT)).rejects.toBeInstanceOf(GatedProbeBlocked);
  });

  it("with full consent the GATED rung stays MANUAL (no auto-fire, no PROVEN)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/account/details")) {
        return mockResponse({ json: { data: { id: "u", attributes: { username: "v" } } } });
      }
      if (call.url.endsWith("/runs")) {
        throw new Error("gated create-run must never auto-fire");
      }
      return mockResponse({ json: { data: [{ id: "acme-corp" }] } });
    });
    const result = await terraformcloudLadder(
      finding("TerraformCloudPersonalToken", KEY),
      FULL_CONSENT,
      { fetchImpl },
    );
    expect(result.verdict).toBe(Verdict.VALID); // manual gated never PROVEN
    const run = result.rungs.find((r) => r.name === "create-run");
    expect(run?.blocked).toBe(false);
    expect(run?.success).toBe(false);
    expect(run?.evidence["manual"]).toBe(true);
    expect(String(run?.evidence["safe_curl"])).toContain("$KEY");
  });

  it("never leaks the raw token in the public view", async () => {
    const { fetchImpl } = mockFetch((call) => {
      if (call.url.endsWith("/account/details")) {
        return mockResponse({ json: { data: { id: "u", attributes: { username: "v" } } } });
      }
      return mockResponse({ json: { data: [{ id: "acme-corp" }] } });
    });
    const result = await terraformcloudLadder(
      finding("TerraformCloudPersonalToken", KEY),
      FULL_CONSENT,
      { fetchImpl },
    );
    expect(JSON.stringify(result.toPublic())).not.toContain(KEY);
  });
});

describe("registration", () => {
  it("registers TerraformCloudPersonalToken (case-insensitive)", () => {
    expect(getLadder("TerraformCloudPersonalToken")).toBeTypeOf("function");
    expect(getLadder("terraformcloudpersonaltoken")).toBeTypeOf("function");
  });
  it("tags the gated create-run probe GATED", () => {
    expect(terraformcloudCreateRun.vtxTier).toBe(ProbeTier.GATED);
  });
});
