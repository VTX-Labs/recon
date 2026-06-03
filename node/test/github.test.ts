/**
 * Tests for the GitHub capability ladder. HTTP is fully MOCKED via an injected
 * fetch (no network, no real GitHub).
 *
 *   * a valid classic token climbs the safe rungs to VALID;
 *   * a dead token is DENIED and stops after identity;
 *   * a fine-grained token is detected behaviourally (no X-OAuth-Scopes);
 *   * the GATED rung is BLOCKED without consent and stays read-only;
 *   * with full consent the GATED rung runs and the verdict becomes PROVEN;
 *   * the ladder refuses to run with no authorized scope (ScopeRequired);
 *   * no raw secret leaks into the serialised evidence.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import { getLadder } from "../src/providers/registry.js";
import { DETECTORS, githubLadder } from "../src/providers/github.js";
import { Consent, ProbeTier, ScopeRequired } from "../src/safety.js";
import { mockFetch, mockResponse, type RecordedCall } from "./helpers.js";
import "../src/providers/index.js";

const VALID_TOKEN = "ghp" + "_" + "A".repeat(36);
const FINEGRAINED_TOKEN = "github_pat" + "_" + "B".repeat(22) + "_" + "C".repeat(30);
const DEAD_TOKEN = "ghp" + "_" + "DEAD".repeat(9);

const AUTHORIZED = new Consent({ prove: false, authorizedScope: "h1:example-program" });
const CONSENTED = new Consent({ prove: true, authorizedScope: "h1:example-program" });

const path = (url: string) => new URL(url).pathname;

function classicHandler(call: RecordedCall): Response {
  expect(call.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
  switch (path(call.url)) {
    case "/user":
      return mockResponse({
        json: { login: "octocat", id: 583231 },
        headers: { "X-OAuth-Scopes": "repo, read:org, admin:org, gist" },
      });
    case "/user/repos":
      return mockResponse({
        json: [
          { full_name: "octocat/secret-api", private: true },
          { full_name: "acme/internal-infra", private: true },
        ],
      });
    case "/user/orgs":
      return mockResponse({ json: [{ login: "acme" }, { login: "octo-org" }] });
    default:
      return mockResponse({ status: 404, json: { message: "unexpected" } });
  }
}

describe("registry wiring", () => {
  it("registers the ladder for all detector names (case-insensitive)", () => {
    for (const name of DETECTORS) expect(getLadder(name)).toBeTypeOf("function");
    expect(getLadder("github")).toBeTypeOf("function");
  });
});

describe("valid classic token", () => {
  it("climbs the safe rungs to VALID", async () => {
    const { fetchImpl } = mockFetch(classicHandler);
    const finding = new Finding({ detectorName: "Github", verified: true, raw: VALID_TOKEN });
    const result = await githubLadder(finding, AUTHORIZED, { fetchImpl });

    expect(result.provider).toBe("github");
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.authorizedScope).toBe("h1:example-program");

    const rungs = Object.fromEntries(result.rungs.map((r) => [r.name, r]));
    expect(rungs["identity"]?.success).toBe(true);
    expect(rungs["identity"]?.evidence["login"]).toBe("octocat");
    expect(rungs["classic_scopes"]?.evidence["token_type"]).toBe("classic");
    expect(rungs["classic_scopes"]?.evidence["scopes"]).toEqual(
      expect.arrayContaining(["repo", "admin:org"]),
    );
    expect(rungs["dangerous_scopes"]?.evidence["dangerous"]).toEqual(
      expect.arrayContaining(["repo", "admin:org"]),
    );
    expect(rungs["private_repos"]?.evidence["private_repo_count"]).toBe(2);
    expect(rungs["org_membership"]?.evidence["orgs"]).toEqual(["acme", "octo-org"]);

    // The gated rung is present but BLOCKED (no consent) and did not run.
    expect(rungs["gated_write_probe"]?.tier).toBe(ProbeTier.GATED);
    expect(rungs["gated_write_probe"]?.blocked).toBe(true);
    expect(rungs["gated_write_probe"]?.success).toBe(false);
  });
});

describe("fine-grained token", () => {
  it("is detected behaviourally (no X-OAuth-Scopes header)", async () => {
    const { fetchImpl } = mockFetch((call) => {
      switch (path(call.url)) {
        case "/user":
          return mockResponse({ json: { login: "fg-bot", id: 999 } }); // no scope header
        case "/user/repos":
          return mockResponse({ json: [{ full_name: "fg-bot/private-one", private: true }] });
        case "/user/orgs":
          return mockResponse({ json: [] });
        default:
          return mockResponse({ status: 404 });
      }
    });
    const finding = new Finding({ detectorName: "Github", verified: true, raw: FINEGRAINED_TOKEN });
    const result = await githubLadder(finding, AUTHORIZED, { fetchImpl });

    expect(result.verdict).toBe(Verdict.VALID);
    const rungs = Object.fromEntries(result.rungs.map((r) => [r.name, r]));
    expect(rungs["classic_scopes"]?.evidence["token_type"]).toBe("fine-grained");
    expect(rungs["dangerous_scopes"]?.success).toBe(false);
    expect(rungs["dangerous_scopes"]?.evidence["dangerous"]).toEqual([]);
    expect(rungs["private_repos"]?.evidence["private_repo_count"]).toBe(1);
  });
});

describe("dead token", () => {
  it("is DENIED and stops after identity", async () => {
    const { fetchImpl } = mockFetch(() =>
      mockResponse({ status: 401, json: { message: "Bad credentials" } }),
    );
    const finding = new Finding({ detectorName: "Github", verified: false, raw: DEAD_TOKEN });
    const result = await githubLadder(finding, AUTHORIZED, { fetchImpl });

    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs.map((r) => r.name)).toEqual(["identity"]);
    expect(result.rungs[0]?.success).toBe(false);
    expect(result.rungs[0]?.evidence["status"]).toBe(401);
  });
});

describe("gated rung", () => {
  it("is blocked without consent and makes no PUT", async () => {
    const seenMethods: string[] = [];
    const { fetchImpl } = mockFetch((call) => {
      seenMethods.push(call.method);
      return classicHandler(call);
    });
    const finding = new Finding({ detectorName: "Github", verified: true, raw: VALID_TOKEN });
    const result = await githubLadder(finding, AUTHORIZED, { fetchImpl });

    const gated = result.rungs.find((r) => r.name === "gated_write_probe");
    expect(gated?.blocked).toBe(true);
    expect(gated?.success).toBe(false);
    expect(String(gated?.evidence["reason"]).toLowerCase()).toContain("prove");
    expect(seenMethods).not.toContain("PUT");
    expect(new Set(seenMethods)).toEqual(new Set(["GET"]));
    expect(result.verdict).toBe(Verdict.VALID);
  });

  it("runs with full consent -> PROVEN", async () => {
    const seen: Array<[string, string]> = [];
    const { fetchImpl } = mockFetch((call) => {
      seen.push([call.method, path(call.url)]);
      if (call.method === "PUT" && path(call.url).startsWith("/user/starred/")) {
        return mockResponse({ status: 204 });
      }
      return classicHandler(call);
    });
    const finding = new Finding({ detectorName: "Github", verified: true, raw: VALID_TOKEN });
    const result = await githubLadder(finding, CONSENTED, { fetchImpl });

    const gated = result.rungs.find((r) => r.name === "gated_write_probe");
    expect(gated?.blocked).toBe(false);
    expect(gated?.success).toBe(true);
    expect(result.verdict).toBe(Verdict.PROVEN);
    expect(seen.some(([method]) => method === "PUT")).toBe(true);
  });
});

describe("scope gate + redaction", () => {
  it("refuses to run with no authorized scope", async () => {
    const { fetchImpl } = mockFetch(classicHandler);
    const finding = new Finding({ detectorName: "Github", verified: true, raw: VALID_TOKEN });
    await expect(githubLadder(finding, Consent.denied(), { fetchImpl })).rejects.toBeInstanceOf(
      ScopeRequired,
    );
  });

  it("never serialises the raw token", async () => {
    const { fetchImpl } = mockFetch(classicHandler);
    const finding = new Finding({ detectorName: "Github", verified: true, raw: VALID_TOKEN });
    const result = await githubLadder(finding, AUTHORIZED, { fetchImpl });
    const blob = JSON.stringify(result.toPublic());
    expect(blob).not.toContain(VALID_TOKEN);
    expect(result.finding.toPublic().redacted.startsWith("ghp_")).toBe(true);
  });
});
