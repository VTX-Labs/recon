/** Integration: key detection + the orchestration layer that the CLI calls. */

import { describe, expect, it } from "vitest";
import { detectKey } from "../src/detect.js";
import { buildBundle, findingFromKey, ladderFinding } from "../src/pipeline.js";
import { Consent } from "../src/safety.js";
import { Verdict } from "../src/models.js";

describe("detectKey", () => {
  it("maps recognizable prefixes to detector names", () => {
    expect(detectKey("ghp_" + "a".repeat(36))?.detector).toBe("GitHub");
    expect(detectKey("github_pat_" + "x".repeat(20))?.detector).toBe("GitHub");
    expect(detectKey("AIza" + "b".repeat(35))?.detector).toBe("GoogleAI");
    expect(detectKey("AKIA" + "C".repeat(16))?.detector).toBe("AWS");
    expect(detectKey("xoxb-abc")?.detector).toBe("Slack");
    expect(detectKey("glpat-abc")?.detector).toBe("GitLab");
    expect(detectKey("sk_live_" + "d".repeat(20))?.detector).toBe("Stripe");
    expect(detectKey("sk-ant-xyz")?.detector).toBe("Anthropic");
  });

  it("returns null for unknown shapes and empty input", () => {
    expect(detectKey("not-a-known-key")).toBeNull();
    expect(detectKey("")).toBeNull();
  });

  it("prefers the more specific Anthropic prefix over OpenAI", () => {
    // sk-ant- matches Anthropic, not the broader OpenAI sk- rule.
    expect(detectKey("sk-ant-api03-abc")?.detector).toBe("Anthropic");
  });
});

describe("findingFromKey", () => {
  it("auto-detects the detector from the key shape", () => {
    expect(findingFromKey("AIza" + "z".repeat(35)).detectorName).toBe("GoogleAI");
  });
  it("honors an explicit detector override", () => {
    expect(findingFromKey("whatever", "Slack").detectorName).toBe("Slack");
  });
  it("falls back to 'generic' for an unknown shape", () => {
    expect(findingFromKey("mystery-token").detectorName).toBe("generic");
  });
});

describe("ladderFinding", () => {
  it("routes a known detector to its ladder (dead key → DENIED, mocked fetch)", async () => {
    const fetchImpl = async () =>
      new Response("", { status: 401, headers: { "content-type": "application/json" } });
    // googleLadder/githubLadder accept an options.fetchImpl, but ladderFinding
    // calls the registered ladder which uses global fetch; stub it.
    const realFetch = globalThis.fetch;
    globalThis.fetch = fetchImpl as unknown as typeof fetch;
    try {
      const finding = findingFromKey("ghp_" + "a".repeat(36));
      const result = await ladderFinding(finding, new Consent({ authorizedScope: "test" }));
      expect(result.provider).toBe("github");
      expect([Verdict.DENIED, Verdict.NA]).toContain(result.verdict);
      expect(result.rungs.length).toBeGreaterThan(0);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("returns N/A for a detector with no registered ladder", async () => {
    const finding = findingFromKey("mystery-token", "TotallyUnknownProvider");
    const result = await ladderFinding(finding, new Consent({ authorizedScope: "test" }));
    expect(result.verdict).toBe(Verdict.NA);
  });

  it("requires an authorized scope to ladder (throws ScopeRequired)", async () => {
    const finding = findingFromKey("ghp_" + "a".repeat(36));
    await expect(ladderFinding(finding, Consent.denied())).rejects.toThrow(/scope/i);
  });
});

describe("buildBundle", () => {
  it("attests no state changed when no gated rung was exercised", async () => {
    const finding = findingFromKey("mystery", "TotallyUnknownProvider");
    const result = await ladderFinding(finding, new Consent({ authorizedScope: "test" }));
    const bundle = buildBundle([result], new Consent({ authorizedScope: "test" }), "0.1.0", 1_700_000_000);
    expect(bundle.noStateChanged).toBe(true);
    expect(bundle.toPublic().authorized_scope).toBe("test");
  });
});
