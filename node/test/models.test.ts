/** The data model: serialisable, secret-free public views. */

import { describe, expect, it } from "vitest";
import {
  EvidenceBundle,
  Finding,
  LadderResult,
  ProbeResult,
  Verdict,
} from "../src/models.js";
import { ProbeTier } from "../src/safety.js";

describe("Finding", () => {
  it("exposes a redacted form and never serialises the raw secret", () => {
    const awsKey = "AKIA" + "EXAMPLE1234567890";
    const f = new Finding({
      detectorName: "AWS",
      verified: true,
      raw: awsKey,
      extraData: { aws_secret_access_key: "supersecretvalue", account: "1234" },
    });
    expect(f.redacted.startsWith("AKIA")).toBe(true);
    const pub = f.toPublic();
    const blob = JSON.stringify(pub);
    expect(blob).not.toContain(awsKey);
    expect(blob).not.toContain("supersecretvalue");
    expect((pub.extra_data as Record<string, unknown>)["account"]).toBe("1234");
  });

  it("prefers TruffleHog's own redacted form when present", () => {
    const f = new Finding({ detectorName: "X", verified: false, raw: "raw", detectorRedacted: "TH****" });
    expect(f.redacted).toBe("TH****");
  });
});

describe("ProbeResult", () => {
  it("serialises tier as its string value and redacts evidence", () => {
    const r = new ProbeResult({
      name: "x",
      tier: ProbeTier.GATED,
      success: true,
      evidence: { token: "xoxb-secret-token", status: 200 },
    });
    const pub = r.toPublic();
    expect(pub.tier).toBe("gated");
    expect(String(pub.evidence["token"])).not.toContain("secret");
    expect(pub.evidence["status"]).toBe(200);
  });
});

describe("EvidenceBundle", () => {
  it("renders an ISO timestamp and the no-state-changed attestation", () => {
    const finding = new Finding({ detectorName: "X", verified: true, raw: "k" });
    const ladder = new LadderResult({ finding, provider: "x", verdict: Verdict.VALID });
    const bundle = new EvidenceBundle({
      authorizedScope: "acme",
      toolVersion: "0.1.0",
      results: [ladder],
      createdAt: 1_780_000_000, // fixed epoch seconds
    });
    const pub = bundle.toPublic();
    expect(pub.tool).toBe("vtx-recon");
    expect(pub.authorized_scope).toBe("acme");
    expect(pub.created_at_iso).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(pub.no_state_changed_attestation).toBe(true);
    expect(pub.results).toHaveLength(1);
  });
});
