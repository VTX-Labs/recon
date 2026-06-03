/** Secrets must never appear raw in output or evidence bundles. */

import { describe, expect, it } from "vitest";
import { redact, redactMapping } from "../src/redact.js";

describe("redact", () => {
  it("keeps a short prefix and masks the rest", () => {
    const out = redact("sk-live-abcdef1234567890");
    expect(out.startsWith("sk-l")).toBe(true);
    expect(out).not.toContain("abcdef");
    expect(new Set(out.slice(4))).toEqual(new Set(["*"]));
  });

  it("clamps the mask length so a long secret does not reveal its length", () => {
    const out = redact("A".repeat(500));
    expect(out.length).toBeLessThanOrEqual(4 + 8); // prefix + capped mask
  });

  it("fully masks very short secrets (no prefix shown)", () => {
    expect(redact("abc")).toBe("***"); // 3 <= prefix(4)
    expect(redact("abcd")).toBe("****"); // 4 == prefix(4)
    expect(redact("short")).toBe("shor*"); // 5 > prefix(4)
  });

  it("handles empty and null/undefined", () => {
    expect(redact("")).toBe("<empty>");
    expect(redact(null)).toBe("<none>");
    expect(redact(undefined)).toBe("<none>");
  });

  it("decodes bytes", () => {
    expect(redact(new TextEncoder().encode("ghp_secrettoken")).startsWith("ghp_")).toBe(true);
  });
});

describe("redactMapping", () => {
  it("walks nested secret keys", () => {
    const data = {
      DetectorName: "AWS",
      Raw: "AKIA" + "EXAMPLE1234567890",
      ExtraData: { token: "xoxb-very-secret", account: "acme" },
      list: [{ password: "hunter2hunter2" }],
    };
    const out = redactMapping(data);
    expect(out["DetectorName"]).toBe("AWS"); // non-secret untouched
    expect(String(out["Raw"])).not.toContain("AKIA" + "EXAMPLE");
    const extra = out["ExtraData"] as Record<string, unknown>;
    expect(String(extra["token"])).not.toContain("very-secret");
    expect(extra["account"]).toBe("acme");
    const list = out["list"] as Array<Record<string, unknown>>;
    expect(String(list[0]?.["password"])).not.toContain("hunter2");
  });

  it("matches keys case-insensitively", () => {
    const out = redactMapping({ API_KEY: "secretvalue123" });
    expect(String(out["API_KEY"])).not.toContain("secretvalue");
  });
});
