/**
 * CLI behaviour: exit-code mapping and the --prove-without-scope usage guard.
 * `main()` returns a code rather than calling process.exit, so it is testable.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import { VERSION } from "../src/index.js";

let stdout: string;
let stderr: string;

beforeEach(() => {
  stdout = "";
  stderr = "";
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    stdout += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    stderr += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("vtx-recon CLI", () => {
  it("prints the version", async () => {
    expect(await main(["--version"])).toBe(0);
    expect(stdout).toContain(`vtx-recon ${VERSION}`);
  });

  it("prints help with exit 0 on --help", async () => {
    expect(await main(["--help"])).toBe(0);
    expect(stdout).toContain("Usage");
    expect(stdout).toContain("AUTHORIZED USE ONLY");
  });

  it("prints help and returns the usage code (2) when no command is given", async () => {
    expect(await main([])).toBe(2);
  });

  it("treats --prove without a scope as a usage error (exit 2)", async () => {
    expect(await main(["ladder", "--prove"])).toBe(2);
    expect(stderr).toContain("--prove requires --i-am-authorized");
  });

  it("emits a JSON usage error when --json is set", async () => {
    expect(await main(["ladder", "--prove", "--json"])).toBe(2);
    expect(JSON.parse(stdout)).toMatchObject({ error: expect.stringContaining("--prove") });
  });

  it("ladder without a scope throws ScopeRequired (mapped to exit 4 by the bin)", async () => {
    // ladder/verify/report require an authorized scope; without one the safety
    // gate raises before any probe runs. runCli() maps this to EXIT_SCOPE_REQUIRED.
    await expect(main(["ladder", "--key", "ghp_" + "x".repeat(36)])).rejects.toThrow(
      /authorized scope/i,
    );
  });
});
