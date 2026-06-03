/**
 * TruffleHog integration: NDJSON parsing + clear missing-binary handling. NEVER
 * invokes the real trufflehog binary — node:child_process and node:fs are
 * mocked so no process is spawned and PATH lookups are controlled.
 */

import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";

// --- mocks -------------------------------------------------------------------
const spawnMock = vi.fn();
const accessSyncMock = vi.fn();

vi.mock("node:child_process", () => ({ spawn: (...args: unknown[]) => spawnMock(...args) }));
vi.mock("node:fs", () => ({
  accessSync: (...args: unknown[]) => accessSyncMock(...args),
  constants: { X_OK: 1 },
}));

const {
  TruffleHogNotFound,
  findBinary,
  parseJsonStream,
  parseTruffleHogRecord,
  runTruffleHog,
} = await import("../src/trufflehog.js");

afterEach(() => {
  spawnMock.mockReset();
  accessSyncMock.mockReset();
});

// --- record parsing ----------------------------------------------------------

describe("parseTruffleHogRecord", () => {
  it("maps the confirmed fields", () => {
    const awsKey = "AKIA" + "EXAMPLE1234567890";
    const finding = parseTruffleHogRecord({
      DetectorName: "AWS",
      Verified: true,
      Raw: awsKey,
      Redacted: "AKIA****",
      ExtraData: { account: "1234" },
      SourceMetadata: { Data: { Filesystem: { file: "config.env" } } },
    });
    expect(finding).not.toBeNull();
    expect(finding?.detectorName).toBe("AWS");
    expect(finding?.verified).toBe(true);
    expect(finding?.raw).toBe(awsKey);
    expect(finding?.extraData).toEqual({ account: "1234" });
    expect(finding?.source).toContain("config.env");
  });

  it("ignores non-results (log lines without DetectorName)", () => {
    expect(parseTruffleHogRecord({ level: "info", msg: "scanning" })).toBeNull();
    expect(parseTruffleHogRecord({})).toBeNull();
  });
});

describe("parseJsonStream", () => {
  it("skips noise (log lines, malformed, blank, non-dict)", () => {
    const lines = [
      '{"level":"info","msg":"starting"}',
      "not json at all",
      "",
      '{"DetectorName":"GitHub","Verified":false,"Raw":"ghp_x"}',
      "[1,2,3]",
    ];
    const findings = parseJsonStream(lines);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.detectorName).toBe("GitHub");
    expect(findings[0]?.verified).toBe(false);
  });
});

// --- binary discovery --------------------------------------------------------

describe("findBinary", () => {
  it("throws TruffleHogNotFound with an install hint when absent", () => {
    accessSyncMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });
    process.env.PATH = "/usr/bin";
    expect(() => findBinary()).toThrow(TruffleHogNotFound);
    try {
      findBinary();
    } catch (err) {
      expect((err as Error).message.toLowerCase()).toContain("trufflehog");
    }
  });

  it("returns the path when found on PATH", () => {
    process.env.PATH = "/usr/bin";
    accessSyncMock.mockImplementation(() => undefined); // first candidate is executable
    const found = findBinary();
    expect(found).toContain("trufflehog");
  });
});

// --- run (spawn is mocked; the real binary is NEVER executed) ----------------

/** A fake ChildProcess that emits canned stdout then closes with `code`. */
function fakeChild(stdout: string, stderr: string, code: number) {
  const child = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: () => void;
  };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => undefined;
  // Emit asynchronously so the caller can attach listeners first.
  setImmediate(() => {
    if (stdout) child.stdout.emit("data", Buffer.from(stdout));
    if (stderr) child.stderr.emit("data", Buffer.from(stderr));
    child.emit("close", code);
  });
  return child;
}

describe("runTruffleHog", () => {
  it("parses findings from the NDJSON stream (verified-secret non-zero exit is fine)", async () => {
    const ndjson =
      '{"level":"info"}\n' +
      '{"DetectorName":"GitHub","Verified":true,"Raw":"ghp_x","Redacted":"ghp_****"}\n';
    spawnMock.mockReturnValue(fakeChild(ndjson, "", 183));

    const findings = await runTruffleHog("filesystem", ".", { binary: "/fake/trufflehog" });
    expect(spawnMock).toHaveBeenCalledOnce();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.detectorName).toBe("GitHub");
  });

  it("throws TruffleHogError when it exits non-zero with no findings", async () => {
    spawnMock.mockReturnValue(fakeChild("", "boom", 1));
    await expect(
      runTruffleHog("filesystem", ".", { binary: "/fake/trufflehog" }),
    ).rejects.toThrow(/exited 1/);
  });

  it("maps a spawn ENOENT to TruffleHogNotFound", async () => {
    const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; kill: () => void };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => undefined;
    setImmediate(() => child.emit("error", Object.assign(new Error("not found"), { code: "ENOENT" })));
    spawnMock.mockReturnValue(child);

    await expect(
      runTruffleHog("filesystem", ".", { binary: "/missing/trufflehog" }),
    ).rejects.toThrow(TruffleHogNotFound);
  });
});
