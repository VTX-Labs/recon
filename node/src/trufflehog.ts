/**
 * Thin wrapper over the `trufflehog` binary — find + parse to Finding[].
 *
 * vtx-recon does the *intelligence* (capability ladders + impact tiering +
 * evidence bundles); TruffleHog does the *finding* and the live/dead verify.
 * This module shells out to `trufflehog --json` and parses the NDJSON stream
 * into {@link Finding} objects.
 *
 * Importing this module is side-effect free: the binary is *not* invoked or
 * even located at import time. Detection and execution happen only when the
 * functions here are called. Tests must mock these functions / `node:child_process`
 * and never run the real binary.
 *
 * Confirmed TruffleHog JSON fields used: `DetectorName`, `Verified`, `Raw`,
 * `Redacted`, `ExtraData`. Subcommands: `git` / `github` / `filesystem` /
 * `docker` / `stdin`. Result filtering via `--results=verified,unknown,unverified`.
 */

import { spawn } from "node:child_process";
import { delimiter, join } from "node:path";
import { accessSync, constants } from "node:fs";
import { Finding } from "./models.js";

export const BINARY_NAME = "trufflehog";

const INSTALL_HINT =
  "The 'trufflehog' binary was not found on PATH.\n" +
  "vtx-recon shells out to TruffleHog for the find/verify stage.\n" +
  "Install it (https://github.com/trufflesecurity/trufflehog):\n" +
  "  brew install trufflehog\n" +
  "  # or:\n" +
  "  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/" +
  "trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin\n" +
  "Or pass a key directly with --key / --from-trufflehog to skip the find stage.";

/** A TruffleHog invocation failed. */
export class TruffleHogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TruffleHogError";
  }
}

/** The trufflehog binary could not be located on PATH. */
export class TruffleHogNotFound extends TruffleHogError {
  constructor() {
    super(INSTALL_HINT);
    this.name = "TruffleHogNotFound";
  }
}

/**
 * Return the absolute path to the trufflehog binary, or throw.
 *
 * Walks `PATH` looking for an executable named `name` (with the platform's
 * executable extensions on Windows). Detection is on-demand only; never call
 * this at import time.
 */
export function findBinary(name: string = BINARY_NAME): string {
  const found = which(name);
  if (found === null) {
    throw new TruffleHogNotFound();
  }
  return found;
}

/** A cross-platform `which`: locate an executable on PATH, or null. */
function which(name: string): string | null {
  const pathEnv = process.env.PATH ?? "";
  const dirs = pathEnv.split(delimiter).filter(Boolean);
  // On Windows, try the PATHEXT extensions; elsewhere just the bare name.
  const exts =
    process.platform === "win32"
      ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean)
      : [""];

  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // not here / not executable — keep looking.
      }
    }
  }
  return null;
}

/** A single raw TruffleHog JSON record (only the fields we read are typed). */
export interface TruffleHogRecord {
  DetectorName?: unknown;
  Verified?: unknown;
  Raw?: unknown;
  Redacted?: unknown;
  ExtraData?: unknown;
  SourceMetadata?: unknown;
  [key: string]: unknown;
}

/**
 * Map one TruffleHog JSON object to a Finding, or null if not a result.
 *
 * TruffleHog emits log lines as well as result objects on the JSON stream;
 * only objects with a `DetectorName` are results.
 */
export function parseTruffleHogRecord(record: TruffleHogRecord): Finding | null {
  const detector = record.DetectorName;
  if (!detector) {
    return null;
  }

  const extra = record.ExtraData;
  const extraData =
    extra !== null && typeof extra === "object" && !Array.isArray(extra)
      ? (extra as Record<string, unknown>)
      : {};

  const sourceMeta = record.SourceMetadata;
  const source = sourceMeta ? JSON.stringify(sourceMeta) : "";

  return new Finding({
    detectorName: String(detector),
    verified: Boolean(record.Verified ?? false),
    raw: String(record.Raw ?? ""),
    detectorRedacted: String(record.Redacted ?? ""),
    extraData,
    source,
  });
}

/**
 * Parse TruffleHog NDJSON output into Findings, skipping non-results.
 *
 * Malformed lines and non-result objects (log lines) are skipped silently so a
 * noisy stream still yields its real findings.
 */
export function parseJsonStream(lines: Iterable<string>): Finding[] {
  const findings: Finding[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) {
      continue;
    }
    let record: unknown;
    try {
      record = JSON.parse(line);
    } catch {
      continue;
    }
    if (record === null || typeof record !== "object" || Array.isArray(record)) {
      continue;
    }
    const finding = parseTruffleHogRecord(record as TruffleHogRecord);
    if (finding !== null) {
      findings.push(finding);
    }
  }
  return findings;
}

export interface RunTruffleHogOptions {
  /** Additional flags (e.g. `["--results=verified,unknown"]`). */
  extraArgs?: string[];
  /** Override the resolved binary path (used by tests). */
  binary?: string;
  /** Milliseconds before the scan is aborted. Default 300_000 (300s). */
  timeoutMs?: number;
}

/**
 * Run `trufflehog <subcommand> <target> --json` and parse the results.
 *
 * @param subcommand one of git / github / filesystem / docker / stdin.
 * @param target the scan target (repo URL, path, image, ...).
 *
 * @throws {@link TruffleHogNotFound} the binary is not installed.
 * @throws {@link TruffleHogError} the scan failed to run.
 */
export async function runTruffleHog(
  subcommand: string,
  target: string,
  options: RunTruffleHogOptions = {},
): Promise<Finding[]> {
  const exe = options.binary ?? findBinary();
  const timeoutMs = options.timeoutMs ?? 300_000;
  const args = [subcommand, target, "--json", ...(options.extraArgs ?? [])];

  const { stdout, stderr, code, error } = await spawnCapture(exe, args, timeoutMs);

  if (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      // Binary vanished between which() and spawn.
      throw new TruffleHogNotFound();
    }
    if ((error as { vtxTimeout?: boolean }).vtxTimeout) {
      throw new TruffleHogError(`trufflehog timed out after ${timeoutMs / 1000}s`);
    }
    throw new TruffleHogError(`trufflehog failed to run: ${error.message}`);
  }

  // TruffleHog exits non-zero when it finds verified secrets, so a non-zero
  // code is not on its own an error; only treat it as failure if there is no
  // parseable JSON output at all.
  const findings = parseJsonStream(stdout.split(/\r?\n/));
  if (findings.length === 0 && code !== 0 && code !== 183) {
    throw new TruffleHogError(
      `trufflehog exited ${code} with no findings: ${stderr.trim() || "(no stderr)"}`,
    );
  }
  return findings;
}

interface SpawnCapture {
  stdout: string;
  stderr: string;
  code: number | null;
  error: Error | null;
}

/** Spawn a process, capture stdout/stderr, and enforce a timeout. */
function spawnCapture(exe: string, args: string[], timeoutMs: number): Promise<SpawnCapture> {
  return new Promise<SpawnCapture>((resolve) => {
    const child = spawn(exe, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      const timeoutError = Object.assign(new Error("timed out"), { vtxTimeout: true });
      child.kill("SIGKILL");
      finish({ stdout, stderr, code: null, error: timeoutError });
    }, timeoutMs);

    const finish = (result: SpawnCapture): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err: Error) => finish({ stdout, stderr, code: null, error: err }));
    child.on("close", (code: number | null) => finish({ stdout, stderr, code, error: null }));
  });
}
