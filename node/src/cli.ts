#!/usr/bin/env node
/**
 * vtx-recon CLI — authorized-use secret intelligence.
 *
 * Pipeline subcommands:
 *
 *   find    scan a target with TruffleHog and emit findings
 *   verify  re-check whether a credential is live (delegates to TruffleHog)
 *   ladder  run the capability ladder for a finding (requires authorized scope)
 *   report  build the court-ready evidence bundle from ladder results
 *
 * Global safety flags:
 *
 *   --prove                   arm gated (billable / PII / state-changing) probes
 *   --i-am-authorized SCOPE   name the engagement you are authorized to test
 *
 * Gated probes are UNREACHABLE unless BOTH are supplied; see {@link "./safety"}.
 * Each command runs the real pipeline (see {@link "./pipeline"}): findings are
 * routed to their provider ladder, tiered, and assembled into an evidence bundle.
 * AUTHORIZED USE ONLY (TERMS.md).
 *
 * Exit codes (documented in README; keep in lockstep):
 *   0  success
 *   1  runtime error
 *   2  usage error
 *   3  TruffleHog binary not found
 *   4  authorized scope required (laddering without --i-am-authorized)
 *   5  a gated probe was blocked (missing --prove / scope)
 */

import { argv as processArgv } from "node:process";
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { renderBanner, shouldShowBanner } from "./banner.js";
import { c } from "./colors.js";
import { Consent } from "./safety.js";
import { VERSION } from "./index.js";
import { Finding, type LadderResult } from "./models.js";
import { parseJsonStream, runTruffleHog } from "./trufflehog.js";
import {
  buildBundle,
  findingFromKey,
  ladderFinding,
  renderBundleMarkdown,
  renderLadderText,
} from "./pipeline.js";

const EXIT_OK = 0;
const EXIT_RUNTIME = 1;
const EXIT_USAGE = 2;
const EXIT_NO_TRUFFLEHOG = 3;
const EXIT_SCOPE_REQUIRED = 4;
const EXIT_GATED_BLOCKED = 5;

const DISCLAIMER =
  "AUTHORIZED USE ONLY. vtx-recon is for security testing of systems you are " +
  "explicitly authorized to test (e.g. an in-scope bug-bounty program or signed " +
  "engagement). Unauthorized use may violate the US CFAA, the UK Computer Misuse " +
  "Act, and equivalent laws. On HackerOne and similar programs: report leaked " +
  "credentials first; do not exercise their functionality beyond what the program " +
  "permits. No warranty; no liability. See TERMS.md.";

const COMMANDS = ["find", "verify", "ladder", "report"] as const;
type Command = (typeof COMMANDS)[number];

interface Args {
  command: Command | null;
  json: boolean;
  prove: boolean;
  authorizedScope: string | null;
  help: boolean;
  version: boolean;
  // find
  source: string;
  target: string | null;
  // verify / ladder
  key: string | null;
  fromTrufflehog: string | null;
  detector: string | null;
  // report
  out: string | null;
}

function defaultArgs(): Args {
  return {
    command: null,
    json: false,
    prove: false,
    authorizedScope: null,
    help: false,
    version: false,
    source: "filesystem",
    target: null,
    key: null,
    fromTrufflehog: null,
    detector: null,
    out: null,
  };
}

function parseArgs(argv: string[]): Args {
  const a = defaultArgs();

  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === undefined) continue;

    switch (tok) {
      case "-h":
      case "--help":
        a.help = true;
        break;
      case "--version":
        a.version = true;
        break;
      case "--json":
        a.json = true;
        break;
      case "--prove":
        a.prove = true;
        break;
      case "--i-am-authorized":
        a.authorizedScope = requireValue(argv, ++i, tok);
        break;
      case "--source":
        a.source = requireValue(argv, ++i, tok);
        break;
      case "--key":
        a.key = requireValue(argv, ++i, tok);
        break;
      case "--from-trufflehog":
        a.fromTrufflehog = requireValue(argv, ++i, tok);
        break;
      case "--detector":
        a.detector = requireValue(argv, ++i, tok);
        break;
      case "--out":
        a.out = requireValue(argv, ++i, tok);
        break;
      default:
        if (tok.startsWith("-")) {
          fail(`unrecognized option: ${tok}`);
        } else if (a.command === null) {
          if (!(COMMANDS as readonly string[]).includes(tok)) {
            fail(`invalid choice: ${tok} (choose from ${COMMANDS.join(", ")})`);
          }
          a.command = tok as Command;
        } else if (a.target === null) {
          // First positional after the command (e.g. the find target).
          a.target = tok;
        } else {
          fail(`unexpected argument: ${tok}`);
        }
    }
  }

  // --key and --from-trufflehog are mutually exclusive (argparse group).
  if (a.key !== null && a.fromTrufflehog !== null) {
    fail("--key and --from-trufflehog are mutually exclusive");
  }
  return a;
}

function requireValue(argv: string[], i: number, flag: string): string {
  const v = argv[i];
  if (v === undefined || v.startsWith("-")) {
    fail(`option ${flag} expects a value`);
  }
  return v as string;
}

/** Bad usage -> print to stderr and exit 2 (argparse convention). */
function fail(msg: string): never {
  process.stderr.write(`${c.red("error")}: ${msg}\nRun \`vtx-recon --help\` for usage.\n`);
  process.exit(EXIT_USAGE);
}

function help(): void {
  const show = shouldShowBanner({ asJson: false });
  const banner = show ? `${renderBanner(c.enabled)}\n\n` : "";
  const b = c.bold;
  process.stdout.write(
    `${banner}${b("vtx-recon")} ${c.dim("v" + VERSION)} — authorized-use secret intelligence

${b("Usage")}
  vtx-recon <command> [options]

${b("Commands")}
  find [target]    scan a target with TruffleHog and emit findings
  verify           check whether a credential is live (delegates to TruffleHog)
  ladder           run the capability ladder for a finding (needs --i-am-authorized)
  report           build the court-ready evidence bundle

${b("Global options")}
  --json                       emit machine-readable JSON and suppress the banner
  --prove                      arm gated (billable / PII / state-changing) probes
  --i-am-authorized <scope>    name the engagement you are authorized to test
                               ${c.dim("(recorded verbatim in the evidence bundle)")}
  -h, --help                   show this help
  --version                    show version

${b("find options")}
  --source <kind>              TruffleHog subcommand: git/github/filesystem/docker/stdin
                               ${c.dim("(default: filesystem)")}

${b("verify / ladder options")}
  --key <secret>               the secret to act on
  --from-trufflehog <json>     path to a TruffleHog --json file (or '-' for stdin)
  --detector <name>            provider detector name when supplying a bare --key

${b("report options")}
  --out <dir>                  directory to write the timestamped bundle into

${c.dim(DISCLAIMER)}

${c.dim("Built by VTX Labs · https://vtxlabs.dev")}
`,
  );
}

/** Build the immutable Consent object from parsed CLI flags. */
function consentFromArgs(args: Args): Consent {
  return new Consent({ prove: args.prove, authorizedScope: args.authorizedScope });
}

function emitError(asJson: boolean, message: string): void {
  if (asJson) {
    process.stdout.write(JSON.stringify({ error: message }) + "\n");
  } else {
    process.stderr.write(`error: ${message}\n`);
  }
}

/** Read all of stdin to a string (used for piped keys / TruffleHog JSON). */
function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/** Resolve the findings a verify/ladder run should operate on. */
function resolveFindings(args: Args): Finding[] {
  // --from-trufflehog <path|-> : parse a TruffleHog --json stream.
  if (args.fromTrufflehog !== null) {
    const raw =
      args.fromTrufflehog === "-" ? readStdin() : readFileSync(args.fromTrufflehog, "utf8");
    return parseJsonStream(raw.split(/\r?\n/));
  }
  // --key <secret> | piped key on stdin.
  const key = args.key ?? readStdin().trim();
  if (key === "") {
    fail("provide a credential via --key, --from-trufflehog, or stdin");
  }
  return [findingFromKey(key, args.detector)];
}

/** Ladder a batch of findings, assemble the bundle, and render it. */
async function runLadderAndReport(args: Args, consent: Consent, findings: Finding[]): Promise<number> {
  const results: LadderResult[] = [];
  for (const finding of findings) {
    results.push(await ladderFinding(finding, consent));
  }
  // Date.now is fine in the CLI (not in workflow scripts); seconds for the bundle.
  const bundle = buildBundle(results, consent, VERSION, Date.now() / 1000);

  if (args.json) {
    process.stdout.write(JSON.stringify(bundle.toPublic(), null, 2) + "\n");
  } else if (args.command === "report") {
    process.stdout.write(renderBundleMarkdown(bundle) + "\n");
  } else {
    for (const r of results) {
      process.stdout.write(renderLadderText(r) + "\n");
    }
  }
  return EXIT_OK;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const args = parseArgs(argv);

  if (args.version) {
    process.stdout.write(`vtx-recon ${VERSION}\n`);
    return EXIT_OK;
  }
  if (args.help) {
    help();
    return EXIT_OK;
  }

  if (args.command === null) {
    // No subcommand: print help (with banner) and signal a usage error.
    help();
    return EXIT_USAGE;
  }

  const consent = consentFromArgs(args);

  // --prove without a scope is a usage error: it can never arm a gated probe,
  // and silently ignoring it would mislead the operator.
  if (consent.prove && !consent.hasScope) {
    emitError(args.json, '--prove requires --i-am-authorized "<scope>"; gated probes stay blocked.');
    return EXIT_USAGE;
  }

  switch (args.command) {
    case "find": {
      // Run TruffleHog over the target, then ladder every finding.
      const target = args.target ?? ".";
      const findings = await runTruffleHog(args.source, target, {
        extraArgs: ["--results=verified,unknown"],
      });
      if (findings.length === 0) {
        if (args.json) process.stdout.write(JSON.stringify({ findings: 0, results: [] }) + "\n");
        else process.stdout.write(`${c.dim("No secrets found by TruffleHog.")}\n`);
        return EXIT_OK;
      }
      return runLadderAndReport(args, consent, findings);
    }
    case "verify":
    case "ladder":
    case "report":
      return runLadderAndReport(args, consent, resolveFindings(args));
  }
}

// Run only when invoked as the bin, not when imported.
const entry = processArgv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  runCli();
}

async function runCli(): Promise<void> {
  try {
    process.exit(await main());
  } catch (err) {
    // Map known error types to their documented exit codes; default runtime.
    const name = err instanceof Error ? err.name : "";
    if (name === "ScopeRequired") {
      process.stderr.write(`error: ${(err as Error).message}\n`);
      process.exit(EXIT_SCOPE_REQUIRED);
    }
    if (name === "GatedProbeBlocked") {
      process.stderr.write(`error: ${(err as Error).message}\n`);
      process.exit(EXIT_GATED_BLOCKED);
    }
    if (name === "TruffleHogNotFound") {
      process.stderr.write(`error: ${(err as Error).message}\n`);
      process.exit(EXIT_NO_TRUFFLEHOG);
    }
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(EXIT_RUNTIME);
  }
}
