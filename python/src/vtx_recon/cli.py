"""``vtx-recon`` command-line entry point.

Pipeline subcommands:

    find    scan a target with TruffleHog and emit findings
    verify  re-check whether a credential is live (delegates to TruffleHog)
    ladder  run the capability ladder for a finding (requires authorized scope)
    report  build the court-ready evidence bundle from ladder results

Global safety flags:

    --prove                   arm gated (billable/state-changing) probes
    --i-am-authorized SCOPE   name the engagement you are authorized to test

Gated probes are UNREACHABLE unless BOTH are supplied; see
:mod:`vtx_recon.safety`. This file wires the skeleton — the actual ladder
execution is filled in by provider modules. AUTHORIZED USE ONLY (TERMS.md).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from .banner import render_banner, should_show_banner
from .models import Finding
from .pipeline import (
    build_bundle,
    finding_from_key,
    ladder_finding,
    render_bundle_markdown,
    render_ladder_text,
)
from .safety import Consent, GatedProbeBlocked, ScopeRequired
from .trufflehog import TruffleHogNotFound, parse_json_stream, run_trufflehog

__all__ = ["build_parser", "main"]

# Exit codes (documented in README; keep in lockstep).
EXIT_OK = 0
EXIT_USAGE = 2  # argparse convention for bad usage
EXIT_NO_TRUFFLEHOG = 3
EXIT_SCOPE_REQUIRED = 4
EXIT_GATED_BLOCKED = 5
EXIT_RUNTIME = 1

_DISCLAIMER = (
    "AUTHORIZED USE ONLY. vtx-recon is for security testing of systems you "
    "are explicitly authorized to test (e.g. an in-scope bug-bounty program "
    "or signed engagement). Unauthorized use may violate the US CFAA, the UK "
    "Computer Misuse Act, and equivalent laws. On HackerOne and similar "
    "programs: report leaked credentials first; do not exercise their "
    "functionality beyond what the program permits. No warranty; no "
    "liability. See TERMS.md."
)


class _BannerHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Prefix --help with the brand banner (colour only on a TTY)."""


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for the whole CLI."""
    show = should_show_banner(as_json=False)
    banner = render_banner(color=show) if show else ""
    description = f"{banner}\n\n{_DISCLAIMER}" if banner else _DISCLAIMER

    # The global flags live on a parent parser shared by the top level AND every
    # subcommand, so `--json` / `--i-am-authorized` / `--prove` are accepted
    # either before OR after the subcommand (order-independent, like the Node CLI).
    globals_parser = argparse.ArgumentParser(add_help=False)
    globals_parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON and suppress the banner",
    )
    globals_parser.add_argument(
        "--prove",
        action="store_true",
        help="arm gated (billable / PII / state-changing) probes; requires --i-am-authorized",
    )
    globals_parser.add_argument(
        "--i-am-authorized",
        dest="authorized_scope",
        metavar="SCOPE",
        default=None,
        help="name the engagement you are authorized to test "
        "(recorded verbatim in the evidence bundle)",
    )

    parser = argparse.ArgumentParser(
        prog="vtx-recon",
        description=description,
        epilog=_DISCLAIMER,
        formatter_class=_BannerHelpFormatter,
        parents=[globals_parser],
    )
    parser.add_argument("--version", action="version", version=f"vtx-recon {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="{find,verify,ladder,report}")

    p_find = sub.add_parser("find", help="scan a target with TruffleHog", parents=[globals_parser])
    p_find.add_argument(
        "--source",
        default="filesystem",
        help="TruffleHog subcommand: git/github/filesystem/docker/stdin",
    )
    p_find.add_argument("target", nargs="?", help="scan target (path, repo, image, ...)")

    p_verify = sub.add_parser(
        "verify", help="check whether a credential is live", parents=[globals_parser]
    )
    _add_key_inputs(p_verify)

    p_ladder = sub.add_parser(
        "ladder", help="run the capability ladder for a finding", parents=[globals_parser]
    )
    _add_key_inputs(p_ladder)

    p_report = sub.add_parser("report", help="build the evidence bundle", parents=[globals_parser])
    p_report.add_argument(
        "--out", default=None, help="directory to write the timestamped bundle into"
    )

    return parser


def _add_key_inputs(p: argparse.ArgumentParser) -> None:
    """Add the mutually-exclusive ways to supply a credential."""
    group = p.add_mutually_exclusive_group()
    group.add_argument("--key", default=None, help="the secret to act on (read from argv)")
    group.add_argument(
        "--from-trufflehog",
        metavar="JSON",
        default=None,
        help="path to a TruffleHog --json file (or '-' for stdin)",
    )
    p.add_argument(
        "--detector",
        default=None,
        help="provider detector name when supplying a bare --key",
    )


def consent_from_args(args: argparse.Namespace) -> Consent:
    """Build the immutable Consent object from parsed CLI flags."""
    return Consent(
        prove=bool(getattr(args, "prove", False)),
        authorized_scope=getattr(args, "authorized_scope", None),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        # No subcommand: print help (with banner) and signal usage error.
        parser.print_help()
        return EXIT_USAGE

    consent = consent_from_args(args)

    # --prove without a scope is a usage error: it can never arm a gated
    # probe, and silently ignoring it would mislead the operator.
    if consent.prove and not consent.has_scope:
        _emit_error(
            args.json,
            '--prove requires --i-am-authorized "<scope>"; gated probes stay blocked.',
        )
        return EXIT_USAGE

    handlers = {
        "find": _cmd_find,
        "verify": _cmd_ladder,  # verify shares the ladder path (live/dead + depth)
        "ladder": _cmd_ladder,
        "report": _cmd_report,
    }
    handler = handlers[args.command]
    try:
        return handler(args, consent)
    except ScopeRequired as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SCOPE_REQUIRED
    except GatedProbeBlocked as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_GATED_BLOCKED
    except TruffleHogNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_NO_TRUFFLEHOG


# --- subcommand handlers -----------------------------------------------------


def _resolve_findings(args: argparse.Namespace) -> list[Finding]:
    """Resolve the findings a verify/ladder run should operate on."""
    from_th = getattr(args, "from_trufflehog", None)
    if from_th is not None:
        raw = _read_stdin() if from_th == "-" else _read_file(from_th)
        return list(parse_json_stream(raw.splitlines()))
    key = getattr(args, "key", None) or _read_stdin().strip()
    if not key:
        print("error: provide a credential via --key, --from-trufflehog, or stdin", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    return [finding_from_key(key, getattr(args, "detector", None))]


def _run_and_report(args: argparse.Namespace, consent: Consent, findings: list[Finding]) -> int:
    """Ladder a batch of findings, assemble the bundle, and render it."""

    async def _run() -> list:
        return [await ladder_finding(f, consent) for f in findings]

    results = asyncio.run(_run())
    bundle = build_bundle(results, consent, __version__)

    if args.json:
        json.dump(bundle.to_public(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.command == "report":
        print(render_bundle_markdown(bundle))
    else:
        for r in results:
            print(render_ladder_text(r))
    return EXIT_OK


def _cmd_find(args: argparse.Namespace, consent: Consent) -> int:
    target = args.target or "."
    findings = run_trufflehog(args.source, target, extra_args=["--results=verified,unknown"])
    if not findings:
        if args.json:
            json.dump({"findings": 0, "results": []}, sys.stdout)
            sys.stdout.write("\n")
        else:
            print("No secrets found by TruffleHog.")
        return EXIT_OK
    return _run_and_report(args, consent, list(findings))


def _cmd_ladder(args: argparse.Namespace, consent: Consent) -> int:
    return _run_and_report(args, consent, _resolve_findings(args))


def _cmd_report(args: argparse.Namespace, consent: Consent) -> int:
    return _run_and_report(args, consent, _resolve_findings(args))


def _read_stdin() -> str:
    try:
        return sys.stdin.read()
    except Exception:
        return ""


def _read_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _emit_error(as_json: bool, message: str) -> None:
    if as_json:
        json.dump({"error": message}, sys.stdout)
        sys.stdout.write("\n")
    else:
        print(f"error: {message}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
