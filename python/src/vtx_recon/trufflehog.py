"""Thin wrapper over the ``trufflehog`` binary — find + parse to Finding[].

vtx-recon does the *intelligence* (capability ladders + impact tiering +
evidence bundles); TruffleHog does the *finding* and the live/dead verify.
This module shells out to ``trufflehog --json`` and parses the NDJSON stream
into :class:`~vtx_recon.models.Finding` objects.

Importing this module is side-effect free: the binary is *not* invoked at
import time. Detection and execution happen only when the functions here are
called. Tests must mock these functions and never run the real binary.

Confirmed TruffleHog JSON fields used: ``DetectorName``, ``Verified``,
``Raw``, ``Redacted``, ``ExtraData``. Subcommands: ``git`` / ``github`` /
``filesystem`` / ``docker`` / ``stdin``. Result filtering via
``--results=verified,unknown,unverified``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable, Iterator

from .models import Finding

__all__ = [
    "BINARY_NAME",
    "TruffleHogError",
    "TruffleHogNotFound",
    "find_binary",
    "parse_json_stream",
    "parse_trufflehog_record",
    "run_trufflehog",
]

BINARY_NAME = "trufflehog"

_INSTALL_HINT = (
    "The 'trufflehog' binary was not found on PATH.\n"
    "vtx-recon shells out to TruffleHog for the find/verify stage.\n"
    "Install it (https://github.com/trufflesecurity/trufflehog):\n"
    "  brew install trufflehog\n"
    "  # or:\n"
    "  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/"
    "trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin\n"
    "Or pass a key directly with --key / --from-trufflehog to skip the find "
    "stage."
)


class TruffleHogError(RuntimeError):
    """A TruffleHog invocation failed."""


class TruffleHogNotFound(TruffleHogError):
    """The trufflehog binary could not be located on PATH."""

    def __init__(self) -> None:
        super().__init__(_INSTALL_HINT)


def find_binary(name: str = BINARY_NAME) -> str:
    """Return the absolute path to the trufflehog binary, or raise.

    Detection is on-demand only; never call this at import time.
    """
    path = shutil.which(name)
    if path is None:
        raise TruffleHogNotFound()
    return path


def parse_trufflehog_record(record: dict[str, object]) -> Finding | None:
    """Map one TruffleHog JSON object to a Finding, or None if not a result.

    TruffleHog emits log lines as well as result objects on the JSON stream;
    only objects with a ``DetectorName`` are results.
    """
    detector = record.get("DetectorName")
    if not detector:
        return None

    extra = record.get("ExtraData")
    extra_data: dict[str, object] = extra if isinstance(extra, dict) else {}

    source_meta = record.get("SourceMetadata")
    source = json.dumps(source_meta, separators=(",", ":")) if source_meta else ""

    return Finding(
        detector_name=str(detector),
        verified=bool(record.get("Verified", False)),
        raw=str(record.get("Raw", "")),
        detector_redacted=str(record.get("Redacted", "")),
        extra_data=extra_data,
        source=source,
    )


def parse_json_stream(lines: Iterable[str]) -> Iterator[Finding]:
    """Parse TruffleHog NDJSON output into Findings, skipping non-results.

    Malformed lines and non-result objects (log lines) are skipped silently
    so a noisy stream still yields its real findings.
    """
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        finding = parse_trufflehog_record(record)
        if finding is not None:
            yield finding


def run_trufflehog(
    subcommand: str,
    target: str,
    *,
    extra_args: list[str] | None = None,
    binary: str | None = None,
    timeout: float = 300.0,
) -> list[Finding]:
    """Run ``trufflehog <subcommand> <target> --json`` and parse the results.

    Args:
        subcommand: one of git / github / filesystem / docker / stdin.
        target: the scan target (repo URL, path, image, ...).
        extra_args: additional flags (e.g. ``["--results=verified,unknown"]``).
        binary: override the resolved binary path (used by tests).
        timeout: seconds before the scan is aborted.

    Raises:
        TruffleHogNotFound: the binary is not installed.
        TruffleHogError: the scan failed to run.
    """
    exe = binary or find_binary()
    cmd = [exe, subcommand, target, "--json", *(extra_args or [])]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:  # binary vanished between which() and run
        raise TruffleHogNotFound() from exc
    except subprocess.TimeoutExpired as exc:
        raise TruffleHogError(f"trufflehog timed out after {timeout}s") from exc

    # TruffleHog exits non-zero when it finds verified secrets, so a non-zero
    # code is not on its own an error; only treat it as failure if there is
    # no parseable JSON output at all.
    findings = list(parse_json_stream(proc.stdout.splitlines()))
    if not findings and proc.returncode not in (0, 183):
        raise TruffleHogError(
            f"trufflehog exited {proc.returncode} with no findings: "
            f"{proc.stderr.strip() or '(no stderr)'}"
        )
    return findings
