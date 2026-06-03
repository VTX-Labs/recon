"""The VTX LABS ASCII banner, rendered brand-blue on a TTY.

The banner is printed on ``--help`` and suppressed for ``--json`` / when
stdout is not a TTY (so machine-readable output is never polluted).
Brand blue is ``#3182ce`` -> nearest stable 256-colour code 39.
"""

from __future__ import annotations

import sys

__all__ = ["BANNER", "TAGLINE", "render_banner", "should_show_banner"]

# Mirrors _brand/banner.txt (kept in lockstep with the org banner).
BANNER = r"""
██╗   ██╗████████╗██╗  ██╗  ██╗      █████╗ ██████╗ ███████╗
██║   ██║╚══██╔══╝╚██╗██╔╝  ██║     ██╔══██╗██╔══██╗██╔════╝
██║   ██║   ██║    ╚███╔╝   ██║     ███████║██████╔╝███████╗
╚██╗ ██╔╝   ██║    ██╔██╗   ██║     ██╔══██║██╔══██╗╚════██║
 ╚████╔╝    ██║   ██╔╝ ██╗  ███████╗██║  ██║██████╔╝███████║
  ╚═══╝     ╚═╝   ╚═╝  ╚═╝  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
""".strip("\n")

TAGLINE = "vtx-recon · authorized-use secret intelligence"

# Brand blue #3182ce in 256-colour space.
_BLUE = "\033[38;5;39m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def should_show_banner(*, as_json: bool, stream: object | None = None) -> bool:
    """Whether the banner should be printed.

    Shown only on an interactive TTY and never when emitting JSON, so piped
    or machine-consumed output stays clean.
    """
    if as_json:
        return False
    stream = stream if stream is not None else sys.stdout
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def render_banner(*, color: bool = True) -> str:
    """Return the banner + tagline, brand-blue when ``color`` is True."""
    if not color:
        return f"{BANNER}\n{TAGLINE}"
    return f"{_BOLD}{_BLUE}{BANNER}{_RESET}\n{_BLUE}{TAGLINE}{_RESET}"
