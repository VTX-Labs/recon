/**
 * The VTX LABS ASCII banner, rendered brand-blue on a TTY.
 *
 * The banner is printed on `--help` and suppressed for `--json` / when stdout
 * is not a TTY (so machine-readable output is never polluted). Brand blue is
 * `#3182ce` -> nearest stable 256-colour code 39.
 */

// Mirrors _brand/banner.txt (kept in lockstep with the org banner).
export const BANNER = [
  "██╗   ██╗████████╗██╗  ██╗  ██╗      █████╗ ██████╗ ███████╗",
  "██║   ██║╚══██╔══╝╚██╗██╔╝  ██║     ██╔══██╗██╔══██╗██╔════╝",
  "██║   ██║   ██║    ╚███╔╝   ██║     ███████║██████╔╝███████╗",
  "╚██╗ ██╔╝   ██║    ██╔██╗   ██║     ██╔══██║██╔══██╗╚════██║",
  " ╚████╔╝    ██║   ██╔╝ ██╗  ███████╗██║  ██║██████╔╝███████║",
  "  ╚═══╝     ╚═╝   ╚═╝  ╚═╝  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝",
].join("\n");

export const TAGLINE = "vtx-recon · authorized-use secret intelligence";

// Brand blue #3182ce in 256-colour space, applied directly (independent of the
// colors helper's TTY/NO_COLOR detection so render can be forced on or off).
const BLUE = `${String.fromCharCode(27)}[38;5;39m`;
const BOLD = `${String.fromCharCode(27)}[1m`;
const RESET = `${String.fromCharCode(27)}[0m`;

/**
 * Whether the banner should be printed.
 *
 * Shown only on an interactive TTY and never when emitting JSON, so piped or
 * machine-consumed output stays clean.
 */
export function shouldShowBanner(options: {
  asJson: boolean;
  stream?: { isTTY?: boolean } | undefined;
}): boolean {
  if (options.asJson) {
    return false;
  }
  const stream = options.stream ?? process.stdout;
  return Boolean(stream && stream.isTTY);
}

/** Return the banner + tagline, brand-blue when `color` is true. */
export function renderBanner(color = true): string {
  if (!color) {
    return `${BANNER}\n${TAGLINE}`;
  }
  return `${BOLD}${BLUE}${BANNER}${RESET}\n${BLUE}${TAGLINE}${RESET}`;
}
