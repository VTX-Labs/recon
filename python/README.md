```
██╗   ██╗████████╗██╗  ██╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║   ██║╚══██╔══╝╚██╗██╔╝     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║   ██║    ╚███╔╝█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚██╗ ██╔╝   ██║    ██╔██╗╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚████╔╝    ██║   ██╔╝ ██╗     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═══╝     ╚═╝   ╚═╝  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

# vtx-recon (Python)

**Secret intelligence for authorized engagements — find a key, then prove what it can actually _do_.**

> ⚠️ **Authorized use only.** vtx-recon is for security testing of systems you are
> explicitly authorized to test (an in-scope bug-bounty program or signed
> engagement). Unauthorized use may violate the US CFAA, the UK Computer Misuse
> Act, and equivalent laws. Provided "as is", no warranty, no liability.

[TruffleHog](https://github.com/trufflesecurity/trufflehog) finds secrets and
verifies they're live; **vtx-recon picks up from there** — it runs ordered,
**read-only capability ladders** across **51 providers** to prove _depth of
access_, tiers each key as **PROVEN / VALID / DENIED**, and emits a redacted,
timestamped evidence bundle.

Safe, read-only probes run by default. Probes that cost money, read PII, or
change state are **gated** and unreachable unless you pass **both** `--prove`
and `--i-am-authorized "<scope>"` — enforced in code, fail-closed.

## Install

```bash
pipx install vtx-recon     # requires the trufflehog binary on PATH
```

## Quick start

```bash
vtx-recon find . --i-am-authorized "bugbounty:acme"
echo "AIza..." | vtx-recon ladder --i-am-authorized "bugbounty:acme" --json
```

Full documentation, the complete 51-provider capability-ladder reference, and
the safety model are in the
[project README](https://github.com/VTX-Labs/recon#readme).

Built by [VTX Labs](https://vtxlabs.dev) · MIT License · see TERMS.
