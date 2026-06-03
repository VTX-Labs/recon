# vtx-recon (Python)

**Secret intelligence for authorized engagements — find a key, then prove what it can actually _do_.**

!!! danger "Authorized use only"
    vtx-recon is for security testing of systems you are **explicitly authorized**
    to test — an in-scope bug-bounty program or a signed engagement. Validating a
    credential beyond authentication may constitute unauthorized access under the
    **US CFAA**, the **UK Computer Misuse Act**, and equivalent laws. On HackerOne
    and similar programs: **report leaked credentials first; do not exercise their
    functionality** beyond what the program permits. Provided "as is", **no
    warranty, no liability**.

---

A found secret that merely _exists_ is not a finding. A found secret you can
prove _does something the program cares about_ is.
[TruffleHog](https://github.com/trufflesecurity/trufflehog) finds secrets and
verifies they're live; **vtx-recon picks up from there** — ordered, **read-only
capability ladders** prove _depth of access_, tier each key as
**PROVEN / VALID / DENIED**, and emit a redacted, timestamped evidence bundle.

```
trufflehog ─▶ findings ─▶ vtx-recon ladder ─▶ PROVEN / VALID / DENIED ─▶ evidence bundle
```

## Install

```bash
pipx install vtx-recon     # requires the trufflehog binary on PATH
```

## Quick start

```bash
# Find + verify secrets in a repo, then ladder the live ones (read-only):
vtx-recon find . --i-am-authorized "bugbounty:acme"

# Validate a single key you already have:
echo "AIza..." | vtx-recon ladder --i-am-authorized "bugbounty:acme" --json
```

By default **only safe, read-only probes run**. Probes that cost money, read
PII, or change state are **gated** and unreachable unless you pass **both**
`--prove` and `--i-am-authorized "<scope>"` — enforced in code, fail-closed
(see [`vtx_recon.safety`](api.md#vtx_recon.safety)).

## Capability ladders

| Provider | Safe rungs (read-only) | Gated rungs |
| :------- | :--------------------- | :---------- |
| Google / Gemini | list models → files → cachedContents → corpora | generateContent, file upload, Maps billable, Firebase anon-signup |
| GitHub | identity → scopes → private repos → org walk | — |
| AWS | STS GetCallerIdentity (stdlib SigV4) | — |
| Slack / GitLab / Stripe | identity / token scopes | Stripe account read |
| Long-tail | declarative spec + safe-curl fallback | — |

## More

- **[API reference →](api.md)** — every module, class, and function.
- **[Project README & Node docs](https://github.com/VTX-Labs/recon#readme)** —
  full pipeline, exit codes, and the npm package.

Built by [VTX Labs](https://vtxlabs.dev) · MIT License · authorized use only.
