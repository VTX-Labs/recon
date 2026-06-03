```
██╗   ██╗████████╗██╗  ██╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║   ██║╚══██╔══╝╚██╗██╔╝     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║   ██║    ╚███╔╝█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚██╗ ██╔╝   ██║    ██╔██╗╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚████╔╝    ██║   ██╔╝ ██╗     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═══╝     ╚═╝   ╚═╝  ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

# vtx-recon

**Secret intelligence for authorized engagements — find a key, then prove what it can actually _do_.**

[![PyPI](https://img.shields.io/pypi/v/vtx-recon?color=3182ce&label=pypi)](https://pypi.org/project/vtx-recon/)
[![npm](https://img.shields.io/npm/v/@vtx-labs/recon?color=3182ce&label=npm)](https://www.npmjs.com/package/@vtx-labs/recon)
[![CI](https://img.shields.io/github/actions/workflow/status/VTX-Labs/recon/ci.yml?branch=main&color=3182ce&label=CI)](https://github.com/VTX-Labs/recon/actions)
[![Docs](https://img.shields.io/badge/docs-Python_%26_Node-3182ce)](https://vtx-labs.github.io/recon/)
[![License: MIT](https://img.shields.io/badge/License-MIT-3182ce.svg)](LICENSE)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20only-c0392b)](TERMS.md)

> ## ⚠️ Authorized use only
>
> vtx-recon is for security testing of systems you are **explicitly authorized**
> to test — an in-scope bug-bounty program or a signed engagement. Validating a
> credential beyond authentication may constitute unauthorized access under the
> **US CFAA**, the **UK Computer Misuse Act**, and equivalent laws. On HackerOne
> and similar programs: **report leaked credentials first; do not exercise their
> functionality** beyond what the program permits. Provided "as is", **no
> warranty, no liability**. By using it you accept the [TERMS](TERMS.md).

---

A found secret that merely _exists_ is not a finding. A found secret you can
prove _does something the program cares about_ is. [TruffleHog](https://github.com/trufflesecurity/trufflehog)
finds secrets and tells you if they're live; **vtx-recon picks up from there** —
it runs ordered, **read-only capability ladders** to prove _depth of access_,
tiers each key as **PROVEN / VALID / DENIED**, and emits a redacted,
timestamped evidence bundle you can drop into a report.

```
trufflehog ──▶ findings ──▶ vtx-recon ladder ──▶ PROVEN / VALID / DENIED ──▶ evidence bundle
   (find +        (live/        (safe, ordered        (impact tier)        (JSON + Markdown,
    verify)        dead)         read-only probes)                          secrets redacted)
```

## Two native implementations, one tool

vtx-recon ships as **two first-class, behavior-equivalent packages** — pick the
one that fits your stack. Both expose the same `vtx-recon` CLI, the same
pipeline, and the same safety guarantees.

|               | Package                                                                  | Install                                            | Source               |
| :------------ | :----------------------------------------------------------------------- | :------------------------------------------------- | :------------------- |
| 🐍 **Python** | [`vtx-recon`](https://pypi.org/project/vtx-recon/) (PyPI)                | `pipx install vtx-recon`                           | [`python/`](python/) |
| 📦 **Node**   | [`@vtx-labs/recon`](https://www.npmjs.com/package/@vtx-labs/recon) (npm) | `npm i -g @vtx-labs/recon` · `npx @vtx-labs/recon` | [`node/`](node/)     |

The Node build has **zero runtime dependencies** (built-in `fetch` + `node:crypto`);
the Python build depends only on `httpx`.

## Requirements

Both implementations orchestrate the **TruffleHog** binary — install it first:

```bash
# macOS / Linux
brew install trufflehog
# or: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## Quick start

```bash
# Find + verify secrets in a repo, then ladder the live ones (read-only):
vtx-recon find . --i-am-authorized "bugbounty:acme"

# Validate a single key you already have:
echo "AIza..." | vtx-recon ladder --i-am-authorized "bugbounty:acme"

# Machine-readable evidence bundle:
vtx-recon ladder --key ghp_xxx --i-am-authorized "h1:acme" --json
```

The commands are identical whether you installed the Python or the Node package.
By default **only safe, read-only probes run** — probes that cost money, read
PII, or change state are **gated** (below) and never run unless you arm them.

## The safety model — read-only by default, gated by construction

Every probe is one of two tiers:

- **SAFE** — read-only, non-billable, idempotent (list models, `GetCallerIdentity`,
  `auth.test`, read token scopes). Runs by default.
- **GATED** — billable, PII-reading, state-changing, or resource-creating
  (Gemini `generateContent` / file upload, a billable Maps call, Firebase
  anonymous signup, a Stripe account read).

A gated probe is **structurally unreachable** unless you pass **both**:

```bash
--prove                      # arm gated probes
--i-am-authorized "<scope>"  # name the engagement you're authorized to test
```

This is enforced **in code** — Python [`safety.py`](python/src/vtx_recon/safety.py),
Node [`safety.ts`](node/src/safety.ts) — identically: a gated probe raises
**before any network call** if consent isn't fully granted, and it fails
_closed_. The authorized scope is recorded verbatim in the evidence bundle, so
every action is attributable. Capability laddering refuses to run at all without
a named scope.

## Capability ladders

**51 providers** ship with a dedicated ladder, auto-detected from the key's
shape / TruffleHog detector name. Each climbs from cheapest/safest to deepest:
identity/whoami first, then reach/scope, then the impactful rung. Gated rungs are
marked 🔒. Where a rung needs an out-of-band value the engine cannot derive from
the secret alone (a second credential half, an account/host/project id), it never
fires a live call — it prints the exact copy-pasteable safe `curl` with the
secret kept as `$KEY` (marked _manual_) for an authorized operator to run by hand.
Both the Python and Node builds ship the same providers with identical rungs.

**Cloud & infra**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **Google / Gemini** (`AIza…`) | list models → files → cachedContents → corpora; read-only Referer-bypass on a referer-restricted key | `generateContent`, file upload, billable Maps probe, Firebase anon-signup |
| **GCP** (service-account JSON) | mint OAuth2 token → tokeninfo → list projects _(manual: engine can't sign the JWT)_ | list storage buckets 🔒 _(manual)_ |
| **AWS** (`AKIA`/`ASIA`) | STS `GetCallerIdentity` (stdlib SigV4, needs paired secret) | `iam:GetAccountAuthorizationDetails` 🔒 (bulk org/PII read) |
| **Azure** (Storage SAS) | SAS resource probe → service-principal token _(manual: needs account/container)_ | list blobs 🔒 _(manual)_ |
| **Cloudflare** (API token) | verify token → permission groups → list zones | edit DNS record 🔒 _(manual)_ |
| **DigitalOcean** (`dop_v1_`…) | `/account` → list droplets | create droplet 🔒 _(manual)_ |
| **Heroku** (Platform key) | `/account` → list apps | read app config vars 🔒 _(manual)_ |
| **Render** (`rnd_`) | list owners → list services | read service env vars 🔒 _(manual)_ |
| **Vercel** (access token) | `/user` → list projects | read decrypted project env 🔒 _(manual)_ |
| **Netlify** (PAT) | `/user` → list sites | read site/account env 🔒 _(manual)_ |
| **Fastly** (`Fastly-Key`) | token self → list services | purge-all cache 🔒 _(manual)_ |

**Data stores**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **Supabase** (`service_role` JWT) | REST root / OpenAPI schema _(manual: needs project ref)_ | list table rows, list auth users 🔒 _(manual)_ |
| **PlanetScale** (`pscale_tkn_`) | list orgs → list databases _(manual: needs token id + org)_ | create branch 🔒 _(manual)_ |
| **Snowflake** (account+user+pass) | `CURRENT_USER()` → list databases _(manual: needs KEYPAIR_JWT)_ | exfil table data 🔒 _(manual)_ |
| **Airtable** (`pat…`) | `whoami`+scopes → list bases | list base records 🔒 _(manual)_ |
| **Algolia** (admin key) | own-key ACL → list all keys → list indices _(manual: needs App ID)_ | clear index 🔒 _(manual)_ |

**CI/CD & packages**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **GitHub** (`ghp_`/`github_pat_`) | `/user` identity → scopes → dangerous-scope flag → reachable private repos → org walk | demonstration state-changing `PUT` 🔒 (proves the boundary is wired) |
| **GitLab** (`glpat-`) | `/user` identity → token scopes | — |
| **Bitbucket** (`ATBB…` app pw) | `/user` whoami → repo permissions _(manual: needs paired username)_ | create repository 🔒 _(manual)_ |
| **CircleCI** (`CCIPAT_`) | `/me` whoami → collaborations | trigger pipeline 🔒 _(manual)_ |
| **Travis CI** (token) | `/user` whoami → list repos | trigger build 🔒 _(manual)_ |
| **Terraform Cloud** (`.atlasv1.`) | account details → list orgs | create run 🔒 _(manual)_ |
| **Docker Hub** (`dckr_pat_`) | auth-token exchange → list namespace repos _(manual: needs username/JWT)_ | delete repository 🔒 _(manual)_ |
| **npm** (`NpmToken`) | `/-/whoami` → token type | publish package 🔒 _(manual)_ |
| **PyPI** (`pypi-` macaroon) | — (upload-only token, no read surface) | publish package 🔒 _(manual)_ |

**Comms & email**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **Slack** (`xox…`) | `auth.test` → conversations → users → files | read channel history, post message 🔒 _(manual)_ |
| **Discord** (bot token) | `/users/@me` → guilds | read channel history, send message 🔒 _(manual)_ |
| **Twilio** (`AC…` SID) | account fetch → phone numbers _(manual: needs AuthToken)_ | read balance 🔒 _(manual)_ |
| **SendGrid** (`SG.…`) | `/v3/scopes` (validity + scopes) | send mail 🔒 |
| **Mailgun** (`key-…`) | list domains → list DKIM keys | send message 🔒 _(manual)_ |
| **Mailchimp** (`…-us21`) | API root whoami → list audiences | add list member 🔒 _(manual)_ |
| **Postmark** (server token) | `/server` → delivery stats | send email 🔒 _(manual)_ |
| **Pusher** (channel key) | list channels → channel info _(manual: needs secret+app_id HMAC)_ | trigger event 🔒 _(manual)_ |

**Support & productivity**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **Asana** (PAT/OAuth) | `/users/me` → list workspaces | list workspace users (PII) 🔒 _(manual)_ |
| **Linear** (`lin_api_`) | viewer identity → organization | list org users (PII) 🔒 |
| **Notion** (`secret_`/`ntn_`) | `/users/me` bot user | list users, search shared content 🔒 |
| **Intercom** (access token) | `/me` → list admins | list contacts (PII) 🔒 |
| **HubSpot** (`pat-…`/OAuth) | token-info / account-info (whoami + scopes) | list CRM contacts (PII) 🔒 |
| **Zendesk** (`ZendeskApi`) | current user → list users _(manual: needs subdomain+email)_ | list tickets (PII) 🔒 _(manual)_ |
| **Figma** (`figd_`) | `/v1/me` whoami → list team projects _(manual)_ | — |

**Observability & ops**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **Datadog** (`DD-API-KEY`) | `/validate` (live check) → current user → list monitors _(manual: needs app key)_ | — |
| **Grafana** (`glsa_…`) | current user → user permissions → list datasources _(manual: needs host)_ | — |
| **New Relic** (`NRAK-`) | viewer identity → list accounts | — |
| **Sentry** (`sntryu_`/`sntrys_`) | list organizations → list org projects _(manual)_ | read project issues (PII) 🔒 _(manual)_ |
| **PagerDuty** (API key) | `/abilities` → list users | create incident 🔒 _(manual)_ |

**Payments & SaaS**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **Stripe** (`sk_`/`rk_`) | `/v1/balance` auth → products → balance transactions | account read, charges list (PII) 🔒 |
| **PayPal** (`PaypalOauth`) | OAuth2 token → userinfo _(manual: needs client id+secret)_ | create payout 🔒 _(manual)_ |
| **Square** (`EAAA…`) | list locations → merchant `/me` → team members | create payment 🔒 _(manual)_ |
| **Shopify** (`shpat_`) | access scopes → shop info _(manual: needs shop domain)_ | list customers (PII) 🔒 _(manual)_ |

**AI**

| Provider | Safe rungs (read-only) | Gated rungs 🔒 |
| :------- | :--------------------- | :------------- |
| **OpenAI** (`sk-`/`sk-proj-`) | `/v1/models` (validity) | chat completion (billable) 🔒 |
| **Anthropic** (`sk-ant-`) | `/v1/models` (validity) | create message (billable) 🔒 |

Beyond these 51, the generic declarative layer is a **runtime extensibility
hook**: register a `ProviderSpec` (header + read-only endpoint per rung) to plug a
new provider in as data, no core changes. A billable rung declared `SAFE` is
rejected; when a spec has no automated rung it prints the exact safe `curl`. It
is no longer a catch-all for the named providers above — every one now has its
own dedicated ladder.

## Impact tiers

| Verdict    | Meaning                                                                                                      |
| :--------- | :----------------------------------------------------------------------------------------------------------- |
| **PROVEN** | A gated probe ran (with consent) and demonstrated real impact. Report this.                                  |
| **VALID**  | Authenticates and safe probes proved access depth, but nothing impactful was exercised. Usually informative. |
| **DENIED** | Live but every probed capability was refused.                                                                |
| **N/A**    | Could not verify, or no ladder for this provider.                                                            |

## Exit codes

| Code | Meaning                                                           |
| :--- | :---------------------------------------------------------------- |
| `0`  | Success                                                           |
| `1`  | Runtime error                                                     |
| `2`  | Usage error                                                       |
| `3`  | TruffleHog binary not found                                       |
| `4`  | Authorized scope required (laddering without `--i-am-authorized`) |
| `5`  | A gated probe was blocked (missing `--prove` / scope)             |

## Development

```bash
# Python
cd python && pip install -e ".[dev]" && ruff check . && pytest

# Node
cd node && pnpm install && pnpm typecheck && pnpm test && pnpm build
```

Both test suites mock all network and the TruffleHog binary — they never touch a
real API or credential.

## License

[MIT](LICENSE) © [VTX Labs](https://vtxlabs.dev). Use governed by [TERMS.md](TERMS.md).

<sub>Built by [VTX Labs](https://vtxlabs.dev) · [GitHub](https://github.com/VTX-Labs) · [@vtxlabs](https://x.com/vtxlabs)</sub>
