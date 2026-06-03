# Terms of Use — vtx-recon

**vtx-recon is for AUTHORIZED security testing only.** Read this before you
run it. By using vtx-recon you agree to these terms.

## Authorized use only

You may use vtx-recon **only** against systems and credentials that you own or
that you are **explicitly authorized in writing** to test — for example:

- a target that is **in scope** for a bug-bounty program you are enrolled in
  (e.g. HackerOne / Bugcrowd), within that program's stated rules; or
- a system covered by a **signed engagement / statement of work** that
  authorizes credential and capability testing.

The `--i-am-authorized "<scope>"` flag exists so you must **name that
authorization** before the capability ladder will run. That scope string is
recorded verbatim in every evidence bundle. Naming a scope you do not actually
hold is a misrepresentation and your sole responsibility.

## What "gated" means, and why it is locked

vtx-recon is **read-only by default**. Probes that are billable, that read
PII, that change state, or that create resources (for example: Gemini
`generateContent` or file upload, a billable Google Maps call, Firebase
anonymous signup, a Stripe account read) are **gated**. Gated probes are
**unreachable** unless you pass **both** `--prove` **and**
`--i-am-authorized "<scope>"`. This is enforced in code, not just documented.
The default (safe) tier is structurally unable to call a gated endpoint.

## Responsible disclosure first

On bug-bounty platforms and in coordinated disclosure generally: **report the
leaked credential first, and do not exercise the functionality it grants**
beyond what the program explicitly permits. Demonstrating *that* a key is live
and *what depth of access it has* via read-only probes is usually sufficient
and far safer than exercising impactful functionality. Use gated probes only
when the program's rules clearly allow it.

## Legal

Unauthorized access to computer systems is a crime in most jurisdictions,
including under the **US Computer Fraud and Abuse Act (CFAA)**, the **UK
Computer Misuse Act 1990**, the EU Directive 2013/40/EU, and equivalent laws
worldwide. You are solely responsible for ensuring your use is lawful and
authorized.

## No warranty, no liability

vtx-recon is provided "AS IS", without warranty of any kind, as set out in the
[MIT LICENSE](LICENSE). To the maximum extent permitted by law, VTX Labs and
the contributors accept **no liability** for any claim, damage, loss, or other
liability arising from your use or misuse of this software. The tool's safety
controls reduce risk but do not relieve you of responsibility for how you use
it.

If you are not certain you are authorized to test a target: **stop, and do not
run vtx-recon against it.**
