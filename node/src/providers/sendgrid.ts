/**
 * SendGrid capability ladder — prove depth of access for a leaked API key.
 *
 * A TruffleHog `SendGrid` finding is an API key (`SG.<id>.<secret>`). The
 * ladder proves what the key can reach, then gates the obvious abuse:
 *
 *   1. `scopes`    `GET /v3/scopes` — SAFE. The key authenticates and returns
 *      the exact scopes granted to it (read-only). This proves both validity and
 *      depth-of-access (e.g. `mail.send`, `mail.batch.read`). Decides VALID vs
 *      DENIED.
 *   2. `send-mail` `POST /v3/mail/send` — GATED. Actually sending email is
 *      state-changing and reputation-/billing-impacting. Wrapped with
 *      {@link gated}: the boundary runs *before* any network call, so without
 *      BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 *      and nothing is sent.
 *
 * The ladder never throws across its public boundary — every failure becomes a
 * {@link ProbeResult}. The raw key is held only transiently and never written
 * into evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { redact } from "../redact.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, readJson, type FetchLike } from "./http.js";
import { register } from "./registry.js";

/** TruffleHog DetectorName values routed to this ladder (case-insensitive). */
export const DETECTORS = ["SendGrid", "Sendgrid"] as const;

const API_BASE = "https://api.sendgrid.com";
const TIMEOUT_MS = 10_000;

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
}

function networkFailure(name: string, tier: ProbeTier, exc: unknown): ProbeResult {
  return new ProbeResult({
    name,
    tier,
    success: false,
    detail: `probe could not complete: ${errName(exc)}`,
    evidence: { error: errName(exc) },
  });
}

function verdictFrom(rungs: ProbeResult[]): Verdict {
  if (rungs.some((r) => r.success && r.tier === ProbeTier.GATED && !r.blocked)) {
    return Verdict.PROVEN;
  }
  if (rungs.some((r) => r.success)) {
    return Verdict.VALID;
  }
  return Verdict.DENIED;
}

/** SendGrid ladder: SAFE `scopes` -> GATED `send-mail`. */
export async function sendgridLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];
  const key = finding.raw;
  const fetchImpl = options.fetchImpl;

  const scopes = await sendgridScopes(key, fetchImpl);
  rungs.push(scopes);

  if (scopes.success) {
    try {
      rungs.push(await sendgridSendMail(consent, key, fetchImpl));
    } catch (exc) {
      if (exc instanceof GatedProbeBlocked) {
        rungs.push(
          new ProbeResult({
            name: "sendgrid.send_mail",
            tier: ProbeTier.GATED,
            success: false,
            blocked: true,
            detail: `gated mail send blocked: ${exc.reason}`,
            evidence: { reason: exc.reason },
          }),
        );
      } else {
        throw exc;
      }
    }
  }

  return new LadderResult({
    finding,
    provider: "sendgrid",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

/** SAFE: `GET /v3/scopes` confirms the key and reveals granted scopes. */
async function sendgridScopes(key: string, fetchImpl: FetchLike | undefined): Promise<ProbeResult> {
  const name = "sendgrid.scopes";
  let resp: Response;
  try {
    resp = await httpRequest(`${API_BASE}/v3/scopes`, {
      headers: { Authorization: `Bearer ${key}` },
      timeoutMs: TIMEOUT_MS,
      fetchImpl,
    });
  } catch (exc) {
    return networkFailure(name, ProbeTier.SAFE, exc);
  }

  if (resp.status !== 200) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `key rejected (HTTP ${resp.status})`,
      evidence: { status: resp.status },
    });
  }

  const body = (await readJson(resp)) as { scopes?: string[] } | undefined;
  if (body === undefined) {
    return networkFailure(name, ProbeTier.SAFE, new SyntaxError("invalid JSON"));
  }

  const scopes = Array.isArray(body.scopes) ? body.scopes : [];
  const canSend = scopes.includes("mail.send");
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: true,
    detail:
      `key authenticates; ${scopes.length} scopes granted` +
      (canSend ? " (including mail.send)" : ""),
    evidence: {
      status: resp.status,
      key_prefix: redact(key),
      scope_count: scopes.length,
      can_send_mail: canSend,
      sample_scopes: scopes.slice(0, 10),
    },
  });
}

/**
 * GATED: `POST /v3/mail/send` — actually sends an email.
 *
 * Wrapped with {@link gated}: the boundary runs before this body, so without
 * BOTH `--prove` and an authorized scope it throws {@link GatedProbeBlocked}
 * and no mail is ever sent.
 */
export const sendgridSendMail = gated(
  "sendgrid.send_mail",
  async (_consent: Consent, key: string, fetchImpl?: FetchLike): Promise<ProbeResult> => {
    const name = "sendgrid.send_mail";
    let resp: Response;
    try {
      resp = await httpRequest(`${API_BASE}/v3/mail/send`, {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: "recon@example.com" }] }],
          from: { email: "recon@example.com" },
          subject: "vtx-recon authorized capability probe",
          content: [{ type: "text/plain", value: "probe" }],
        }),
        timeoutMs: TIMEOUT_MS,
        fetchImpl,
      });
    } catch (exc) {
      return networkFailure(name, ProbeTier.GATED, exc);
    }

    // SendGrid returns 202 Accepted for a queued send.
    if (resp.status !== 202) {
      return new ProbeResult({
        name,
        tier: ProbeTier.GATED,
        success: false,
        detail: `mail send refused (HTTP ${resp.status})`,
        evidence: { status: resp.status },
      });
    }

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: true,
      detail: "mail send accepted (state-changing: an email was queued)",
      evidence: { status: resp.status, state_changed: true },
    });
  },
);

register([...DETECTORS], (finding, consent) => sendgridLadder(finding, consent));
