/**
 * Pusher Channels capability ladder — prove depth of access from a leaked key.
 *
 * A TruffleHog `PusherChannelKey` finding is the app's **public key** (the
 * 20-char `key`). On its own that key is NOT sufficient to call the Channels
 * HTTP API: every request to `api-{cluster}.pusher.com` must be **HMAC-SHA256
 * signed** with the paired app **SECRET**, and the signature plus
 * `auth_key`/`auth_timestamp`/`auth_version` query params must be appended to
 * the URL (see https://pusher.com/docs/channels/library_auth_reference/rest-api/).
 * The signing also needs the numeric `app_id`. None of `secret`, `app_id`, or
 * `cluster` are present in the raw finding, and every rung's URL carries the
 * `{cluster}`/`{app_id}` placeholders the engine cannot fill.
 *
 * Per the manual-rung rule, that means **every rung is MANUAL**: no rung issues
 * a live call. Each rung instead emits a copy-pasteable, safe `curl` an operator
 * can run by hand once they have recovered the paired secret + app_id and
 * produced the HMAC signature, with the key kept as a `$KEY` placeholder (and
 * `$SIGNATURE`/`$TIMESTAMP` placeholders for the per-request HMAC) so nothing
 * sensitive is ever stored.
 *
 * Rungs (ordered, identity / read first):
 *
 *   1. `list-channels` — SAFE/MANUAL. `GET /apps/{app_id}/channels` lists the
 *      app's occupied realtime channels (read-only). Proves the credential set
 *      reaches live app data. Non-billable.
 *   2. `channel-info` — SAFE/MANUAL. `GET /apps/{app_id}/channels/{channel_name}`
 *      reads a specific channel's attributes (occupancy, subscription count) —
 *      a deeper read into the app. Read-only, non-billable.
 *   3. `trigger-event` — GATED/MANUAL. `POST /apps/{app_id}/events` publishes an
 *      event to all subscribers of a channel — state-changing, pushes arbitrary
 *      payloads to every connected client. Routed through {@link gated} so it is
 *      structurally unreachable without BOTH `--prove` and
 *      `--i-am-authorized "<scope>"`; even when consent is granted it never
 *      auto-fires (placeholders + HMAC cannot be filled) — it renders the safe
 *      curl for the operator.
 *
 * The ladder never throws across its public boundary: every failure becomes a
 * {@link ProbeResult}. Secrets are never persisted; only non-secret values land
 * in evidence.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { register } from "./registry.js";

// --------------------------------------------------------------------------- //
// safe-curl rendering (no live call is ever made by this provider)
// --------------------------------------------------------------------------- //

/** Minimal POSIX single-quote shell quoting for a curl argument. */
function shquote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

/**
 * Build a copy-pasteable curl with the key kept as a `$KEY` placeholder and the
 * per-request HMAC kept as `$SIGNATURE`/`$TIMESTAMP` placeholders. The
 * `{cluster}`/`{app_id}` URL placeholders are left for the operator to
 * substitute. The string never contains a live secret, so it is safe to print
 * and to store.
 */
function safeCurl(args: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): string {
  const parts = ["curl", "-sS", "-X", args.method];
  for (const [headerName, headerValue] of Object.entries(args.headers)) {
    parts.push("-H", shquote(`${headerName}: ${headerValue}`));
  }
  if (args.body !== undefined) {
    parts.push("--data", shquote(args.body));
  }
  parts.push(shquote(args.url));
  return parts.join(" ");
}

// Every Pusher REST request must carry HMAC-SHA256 auth as query params.
// `$KEY` is the leaked public key; `$TIMESTAMP` and `$SIGNATURE` are the
// per-request HMAC the engine cannot compute (it needs the paired app SECRET).
const AUTH_QUERY =
  "auth_key=$KEY&auth_timestamp=$TIMESTAMP&auth_version=1.0&auth_signature=$SIGNATURE";

/**
 * Derive the impact tier from the rungs that ran.
 * - A successful GATED rung that actually ran (not blocked) -> PROVEN.
 * - Any successful SAFE rung -> VALID.
 * - Nothing succeeded -> DENIED.
 *
 * NOTE: every Pusher rung is manual and never makes a live call, so no rung is
 * ever `success: true`. The verdict is therefore always DENIED — the ladder
 * cannot prove live access without the out-of-band secret + app_id and a
 * computed HMAC signature.
 */
function verdictFrom(rungs: ProbeResult[]): Verdict {
  if (rungs.some((r) => r.success && r.tier === ProbeTier.GATED && !r.blocked)) {
    return Verdict.PROVEN;
  }
  if (rungs.some((r) => r.success)) {
    return Verdict.VALID;
  }
  return Verdict.DENIED;
}

// --------------------------------------------------------------------------- //
// rung 1 — SAFE / MANUAL: list-channels
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /apps/{app_id}/channels` lists the app's occupied realtime
 * channels (read-only). Proves the credential set reaches live app data —
 * confirms the key is for a real, reachable app. Non-billable. MANUAL because
 * it needs the paired app SECRET to HMAC-sign the request (not in the raw
 * finding) plus the `{cluster}`/`{app_id}` host/path placeholders — no live
 * call is made; the operator is handed the exact safe curl.
 */
function pusherListChannels(): ProbeResult {
  const name = "list-channels";
  const url = `https://api-{cluster}.pusher.com/apps/{app_id}/channels?${AUTH_QUERY}`;
  const curl = safeCurl({ method: "GET", url, headers: {} });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the paired app SECRET to HMAC-sign (not in the raw finding) " +
      "and the {cluster}/{app_id} host; run this by hand to list occupied " +
      `channels: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — SAFE / MANUAL: channel-info
// --------------------------------------------------------------------------- //
/**
 * SAFE/MANUAL: `GET /apps/{app_id}/channels/{channel_name}` reads a specific
 * channel's attributes (occupancy, subscription count) — a deeper read into the
 * app's live state. Read-only, idempotent, non-billable. MANUAL (HMAC secret +
 * `{cluster}`/`{app_id}`/`{channel_name}` placeholders); no live call is made —
 * the operator is handed the safe curl.
 */
function pusherChannelInfo(): ProbeResult {
  const name = "channel-info";
  const url =
    `https://api-{cluster}.pusher.com/apps/{app_id}/channels/{channel_name}` +
    `?info=user_count,subscription_count&${AUTH_QUERY}`;
  const curl = safeCurl({ method: "GET", url, headers: {} });
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the paired app SECRET to HMAC-sign and the " +
      "{cluster}/{app_id}/{channel_name} host/path; run this by hand to read a " +
      `channel's occupancy/subscription count: ${curl}`,
    evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
  });
}

// --------------------------------------------------------------------------- //
// rung 3 — GATED / MANUAL: trigger-event (state-changing broadcast)
// --------------------------------------------------------------------------- //
/**
 * GATED/MANUAL: `POST /apps/{app_id}/events` publishes an event to all
 * subscribers of a channel.
 *
 * State-changing: pushes an arbitrary payload to every connected client — the
 * impact rung. Wrapped with {@link gated}: the safety boundary runs *before*
 * this body, so without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and nothing is rendered as runnable. Even with
 * consent it is MANUAL — the engine cannot HMAC-sign with the secret or fill
 * the `{cluster}`/`{app_id}` placeholders, so it returns the safe curl rather
 * than firing.
 */
export const pusherTriggerEvent = gated(
  "pusher.trigger-event",
  async (_consent: Consent): Promise<ProbeResult> => {
    const name = "trigger-event";
    const url = `https://api-{cluster}.pusher.com/apps/{app_id}/events?${AUTH_QUERY}`;
    const body =
      '{"name":"vtx-recon-probe","channels":["my-channel"],"data":"{\\"ping\\":1}"}';
    const curl = safeCurl({
      method: "POST",
      url,
      headers: { "Content-Type": "application/json" },
      body,
    });
    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      blocked: false,
      detail:
        "MANUAL GATED: would broadcast an arbitrary event to every subscriber " +
        "(state-changing). Needs the app SECRET to HMAC-sign and {cluster}/{app_id}; " +
        `run by hand only when authorized: ${curl}`,
      evidence: { manual: true, billable: false, safe_curl: curl, success_status: [200] },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Pusher capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope. Every rung is MANUAL (no live
 * call): the SAFE rungs always render their safe curl; the GATED rung is reached
 * only through the safety boundary — when consent is missing it is recorded as a
 * blocked rung, when consent is present it still only renders a safe curl.
 */
export async function pusherLadder(
  finding: Finding,
  consent: Consent,
): Promise<LadderResult> {
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE/MANUAL): reachability — list occupied channels. Manual rungs
  // always render, so subsequent rungs are not gated on a (never-true) success —
  // the operator gets the full hand-run plan.
  rungs.push(pusherListChannels());
  // Rung 2 (SAFE/MANUAL): deeper read — a specific channel's attributes.
  rungs.push(pusherChannelInfo());

  // Rung 3 (GATED/MANUAL): state-changing broadcast. Reachable only via the
  // gated wrapper; without full consent it throws GatedProbeBlocked, recorded as
  // a blocked rung (the safe curl is still surfaced as evidence). The ladder
  // never throws across its public boundary.
  const triggerBody =
    '{"name":"vtx-recon-probe","channels":["my-channel"],"data":"{\\"ping\\":1}"}';
  const triggerCurl = safeCurl({
    method: "POST",
    url: `https://api-{cluster}.pusher.com/apps/{app_id}/events?${AUTH_QUERY}`,
    headers: { "Content-Type": "application/json" },
    body: triggerBody,
  });
  try {
    rungs.push(await pusherTriggerEvent(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "trigger-event",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            billable: false,
            safe_curl: triggerCurl,
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  return new LadderResult({
    finding,
    provider: "pusher",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(["PusherChannelKey"], (finding, consent) => pusherLadder(finding, consent));
