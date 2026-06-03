/**
 * Azure Storage SAS capability ladder — prove the blast radius of a leaked SAS.
 *
 * A TruffleHog `AzureSasToken` / `AzureStorage` finding is a Shared Access
 * Signature: a self-contained query-string credential
 * (`sp=...&st=...&se=...&sig=...`) appended to a
 * `https://<account>.blob.core.windows.net/<container|blob>` URL. The SAS needs
 * no second secret — the signature alone authorises the scoped operations — so
 * `{key}` (the whole SAS query string) is everything we hold.
 *
 * Rungs (ordered):
 *
 *   1. `sas-resource-probe` — SAFE. `GET <container>?{key}&restype=container`
 *      (no `comp=list`) reads only container *properties*, not blob contents,
 *      and proves the signature is valid / unexpired against the exact resource
 *      it is scoped to (200 = readable, 403 = valid principal, action denied).
 *
 *   2. `list-blobs` — GATED. `GET <container>?{key}&comp=list&restype=container`
 *      enumerates every blob name in the container — the impact rung, since the
 *      inventory may include third-party PII / backups. Reachable only with BOTH
 *      `--prove` and `--i-am-authorized "<scope>"`.
 *
 *   3. `service-principal-token` — SAFE / MANUAL. An Azure AD client secret is a
 *      DIFFERENT credential: redeeming it for a token needs the paired
 *      `tenant_id` + `client_id`, which are NOT in the raw secret.
 *
 * Every rung here carries a placeholder the engine cannot fill from the raw
 * secret alone — the storage `ACCOUNT` and `CONTAINER` for rungs 1-2, and the
 * `TENANT_ID` / `client_id` for rung 3. Per the ladder convention, a rung whose
 * URL or headers contain ANY placeholder besides `{key}` MUST NOT fire a live
 * call: it is rendered as a MANUAL safe-curl note (the SAS stays `$KEY`) so an
 * authorized operator can run it by hand once they supply the missing
 * identifiers. The GATED rung is additionally consent-gated, so it is shown as a
 * blocked/manual note and never auto-fires.
 *
 * The ladder never throws across its public boundary, performs no network I/O
 * (every rung is manual), and never persists the raw SAS.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { register } from "./registry.js";

// Detector names this ladder answers for.
const DETECTORS = ["AzureSasToken", "AzureStorage"];

// The {key} placeholder is the live SAS query string; in a safe curl it stays
// `$KEY` so nothing secret is ever written out. The other tokens (ACCOUNT,
// CONTAINER, TENANT_ID, client id) are NOT in the raw secret, so the operator
// fills them by hand — which is exactly why each rung is manual.
const SAS_PLACEHOLDER = "$KEY";

// The exact safe curl for the gated container inventory. The SAS stays `$KEY`
// and the unfillable ACCOUNT / CONTAINER are left for the operator. Shared
// between the gated rung body and the blocked-rung note so both render the same
// copy-pasteable command.
const LIST_BLOBS_CURL =
  `curl -sS -X GET ` +
  `'https://ACCOUNT.blob.core.windows.net/CONTAINER?${SAS_PLACEHOLDER}&comp=list&restype=container'`;

/**
 * Derive the impact tier from the rungs that ran.
 *
 * Every rung in this ladder is manual (no live call is possible without
 * operator-supplied identifiers), so no rung reports `success`. A successful
 * GATED rung that actually ran (not blocked) would be PROVEN; any successful
 * SAFE rung would be VALID; otherwise DENIED.
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
// rung 1 — SAFE / MANUAL: sas-resource-probe
// --------------------------------------------------------------------------- //
/**
 * SAFE rung, rendered MANUAL.
 *
 * `GET https://ACCOUNT.blob.core.windows.net/CONTAINER?{key}&restype=container`
 * proves the SAS signature is valid and not expired/revoked against the exact
 * resource it is scoped to (200 = readable, 403 = valid principal, action not
 * permitted). `restype=container` with no `comp=list` returns only container
 * properties, never blob contents.
 *
 * The URL needs the storage ACCOUNT and CONTAINER names, neither of which is in
 * the raw SAS, so the engine cannot fire it — we hand back the safe curl.
 */
function sasResourceProbe(): ProbeResult {
  const curl =
    `curl -sS -X GET ` +
    `'https://ACCOUNT.blob.core.windows.net/CONTAINER?${SAS_PLACEHOLDER}&restype=container'`;
  return new ProbeResult({
    name: "sas-resource-probe",
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: needs the storage ACCOUNT and CONTAINER names (not in the raw " +
      `SAS); run by hand to confirm the signature is live (200/403): ${curl}`,
    evidence: {
      manual: true,
      safe_curl: curl,
      success_status: [200, 403],
      proves:
        "valid, unexpired SAS signature against its scoped resource " +
        "(restype=container returns only container properties, not blobs)",
    },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — GATED / MANUAL: list-blobs (container inventory)
// --------------------------------------------------------------------------- //
/**
 * GATED rung, rendered MANUAL (blocked note).
 *
 * `GET <container>?{key}&comp=list&restype=container` enumerates every blob name
 * in the SAS-scoped container — the impact rung, proving the SAS can inventory
 * (and by extension read) stored objects which may include third-party PII or
 * backups. It is GATED because it reads the data the credential points at, AND
 * manual because the ACCOUNT / CONTAINER names are not in the raw SAS, so it
 * never auto-fires.
 *
 * Wrapped with {@link gated}: the safety boundary runs before this body, so
 * without BOTH `--prove` and an authorized scope it throws
 * {@link GatedProbeBlocked} and we record a blocked rung. Even when consent IS
 * granted, the rung stays manual: it returns the gated curl rather than firing.
 */
const listBlobsGated = gated("azure.list-blobs", async (_consent: Consent): Promise<ProbeResult> => {
  return new ProbeResult({
    name: "list-blobs",
    tier: ProbeTier.GATED,
    success: false,
    blocked: false,
    detail:
      "GATED + MANUAL: enumerates every blob name in the container (may expose " +
      `PII/backups); needs ACCOUNT + CONTAINER, run by hand: ${LIST_BLOBS_CURL}`,
    evidence: {
      manual: true,
      safe_curl: LIST_BLOBS_CURL,
      success_status: [200],
      proves:
        "the SAS can inventory (and by extension read) stored objects in its " +
        "scoped container",
    },
  });
});

// --------------------------------------------------------------------------- //
// rung 3 — SAFE / MANUAL: service-principal-token (different credential)
// --------------------------------------------------------------------------- //
/**
 * SAFE rung, rendered MANUAL.
 *
 * For an Azure AD client secret: `POST https://login.microsoftonline.com/
 * TENANT_ID/oauth2/v2.0/token` with
 * `grant_type=client_credentials&client_id=...&client_secret={key}&scope=...`
 * redeems the secret for an access token, proving it is live and revealing the
 * app identity.
 *
 * This is always manual: it needs the paired `tenant_id` and `client_id`, which
 * are a SEPARATE credential from the SAS and are NOT present in the raw secret.
 */
function servicePrincipalToken(): ProbeResult {
  const curl =
    `curl -sS -X POST ` +
    `-H 'Content-Type: application/x-www-form-urlencoded' ` +
    `--data 'grant_type=client_credentials&client_id=CLIENT_ID&client_secret=${SAS_PLACEHOLDER}&scope=https://management.azure.com/.default' ` +
    `'https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token'`;
  return new ProbeResult({
    name: "service-principal-token",
    tier: ProbeTier.SAFE,
    success: false,
    blocked: false,
    detail:
      "MANUAL: only applies to an Azure AD client secret, and needs the paired " +
      `TENANT_ID + CLIENT_ID (a different credential, not in the raw secret): ${curl}`,
    evidence: {
      manual: true,
      safe_curl: curl,
      success_status: [200],
      proves:
        "an Azure AD client secret is live and reveals the app identity " +
        "(requires the paired tenant_id + client_id)",
    },
  });
}

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
/**
 * Run the ordered Azure SAS capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle). Every
 * rung carries a placeholder the engine cannot fill, so each is emitted as a
 * MANUAL safe-curl note and no network call is made. The GATED `list-blobs`
 * rung is additionally routed through the safety boundary: without full consent
 * it is recorded as a blocked rung. Never throws across this boundary.
 */
export async function azureLadder(finding: Finding, consent: Consent): Promise<LadderResult> {
  // Whole-ladder gate: refuse to probe without a named, authorized scope.
  const scope = consent.requireLadderScope();
  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE, manual): is the SAS signature live against its resource?
  rungs.push(sasResourceProbe());

  // Rung 2 (GATED, manual): container inventory. Route through the safety
  // boundary so the safe tier cannot reach the gated body; without consent the
  // gated wrapper throws GatedProbeBlocked, captured here as a blocked rung. The
  // ladder never throws across its public boundary.
  try {
    rungs.push(await listBlobsGated(consent));
  } catch (exc) {
    if (exc instanceof GatedProbeBlocked) {
      rungs.push(
        new ProbeResult({
          name: "list-blobs",
          tier: ProbeTier.GATED,
          success: false,
          blocked: true,
          detail: `gated rung blocked: ${exc.reason}`,
          evidence: {
            reason: exc.reason,
            manual: true,
            safe_curl: LIST_BLOBS_CURL,
          },
        }),
      );
    } else {
      throw exc;
    }
  }

  // Rung 3 (SAFE, manual): the separate client-secret token redemption.
  rungs.push(servicePrincipalToken());

  return new LadderResult({
    finding,
    provider: "azure",
    verdict: verdictFrom(rungs),
    rungs,
    authorizedScope: scope,
  });
}

register(DETECTORS, (finding, consent) => azureLadder(finding, consent));
