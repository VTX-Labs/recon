/**
 * AWS capability ladder — prove depth of access from a leaked access key.
 *
 * A TruffleHog `AWS` finding is an access-key id (`AKIA...` long-term or
 * `ASIA...` temporary) plus, in its `ExtraData`, the paired secret access key
 * (and sometimes a session token / account / region). vtx-recon ladders that
 * credential with **read-only, free, non-mutating** AWS calls to prove how deep
 * the access goes — without ever changing state or incurring meaningful cost.
 *
 * Rungs (ordered):
 *
 *   1. `sts:GetCallerIdentity` — SAFE. Requires *no* IAM permissions, is free,
 *      and changes nothing. The canonical "who am I" probe: returns the
 *      `Account`, `Arn` and `UserId` behind the key, proving the credential is
 *      live and revealing the principal. Decides VALID vs DENIED.
 *
 *   2. `iam:GetAccountAuthorizationDetails` — GATED. Enumerates *every* user,
 *      role, group and inline/managed policy in the account: a bulk PII /
 *      org-structure read. Unreachable unless the operator passed BOTH
 *      `--prove` and `--i-am-authorized "<scope>"`. Implemented behind
 *      {@link gated} so the SAFE tier is *structurally* unable to call it.
 *
 * Signing is AWS Signature Version 4, implemented with `node:crypto` — no
 * aws-sdk, no axios. HTTP is the built-in `fetch`.
 *
 * The ladder never throws across its public boundary: every failure becomes a
 * `ProbeResult` and the finding is tiered N/A / DENIED / VALID / PROVEN.
 *
 * AUTHORIZED USE ONLY. See TERMS.md.
 */

import { createHash, createHmac } from "node:crypto";
import { Finding, LadderResult, ProbeResult, Verdict } from "../models.js";
import { redact } from "../redact.js";
import { Consent, GatedProbeBlocked, ProbeTier, gated } from "../safety.js";
import { HttpError, httpRequest, type FetchLike } from "./http.js";
import { register } from "./registry.js";

// STS is global; the classic global endpoint needs no region routing and
// GetCallerIdentity is available there for every account.
const STS_HOST = "sts.amazonaws.com";
const STS_ENDPOINT = `https://${STS_HOST}/`;
const STS_REGION = "us-east-1";
const STS_SERVICE = "sts";

// IAM is likewise global and homed in us-east-1 for SigV4 purposes.
const IAM_HOST = "iam.amazonaws.com";
const IAM_ENDPOINT = `https://${IAM_HOST}/`;
const IAM_REGION = "us-east-1";
const IAM_SERVICE = "iam";

const ALGORITHM = "AWS4-HMAC-SHA256";
const HTTP_TIMEOUT_MS = 15_000;

// Keys under which a TruffleHog AWS finding may carry the paired secret /
// session token in ExtraData. Matched case-insensitively.
const SECRET_KEYS = ["aws_secret_access_key", "secret", "secret_access_key", "secretkey"];
const TOKEN_KEYS = ["aws_session_token", "session_token", "token", "sessiontoken"];

// --------------------------------------------------------------------------- //
// SigV4 signing (node:crypto only)
// --------------------------------------------------------------------------- //
function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: string | Uint8Array, msg: string): Buffer {
  return createHmac("sha256", key).update(msg, "utf8").digest();
}

/** Derive the SigV4 signing key (AWS4 + date + region + service + request). */
function signingKey(secretKey: string, datestamp: string, region: string, service: string): Buffer {
  const kDate = hmac(`AWS4${secretKey}`, datestamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

export interface SignRequestOptions {
  accessKey: string;
  secretKey: string;
  region: string;
  service: string;
  host: string;
  body: string;
  sessionToken?: string | null;
  /** Injectable clock so tests can pin the signature. */
  now?: Date;
}

/**
 * Build the SigV4 headers for a POST x-www-form-urlencoded API call.
 *
 * Pure and deterministic given `now`; returns only the headers to send (it
 * never performs I/O). `now` is injectable so tests can pin the signature.
 * Implements the canonical-request / string-to-sign / signature chain exactly
 * as AWS specifies for `AWS4-HMAC-SHA256`.
 */
export function signRequest(options: SignRequestOptions): Record<string, string> {
  const { accessKey, secretKey, region, service, host, body } = options;
  const sessionToken = options.sessionToken ?? null;
  const now = options.now ?? new Date();

  const amzDate = formatAmzDate(now);
  const datestamp = amzDate.slice(0, 8);

  const contentType = "application/x-www-form-urlencoded; charset=utf-8";
  const payloadHash = sha256Hex(body);

  // Canonical (sorted, signed) headers. Including the session token in the
  // signature is required when one is present.
  let canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;
  let signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
  if (sessionToken) {
    canonicalHeaders += `x-amz-security-token:${sessionToken}\n`;
    signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
  }

  const canonicalRequest = ["POST", "/", "", canonicalHeaders, signedHeaders, payloadHash].join(
    "\n",
  );

  const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    ALGORITHM,
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const signature = createHmac("sha256", signingKey(secretKey, datestamp, region, service))
    .update(stringToSign, "utf8")
    .digest("hex");

  const authorization =
    `${ALGORITHM} Credential=${accessKey}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers: Record<string, string> = {
    "Content-Type": contentType,
    Host: host,
    "X-Amz-Content-Sha256": payloadHash,
    "X-Amz-Date": amzDate,
    Authorization: authorization,
  };
  if (sessionToken) {
    headers["X-Amz-Security-Token"] = sessionToken;
  }
  return headers;
}

/** Format a Date as the AWS `%Y%m%dT%H%M%SZ` basic-ISO timestamp (UTC). */
function formatAmzDate(date: Date): string {
  const iso = date.toISOString(); // 2026-06-02T12:00:00.000Z
  return iso.replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

// --------------------------------------------------------------------------- //
// helpers
// --------------------------------------------------------------------------- //
/** Case-insensitive lookup of the first present key with a non-empty string value. */
function extraLookup(extra: Record<string, unknown>, keys: string[]): string | null {
  const lowered: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(extra)) {
    lowered[k.toLowerCase()] = v;
  }
  for (const key of keys) {
    const val = lowered[key];
    if (typeof val === "string" && val) {
      return val;
    }
  }
  return null;
}

/**
 * Extract the text content of the first occurrence of each named element from
 * an AWS XML response (namespace-insensitive). Minimal, dependency-free — AWS
 * query-API XML is simple and flat enough that a regex per tag is sufficient.
 */
function extractTags(xmlText: string, tags: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of tags) {
    // Match `<Tag>...<` or `<ns:Tag>...<`, capturing inner text up to the next tag.
    const re = new RegExp(`<(?:[\\w-]+:)?${tag}>([^<]*)</(?:[\\w-]+:)?${tag}>`);
    const m = re.exec(xmlText);
    if (m && m[1] !== undefined) {
      out[tag] = m[1].trim();
    }
  }
  return out;
}

/** Pull the <Code> out of an AWS error response, best-effort. */
function awsErrorCode(xmlText: string): string {
  return extractTags(xmlText, ["Code"])["Code"] ?? "";
}

/**
 * Count the principals/policies in a GetAccountAuthorizationDetails body.
 *
 * Counts are non-secret aggregates only — no names/ARNs are stored, so the
 * gated read's evidence cannot itself leak the enumerated PII.
 */
function countAuthDetails(xmlText: string): Record<string, number> {
  const counts: Record<string, number> = { users: 0, roles: 0, groups: 0, policies: 0 };
  const tagToKey: Record<string, string> = {
    UserDetailList: "users",
    RoleDetailList: "roles",
    GroupDetailList: "groups",
    Policies: "policies",
  };
  for (const [tag, key] of Object.entries(tagToKey)) {
    // Count the <member> children inside the named list element.
    const listRe = new RegExp(
      `<(?:[\\w-]+:)?${tag}>([\\s\\S]*?)</(?:[\\w-]+:)?${tag}>`,
    );
    const m = listRe.exec(xmlText);
    if (m && m[1] !== undefined) {
      const members = m[1].match(/<(?:[\w-]+:)?member[\s>]/g);
      counts[key] = members ? members.length : 0;
    }
  }
  return counts;
}

/** Sign and POST an AWS query API call. Caller owns exception handling. */
async function postSigned(args: {
  endpoint: string;
  host: string;
  region: string;
  service: string;
  body: string;
  accessKey: string;
  secretKey: string;
  sessionToken: string | null;
  fetchImpl: FetchLike | undefined;
}): Promise<Response> {
  const headers = signRequest({
    accessKey: args.accessKey,
    secretKey: args.secretKey,
    region: args.region,
    service: args.service,
    host: args.host,
    body: args.body,
    sessionToken: args.sessionToken,
  });
  return httpRequest(args.endpoint, {
    method: "POST",
    headers,
    body: args.body,
    timeoutMs: HTTP_TIMEOUT_MS,
    fetchImpl: args.fetchImpl,
  });
}

// --------------------------------------------------------------------------- //
// rung 1 — SAFE: sts:GetCallerIdentity
// --------------------------------------------------------------------------- //
/**
 * SAFE rung: `sts:GetCallerIdentity` (free, no perms, no state change). Never
 * throws: any transport/parse failure is folded into the result. Success
 * proves the credential is live and surfaces the principal.
 */
export async function probeCallerIdentity(args: {
  accessKey: string;
  secretKey: string;
  sessionToken?: string | null | undefined;
  fetchImpl?: FetchLike | undefined;
}): Promise<ProbeResult> {
  const name = "sts:GetCallerIdentity";
  const body = "Action=GetCallerIdentity&Version=2011-06-15";
  let resp: Response;
  try {
    resp = await postSigned({
      endpoint: STS_ENDPOINT,
      host: STS_HOST,
      region: STS_REGION,
      service: STS_SERVICE,
      body,
      accessKey: args.accessKey,
      secretKey: args.secretKey,
      sessionToken: args.sessionToken ?? null,
      fetchImpl: args.fetchImpl,
    });
  } catch (exc) {
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: `transport error contacting STS: ${errName(exc)}`,
      evidence: { error: errMessage(exc) },
    });
  }

  const text = await resp.text().catch(() => "");
  if (resp.status === 200) {
    const ident = extractTags(text, ["Account", "Arn", "UserId"]);
    if (Object.keys(ident).length > 0) {
      const arn = ident["Arn"] ?? "?";
      return new ProbeResult({
        name,
        tier: ProbeTier.SAFE,
        success: true,
        detail: `credential is live; caller ${arn}`,
        evidence: {
          status_code: resp.status,
          account: ident["Account"] ?? "",
          arn,
          user_id: ident["UserId"] ?? "",
        },
      });
    }
    // 200 but unparseable — treat as inconclusive, not live.
    return new ProbeResult({
      name,
      tier: ProbeTier.SAFE,
      success: false,
      detail: "STS returned 200 but no identity could be parsed",
      evidence: { status_code: resp.status },
    });
  }

  // 403 InvalidClientTokenId / SignatureDoesNotMatch -> dead/invalid key.
  return new ProbeResult({
    name,
    tier: ProbeTier.SAFE,
    success: false,
    detail: `STS rejected the credential (HTTP ${resp.status})`,
    evidence: { status_code: resp.status, aws_error: awsErrorCode(text) },
  });
}

// --------------------------------------------------------------------------- //
// rung 2 — GATED: iam:GetAccountAuthorizationDetails (bulk org/PII read)
// --------------------------------------------------------------------------- //
/**
 * GATED rung: `iam:GetAccountAuthorizationDetails`.
 *
 * Bulk-reads every IAM user/role/group/policy in the account — org-structure
 * and PII disclosure. The {@link gated} wrapper enforces consent *before* this
 * body runs, so it is unreachable from the safe tier and makes no request
 * unless BOTH `--prove` and `--i-am-authorized` were supplied.
 */
export const probeAccountAuthorizationDetails = gated(
  "aws.probe_account_authorization_details",
  async (
    _consent: Consent,
    args: {
      accessKey: string;
      secretKey: string;
      sessionToken?: string | null | undefined;
      fetchImpl?: FetchLike | undefined;
    },
  ): Promise<ProbeResult> => {
    const name = "iam:GetAccountAuthorizationDetails";
    const body = "Action=GetAccountAuthorizationDetails&Version=2010-05-08";
    let resp: Response;
    try {
      resp = await postSigned({
        endpoint: IAM_ENDPOINT,
        host: IAM_HOST,
        region: IAM_REGION,
        service: IAM_SERVICE,
        body,
        accessKey: args.accessKey,
        secretKey: args.secretKey,
        sessionToken: args.sessionToken ?? null,
        fetchImpl: args.fetchImpl,
      });
    } catch (exc) {
      return new ProbeResult({
        name,
        tier: ProbeTier.GATED,
        success: false,
        detail: `transport error contacting IAM: ${errName(exc)}`,
        evidence: { error: errMessage(exc) },
      });
    }

    const text = await resp.text().catch(() => "");
    if (resp.status === 200) {
      const counts = countAuthDetails(text);
      return new ProbeResult({
        name,
        tier: ProbeTier.GATED,
        success: true,
        detail:
          "READ the full account authorization detail: " +
          `${counts["users"]} users, ${counts["roles"]} roles, ` +
          `${counts["groups"]} groups, ${counts["policies"]} policies`,
        evidence: { status_code: resp.status, ...counts },
      });
    }

    return new ProbeResult({
      name,
      tier: ProbeTier.GATED,
      success: false,
      detail: `IAM denied the bulk read (HTTP ${resp.status})`,
      evidence: { status_code: resp.status, aws_error: awsErrorCode(text) },
    });
  },
);

// --------------------------------------------------------------------------- //
// the ladder
// --------------------------------------------------------------------------- //
function na(finding: Finding, scope: string, detail: string): LadderResult {
  return new LadderResult({
    finding,
    provider: "aws",
    verdict: Verdict.NA,
    rungs: [new ProbeResult({ name: "aws:precondition", tier: ProbeTier.SAFE, success: false, detail })],
    authorizedScope: scope,
  });
}

/**
 * Run the ordered AWS capability ladder for one finding.
 *
 * Refuses to ladder without an authorized scope (recorded in the bundle).
 * Climbs the SAFE rung first; the GATED rung is attempted only via the safety
 * boundary and only after a live credential is proven. Returns a
 * {@link LadderResult} and never throws across this boundary.
 */
export async function awsLadder(
  finding: Finding,
  consent: Consent,
  options: { fetchImpl?: FetchLike } = {},
): Promise<LadderResult> {
  // Whole-ladder gate: refuse to probe without a named, authorized scope.
  const scope = consent.requireLadderScope();
  const fetchImpl = options.fetchImpl;

  const accessKey = finding.raw.trim();
  const secretKey = extraLookup(finding.extraData, SECRET_KEYS);
  const sessionToken = extraLookup(finding.extraData, TOKEN_KEYS);

  if (!accessKey) {
    return na(finding, scope, "no access-key id present on the finding");
  }
  if (!secretKey) {
    return na(
      finding,
      scope,
      "no paired AWS secret access key in ExtraData; AWS SigV4 requires both halves to probe",
    );
  }

  const rungs: ProbeResult[] = [];

  // Rung 1 (SAFE): who-am-I. Decides live/dead.
  const identity = await probeCallerIdentity({ accessKey, secretKey, sessionToken, fetchImpl });
  rungs.push(identity);

  if (!identity.success) {
    // Live verification failed: the key is dead/invalid -> DENIED.
    return new LadderResult({
      finding,
      provider: "aws",
      verdict: Verdict.DENIED,
      rungs,
      authorizedScope: scope,
    });
  }

  // Rung 2 (GATED): bulk IAM authorization-detail read. Reachable only with
  // full consent; the gated wrapper throws GatedProbeBlocked otherwise, which
  // we record as a blocked rung rather than letting it escape.
  let verdict = Verdict.VALID;
  try {
    const bulk = await probeAccountAuthorizationDetails(consent, {
      accessKey,
      secretKey,
      sessionToken,
      fetchImpl,
    });
    rungs.push(bulk);
    if (bulk.success) {
      // A gated, state-observing PII read was actually exercised.
      verdict = Verdict.PROVEN;
    }
  } catch (exc) {
    // never throw across the public boundary. The common case is
    // GatedProbeBlocked (no consent). Record it as a blocked rung; the
    // credential is still VALID from rung 1.
    const reason = exc instanceof GatedProbeBlocked ? exc.reason : errMessage(exc);
    rungs.push(
      new ProbeResult({
        name: "iam:GetAccountAuthorizationDetails",
        tier: ProbeTier.GATED,
        success: false,
        blocked: true,
        detail: `gated probe blocked: ${reason}`,
        evidence: { blocked_reason: reason, key_prefix: redact(accessKey) },
      }),
    );
  }

  return new LadderResult({ finding, provider: "aws", verdict, rungs, authorizedScope: scope });
}

register(["AWS"], (finding, consent) => awsLadder(finding, consent));

function errName(exc: unknown): string {
  if (exc instanceof HttpError) return exc.kind;
  return exc instanceof Error ? exc.constructor.name : "Error";
}

function errMessage(exc: unknown): string {
  return exc instanceof Error ? exc.message : String(exc);
}
