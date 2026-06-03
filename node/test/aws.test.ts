/**
 * Tests for the AWS capability ladder — fully mocked, never hits real AWS.
 *
 *   * a valid key climbs the SAFE rung -> VALID (and -> PROVEN once the GATED
 *     rung is consented and exercised);
 *   * a dead key -> DENIED;
 *   * the GATED rung is blocked (no request made) without full consent.
 *
 * Plus: the whole ladder refuses to run without an authorized scope, the
 * provider is wired into the registry, and SigV4 signing is deterministic.
 */

import { describe, expect, it } from "vitest";
import { Finding, Verdict } from "../src/models.js";
import {
  awsLadder,
  probeAccountAuthorizationDetails,
  signRequest,
} from "../src/providers/aws.js";
import { getLadder } from "../src/providers/registry.js";
import { Consent, GatedProbeBlocked, ProbeTier, ScopeRequired } from "../src/safety.js";
import { failingFetch, mockFetch, mockResponse } from "./helpers.js";
import "../src/providers/index.js";

const CALLER_IDENTITY_OK = `<?xml version="1.0"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/leaked-ci-bot</Arn>
    <UserId>AIDAEXAMPLEUSERID</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`;

const STS_INVALID = `<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message></Error>
</ErrorResponse>`;

const IAM_AUTH_DETAILS_OK = `<?xml version="1.0"?>
<GetAccountAuthorizationDetailsResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetAccountAuthorizationDetailsResult>
    <UserDetailList>
      <member><UserName>alice</UserName></member>
      <member><UserName>bob</UserName></member>
    </UserDetailList>
    <RoleDetailList><member><RoleName>admin</RoleName></member></RoleDetailList>
    <GroupDetailList/>
    <Policies>
      <member><PolicyName>p1</PolicyName></member>
      <member><PolicyName>p2</PolicyName></member>
      <member><PolicyName>p3</PolicyName></member>
    </Policies>
  </GetAccountAuthorizationDetailsResult>
</GetAccountAuthorizationDetailsResponse>`;

const IAM_DENIED = `<?xml version="1.0"?>
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code>
    <Message>User is not authorized to perform iam:GetAccountAuthorizationDetails</Message></Error>
</ErrorResponse>`;

const ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const AUTHORIZED = new Consent({ prove: true, authorizedScope: "h1:example-program" });
const SCOPE_ONLY = new Consent({ prove: false, authorizedScope: "h1:example-program" });
const DENIED = Consent.denied();

function finding(withSecret = true): Finding {
  const extra: Record<string, unknown> = { account: "123456789012", resource_type: "Access key" };
  if (withSecret) extra["aws_secret_access_key"] = SECRET_KEY;
  return new Finding({ detectorName: "AWS", verified: true, raw: ACCESS_KEY, extraData: extra });
}

/** A fetch handler routing STS / IAM endpoints to canned XML. */
function awsFetch(opts: { sts: { status: number; xml: string }; iam?: { status: number; xml: string } }) {
  return mockFetch((call) => {
    if (call.url.startsWith("https://sts.amazonaws.com/")) {
      return mockResponse({ status: opts.sts.status, text: opts.sts.xml });
    }
    if (call.url.startsWith("https://iam.amazonaws.com/")) {
      const iam = opts.iam ?? { status: 200, xml: IAM_AUTH_DETAILS_OK };
      return mockResponse({ status: iam.status, text: iam.xml });
    }
    return mockResponse({ status: 404, text: "" });
  });
}

describe("registry wiring", () => {
  it("registers AWS case-insensitively", () => {
    expect(getLadder("AWS")).toBeTypeOf("function");
    expect(getLadder("aws")).toBeTypeOf("function");
  });
  it("tags the gated rung GATED without invoking it", () => {
    expect(probeAccountAuthorizationDetails.vtxTier).toBe(ProbeTier.GATED);
  });
});

describe("SigV4 signing (node:crypto, no aws-sdk)", () => {
  it("is deterministic and well-formed", () => {
    const fixed = new Date(Date.UTC(2026, 5, 2, 12, 0, 0));
    const opts = {
      accessKey: ACCESS_KEY,
      secretKey: SECRET_KEY,
      region: "us-east-1",
      service: "sts",
      host: "sts.amazonaws.com",
      body: "Action=GetCallerIdentity&Version=2011-06-15",
      now: fixed,
    };
    const headers = signRequest(opts);
    const again = signRequest(opts);
    expect(headers).toEqual(again);
    expect(headers["X-Amz-Date"]).toBe("20260602T120000Z");
    const auth = headers["Authorization"] ?? "";
    expect(auth.startsWith("AWS4-HMAC-SHA256 ")).toBe(true);
    expect(auth).toContain(`Credential=${ACCESS_KEY}/20260602/us-east-1/sts/aws4_request`);
    expect(auth).toContain("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date");
    // The raw secret never appears in the signing output.
    expect(auth).not.toContain(SECRET_KEY);
    expect(JSON.stringify(headers)).not.toContain(SECRET_KEY);
  });

  it("includes the session token when present", () => {
    const headers = signRequest({
      accessKey: "ASIAEXAMPLE",
      secretKey: SECRET_KEY,
      region: "us-east-1",
      service: "sts",
      host: "sts.amazonaws.com",
      body: "Action=GetCallerIdentity&Version=2011-06-15",
      sessionToken: "FwoGZXIvYXdzEXAMPLE",
      now: new Date(Date.UTC(2026, 5, 2)),
    });
    expect(headers["X-Amz-Security-Token"]).toBe("FwoGZXIvYXdzEXAMPLE");
    expect(headers["Authorization"]).toContain("x-amz-security-token");
  });
});

describe("scope gate", () => {
  it("refuses without an authorized scope", async () => {
    await expect(awsLadder(finding(), DENIED)).rejects.toBeInstanceOf(ScopeRequired);
  });
});

describe("preconditions", () => {
  it("is N/A and makes no request without a paired secret", async () => {
    const { fetchImpl, calls } = awsFetch({ sts: { status: 200, xml: CALLER_IDENTITY_OK } });
    const result = await awsLadder(finding(false), SCOPE_ONLY, { fetchImpl });
    expect(result.verdict).toBe(Verdict.NA);
    expect(calls).toHaveLength(0);
  });
});

describe("ladder behaviour", () => {
  it("valid key -> VALID without consent, and never calls IAM", async () => {
    const { fetchImpl, calls } = awsFetch({ sts: { status: 200, xml: CALLER_IDENTITY_OK } });
    const result = await awsLadder(finding(), SCOPE_ONLY, { fetchImpl });

    expect(calls.some((c) => c.url.startsWith("https://sts.amazonaws.com/"))).toBe(true);
    expect(calls.some((c) => c.url.startsWith("https://iam.amazonaws.com/"))).toBe(false);
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.authorizedScope).toBe("h1:example-program");

    const safe = result.rungs[0];
    expect(safe?.name).toBe("sts:GetCallerIdentity");
    expect(safe?.tier).toBe(ProbeTier.SAFE);
    expect(safe?.success).toBe(true);
    expect(safe?.evidence["account"]).toBe("123456789012");
    expect(String(safe?.evidence["arn"])).toContain("leaked-ci-bot");

    const gatedRung = result.rungs[1];
    expect(gatedRung?.tier).toBe(ProbeTier.GATED);
    expect(gatedRung?.blocked).toBe(true);
    expect(gatedRung?.success).toBe(false);
  });

  it("dead key -> DENIED and never escalates to IAM", async () => {
    const { fetchImpl, calls } = awsFetch({ sts: { status: 403, xml: STS_INVALID } });
    const result = await awsLadder(finding(), AUTHORIZED, { fetchImpl });
    expect(calls.some((c) => c.url.startsWith("https://iam.amazonaws.com/"))).toBe(false);
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs[0]?.success).toBe(false);
    expect(result.rungs[0]?.evidence["aws_error"]).toBe("InvalidClientTokenId");
  });

  it("full consent exercises the gated rung -> PROVEN", async () => {
    const { fetchImpl, calls } = awsFetch({
      sts: { status: 200, xml: CALLER_IDENTITY_OK },
      iam: { status: 200, xml: IAM_AUTH_DETAILS_OK },
    });
    const result = await awsLadder(finding(), AUTHORIZED, { fetchImpl });
    expect(calls.some((c) => c.url.startsWith("https://iam.amazonaws.com/"))).toBe(true);
    expect(result.verdict).toBe(Verdict.PROVEN);
    const gatedRung = result.rungs[1];
    expect(gatedRung?.blocked).toBe(false);
    expect(gatedRung?.success).toBe(true);
    expect(gatedRung?.evidence["users"]).toBe(2);
    expect(gatedRung?.evidence["roles"]).toBe(1);
    expect(gatedRung?.evidence["groups"]).toBe(0);
    expect(gatedRung?.evidence["policies"]).toBe(3);
  });

  it("full consent but IAM denied stays VALID", async () => {
    const { fetchImpl } = awsFetch({
      sts: { status: 200, xml: CALLER_IDENTITY_OK },
      iam: { status: 403, xml: IAM_DENIED },
    });
    const result = await awsLadder(finding(), AUTHORIZED, { fetchImpl });
    expect(result.verdict).toBe(Verdict.VALID);
    expect(result.rungs[1]?.success).toBe(false);
    expect(result.rungs[1]?.evidence["aws_error"]).toBe("AccessDenied");
  });

  it("transport error is DENIED, not raised", async () => {
    const { fetchImpl } = failingFetch("network down");
    const result = await awsLadder(finding(), SCOPE_ONLY, { fetchImpl });
    expect(result.verdict).toBe(Verdict.DENIED);
    expect(result.rungs[0]?.success).toBe(false);
    expect(result.rungs[0]?.detail).toContain("transport error");
  });

  it("never leaks the raw secret or access-key id into the public result", async () => {
    const { fetchImpl } = awsFetch({
      sts: { status: 200, xml: CALLER_IDENTITY_OK },
      iam: { status: 200, xml: IAM_AUTH_DETAILS_OK },
    });
    const result = await awsLadder(finding(), AUTHORIZED, { fetchImpl });
    const blob = JSON.stringify(result.toPublic());
    expect(blob).not.toContain(SECRET_KEY);
    expect(blob).not.toContain(ACCESS_KEY);
  });
});

describe("gated rung is structurally unreachable without consent", () => {
  it("blocks before any request with denied consent", async () => {
    const { fetchImpl, calls } = awsFetch({ sts: { status: 200, xml: CALLER_IDENTITY_OK } });
    await expect(
      probeAccountAuthorizationDetails(DENIED, {
        accessKey: ACCESS_KEY,
        secretKey: SECRET_KEY,
        fetchImpl,
      }),
    ).rejects.toBeInstanceOf(GatedProbeBlocked);
    expect(calls.some((c) => c.url.startsWith("https://iam.amazonaws.com/"))).toBe(false);
  });

  it("blocks with --prove but no scope", async () => {
    const { fetchImpl, calls } = awsFetch({ sts: { status: 200, xml: CALLER_IDENTITY_OK } });
    await expect(
      probeAccountAuthorizationDetails(new Consent({ prove: true, authorizedScope: null }), {
        accessKey: ACCESS_KEY,
        secretKey: SECRET_KEY,
        fetchImpl,
      }),
    ).rejects.toBeInstanceOf(GatedProbeBlocked);
    expect(calls.some((c) => c.url.startsWith("https://iam.amazonaws.com/"))).toBe(false);
  });
});
