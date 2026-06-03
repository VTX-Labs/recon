"""Tests for the AWS capability ladder — fully mocked, never hits real AWS.

HTTP is intercepted with respx so no network call leaves the test process.
We cover the three behaviours the spec calls out:

  * a valid key climbs the SAFE rung -> VALID (and -> PROVEN once the GATED
    rung is consented and exercised);
  * a dead key -> DENIED;
  * the GATED rung is blocked (no request made) without full consent.

Plus: the whole ladder refuses to run without an authorized scope, the
provider is wired into the registry, and SigV4 signing is deterministic.
"""

from __future__ import annotations

import datetime as _dt

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import aws as aws_mod
from vtx_recon.providers import get_ladder
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

# --- canned AWS XML responses ---------------------------------------------- #

_CALLER_IDENTITY_OK = """<?xml version="1.0"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/leaked-ci-bot</Arn>
    <UserId>AIDAEXAMPLEUSERID</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"""

_STS_INVALID = """<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
</ErrorResponse>"""

_IAM_AUTH_DETAILS_OK = """<?xml version="1.0"?>
<GetAccountAuthorizationDetailsResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetAccountAuthorizationDetailsResult>
    <UserDetailList>
      <member><UserName>alice</UserName></member>
      <member><UserName>bob</UserName></member>
    </UserDetailList>
    <RoleDetailList>
      <member><RoleName>admin</RoleName></member>
    </RoleDetailList>
    <GroupDetailList/>
    <Policies>
      <member><PolicyName>p1</PolicyName></member>
      <member><PolicyName>p2</PolicyName></member>
      <member><PolicyName>p3</PolicyName></member>
    </Policies>
  </GetAccountAuthorizationDetailsResult>
</GetAccountAuthorizationDetailsResponse>"""

_IAM_DENIED = """<?xml version="1.0"?>
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User is not authorized to perform iam:GetAccountAuthorizationDetails</Message>
  </Error>
</ErrorResponse>"""

_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

_AUTHORIZED = Consent(prove=True, authorized_scope="h1:example-program")
_SCOPE_ONLY = Consent(prove=False, authorized_scope="h1:example-program")
_DENIED = Consent.denied()


def _finding(*, with_secret: bool = True) -> Finding:
    extra: dict[str, object] = {"account": "123456789012", "resource_type": "Access key"}
    if with_secret:
        extra["aws_secret_access_key"] = _SECRET_KEY
    return Finding(
        detector_name="AWS",
        verified=True,
        raw=_ACCESS_KEY,
        extra_data=extra,
    )


# --------------------------------------------------------------------------- #
# registry wiring
# --------------------------------------------------------------------------- #
def test_provider_registered_for_aws_detector() -> None:
    assert get_ladder("AWS") is aws_mod.aws_ladder
    # Case-insensitive routing.
    assert get_ladder("aws") is aws_mod.aws_ladder


def test_gated_rung_is_tagged_gated() -> None:
    # The gated rung must advertise its tier without being invoked.
    assert aws_mod.probe_account_authorization_details.__vtx_tier__ is ProbeTier.GATED


# --------------------------------------------------------------------------- #
# SigV4 signing is deterministic and well-formed (stdlib, no boto3)
# --------------------------------------------------------------------------- #
def test_sign_request_is_deterministic_and_signed() -> None:
    fixed = _dt.datetime(2026, 6, 2, 12, 0, 0, tzinfo=_dt.timezone.utc)
    headers = aws_mod.sign_request(
        access_key=_ACCESS_KEY,
        secret_key=_SECRET_KEY,
        region="us-east-1",
        service="sts",
        host="sts.amazonaws.com",
        body="Action=GetCallerIdentity&Version=2011-06-15",
        now=fixed,
    )
    again = aws_mod.sign_request(
        access_key=_ACCESS_KEY,
        secret_key=_SECRET_KEY,
        region="us-east-1",
        service="sts",
        host="sts.amazonaws.com",
        body="Action=GetCallerIdentity&Version=2011-06-15",
        now=fixed,
    )
    assert headers == again  # deterministic given a fixed clock
    assert headers["X-Amz-Date"] == "20260602T120000Z"
    auth = headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert f"Credential={_ACCESS_KEY}/20260602/us-east-1/sts/aws4_request" in auth
    assert "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date" in auth
    # The raw secret never appears in the signing output.
    assert _SECRET_KEY not in auth
    assert _SECRET_KEY not in str(headers)


def test_sign_request_includes_session_token_when_present() -> None:
    headers = aws_mod.sign_request(
        access_key="ASIAEXAMPLE",
        secret_key=_SECRET_KEY,
        region="us-east-1",
        service="sts",
        host="sts.amazonaws.com",
        body="Action=GetCallerIdentity&Version=2011-06-15",
        session_token="FwoGZXIvYXdzEXAMPLE",
        now=_dt.datetime(2026, 6, 2, tzinfo=_dt.timezone.utc),
    )
    assert headers["X-Amz-Security-Token"] == "FwoGZXIvYXdzEXAMPLE"
    assert "x-amz-security-token" in headers["Authorization"]


# --------------------------------------------------------------------------- #
# whole-ladder scope gate
# --------------------------------------------------------------------------- #
async def test_ladder_refuses_without_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await aws_mod.aws_ladder(_finding(), _DENIED)


# --------------------------------------------------------------------------- #
# N/A: no paired secret to sign with
# --------------------------------------------------------------------------- #
@respx.mock
async def test_no_paired_secret_is_na_and_makes_no_request() -> None:
    route = respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_CALLER_IDENTITY_OK)
    )
    result = await aws_mod.aws_ladder(_finding(with_secret=False), _SCOPE_ONLY)
    assert result.verdict is Verdict.NA
    assert not route.called  # never signed/sent without both halves


# --------------------------------------------------------------------------- #
# valid key climbs the SAFE rung
# --------------------------------------------------------------------------- #
@respx.mock
async def test_valid_key_safe_rung_yields_valid_without_consent() -> None:
    sts = respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_CALLER_IDENTITY_OK)
    )
    # No consent for the gated rung -> the ladder must not call IAM at all.
    iam = respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_IAM_AUTH_DETAILS_OK)
    )

    result = await aws_mod.aws_ladder(_finding(), _SCOPE_ONLY)

    assert sts.called
    assert not iam.called  # gated rung blocked before any IAM request
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == "h1:example-program"

    safe = result.rungs[0]
    assert safe.name == "sts:GetCallerIdentity"
    assert safe.tier is ProbeTier.SAFE
    assert safe.success is True
    assert safe.evidence["account"] == "123456789012"
    assert "leaked-ci-bot" in str(safe.evidence["arn"])

    gated_rung = result.rungs[1]
    assert gated_rung.tier is ProbeTier.GATED
    assert gated_rung.blocked is True
    assert gated_rung.success is False


# --------------------------------------------------------------------------- #
# dead key -> DENIED
# --------------------------------------------------------------------------- #
@respx.mock
async def test_dead_key_is_denied() -> None:
    sts = respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(403, text=_STS_INVALID)
    )
    iam = respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_IAM_AUTH_DETAILS_OK)
    )

    result = await aws_mod.aws_ladder(_finding(), _AUTHORIZED)

    assert sts.called
    assert not iam.called  # never escalate past a dead credential
    assert result.verdict is Verdict.DENIED
    rung = result.rungs[0]
    assert rung.success is False
    assert rung.evidence["aws_error"] == "InvalidClientTokenId"


# --------------------------------------------------------------------------- #
# gated rung is exercised under full consent -> PROVEN
# --------------------------------------------------------------------------- #
@respx.mock
async def test_full_consent_exercises_gated_rung_to_proven() -> None:
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_CALLER_IDENTITY_OK)
    )
    iam = respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_IAM_AUTH_DETAILS_OK)
    )

    result = await aws_mod.aws_ladder(_finding(), _AUTHORIZED)

    assert iam.called  # consent granted -> gated rung actually runs
    assert result.verdict is Verdict.PROVEN
    gated_rung = result.rungs[1]
    assert gated_rung.tier is ProbeTier.GATED
    assert gated_rung.blocked is False
    assert gated_rung.success is True
    assert gated_rung.evidence["users"] == 2
    assert gated_rung.evidence["roles"] == 1
    assert gated_rung.evidence["groups"] == 0
    assert gated_rung.evidence["policies"] == 3


@respx.mock
async def test_full_consent_but_iam_denied_stays_valid() -> None:
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_CALLER_IDENTITY_OK)
    )
    respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(403, text=_IAM_DENIED)
    )

    result = await aws_mod.aws_ladder(_finding(), _AUTHORIZED)

    # Gated rung ran but was refused by IAM: credential is VALID, not PROVEN.
    assert result.verdict is Verdict.VALID
    gated_rung = result.rungs[1]
    assert gated_rung.success is False
    assert gated_rung.evidence["aws_error"] == "AccessDenied"


# --------------------------------------------------------------------------- #
# the gated rung is STRUCTURALLY unreachable without consent
# --------------------------------------------------------------------------- #
@respx.mock
async def test_gated_probe_blocks_before_any_request_without_consent() -> None:
    iam = respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_IAM_AUTH_DETAILS_OK)
    )
    # Calling the gated rung directly with denied consent must raise before
    # any HTTP call is signed or sent.
    with pytest.raises(GatedProbeBlocked):
        await aws_mod.probe_account_authorization_details(
            _DENIED,
            access_key=_ACCESS_KEY,
            secret_key=_SECRET_KEY,
        )
    assert not iam.called


@respx.mock
async def test_gated_probe_blocks_with_prove_but_no_scope() -> None:
    iam = respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_IAM_AUTH_DETAILS_OK)
    )
    # --prove alone (no authorized scope) is not enough.
    with pytest.raises(GatedProbeBlocked):
        await aws_mod.probe_account_authorization_details(
            Consent(prove=True, authorized_scope=None),
            access_key=_ACCESS_KEY,
            secret_key=_SECRET_KEY,
        )
    assert not iam.called


# --------------------------------------------------------------------------- #
# transport failure never escapes the ladder boundary
# --------------------------------------------------------------------------- #
@respx.mock
async def test_transport_error_is_denied_not_raised() -> None:
    respx.post("https://sts.amazonaws.com/").mock(side_effect=httpx.ConnectError("network down"))
    result = await aws_mod.aws_ladder(_finding(), _SCOPE_ONLY)
    assert result.verdict is Verdict.DENIED
    assert result.rungs[0].success is False
    assert "transport error" in result.rungs[0].detail


# --------------------------------------------------------------------------- #
# redaction: no raw secret leaks into the serialised evidence
# --------------------------------------------------------------------------- #
@respx.mock
async def test_no_raw_secret_in_public_result() -> None:
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_CALLER_IDENTITY_OK)
    )
    respx.post("https://iam.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=_IAM_AUTH_DETAILS_OK)
    )
    result = await aws_mod.aws_ladder(_finding(), _AUTHORIZED)
    blob = repr(result.to_public())
    assert _SECRET_KEY not in blob
    assert _ACCESS_KEY not in blob  # the access-key id is redacted too
