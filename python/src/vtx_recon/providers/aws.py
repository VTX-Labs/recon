"""AWS capability ladder — prove depth of access from a leaked access key.

A TruffleHog ``AWS`` finding is an access-key id (``AKIA...`` long-term or
``ASIA...`` temporary) plus, in its ``ExtraData``, the paired secret access
key (and sometimes a session token / account / region). vtx-recon ladders
that credential with **read-only, free, non-mutating** AWS calls to prove how
deep the access goes — without ever changing state or incurring meaningful
cost.

Rungs (ordered):

  1. ``sts:GetCallerIdentity`` — SAFE. Requires *no* IAM permissions, is free,
     and changes nothing. It is the canonical "who am I" probe: it returns the
     ``Account``, ``Arn`` and ``UserId`` behind the key, which already proves
     the credential is live and reveals the principal. This is the rung that
     decides VALID vs DENIED.

  2. ``iam:GetAccountAuthorizationDetails`` — GATED. This enumerates *every*
     user, role, group and inline/managed policy in the account: a bulk PII /
     org-structure read that a bug-bounty triage should not perform without
     explicit authorization. It is unreachable unless the operator passed BOTH
     ``--prove`` and ``--i-am-authorized "<scope>"`` (see
     :mod:`vtx_recon.safety`). It is implemented behind ``@gated`` so the SAFE
     tier is *structurally* unable to call it.

Signing is AWS Signature Version 4, implemented with the standard library
(``hmac`` / ``hashlib``) — no boto3, no requests. HTTP is async via httpx.

The ladder never raises across its public boundary: every failure becomes a
``ProbeResult`` and the finding is tiered N/A / DENIED / VALID / PROVEN.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
from xml.etree import ElementTree as ET

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..redact import redact
from ..safety import Consent, ProbeTier, gated
from . import register

__all__ = ["aws_ladder", "sign_request"]

# STS is global; the classic global endpoint needs no region routing and
# GetCallerIdentity is available there for every account.
_STS_HOST = "sts.amazonaws.com"
_STS_ENDPOINT = f"https://{_STS_HOST}/"
_STS_REGION = "us-east-1"
_STS_SERVICE = "sts"

# IAM is likewise global and homed in us-east-1 for SigV4 purposes.
_IAM_HOST = "iam.amazonaws.com"
_IAM_ENDPOINT = f"https://{_IAM_HOST}/"
_IAM_REGION = "us-east-1"
_IAM_SERVICE = "iam"

_ALGORITHM = "AWS4-HMAC-SHA256"
_HTTP_TIMEOUT = 15.0

# Keys under which a TruffleHog AWS finding may carry the paired secret /
# session token in ExtraData. Matched case-insensitively.
_SECRET_KEYS = ("aws_secret_access_key", "secret", "secret_access_key", "secretkey")
_TOKEN_KEYS = ("aws_session_token", "session_token", "token", "sessiontoken")


# --------------------------------------------------------------------------- #
# SigV4 signing (stdlib only)
# --------------------------------------------------------------------------- #
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, datestamp: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key (AWS4 + date + region + service + request)."""
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sign_request(
    *,
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    host: str,
    body: str,
    session_token: str | None = None,
    now: _dt.datetime | None = None,
) -> dict[str, str]:
    """Build the SigV4 headers for a POST x-www-form-urlencoded API call.

    Pure and deterministic given ``now``; returns only the headers to send
    (it never performs I/O). ``now`` is injectable so tests can pin the
    signature. Implements the canonical-request / string-to-sign / signature
    chain exactly as AWS specifies for ``AWS4-HMAC-SHA256``.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    content_type = "application/x-www-form-urlencoded; charset=utf-8"
    payload_hash = _sha256_hex(body.encode("utf-8"))

    # Canonical (sorted, signed) headers. Including the session token in the
    # signature is required when one is present.
    canonical_headers = (
        f"content-type:{content_type}\n"
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date"
    if session_token:
        canonical_headers += f"x-amz-security-token:{session_token}\n"
        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"

    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_headers, payload_hash]
    )

    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [_ALGORITHM, amz_date, credential_scope, _sha256_hex(canonical_request.encode("utf-8"))]
    )

    signature = hmac.new(
        _signing_key(secret_key, datestamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{_ALGORITHM} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _extra_lookup(extra: dict[str, object], keys: tuple[str, ...]) -> str | None:
    """Case-insensitive lookup of the first present key with a str value."""
    lowered = {str(k).lower(): v for k, v in extra.items()}
    for key in keys:
        val = lowered.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _strip_ns(tag: str) -> str:
    """Drop an XML namespace, e.g. '{...}Arn' -> 'Arn'."""
    return tag.rsplit("}", 1)[-1]


def _parse_caller_identity(xml_text: str) -> dict[str, str]:
    """Extract Account / Arn / UserId from a GetCallerIdentity XML response."""
    out: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for el in root.iter():
        name = _strip_ns(el.tag)
        if name in ("Account", "Arn", "UserId") and el.text:
            out[name] = el.text.strip()
    return out


async def _post_signed(
    *,
    endpoint: str,
    host: str,
    region: str,
    service: str,
    body: str,
    access_key: str,
    secret_key: str,
    session_token: str | None,
    client: httpx.AsyncClient | None,
) -> httpx.Response:
    """Sign and POST an AWS query API call. Caller owns exception handling."""
    headers = sign_request(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        service=service,
        host=host,
        body=body,
        session_token=session_token,
    )
    if client is not None:
        return await client.post(endpoint, content=body, headers=headers)
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as owned:
        return await owned.post(endpoint, content=body, headers=headers)


# --------------------------------------------------------------------------- #
# rung 1 — SAFE: sts:GetCallerIdentity
# --------------------------------------------------------------------------- #
async def probe_caller_identity(
    *,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> ProbeResult:
    """SAFE rung: ``sts:GetCallerIdentity`` (free, no perms, no state change).

    Never raises: any transport/parse failure is folded into the result. A
    success proves the credential is live and surfaces the principal.
    """
    name = "sts:GetCallerIdentity"
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    try:
        resp = await _post_signed(
            endpoint=_STS_ENDPOINT,
            host=_STS_HOST,
            region=_STS_REGION,
            service=_STS_SERVICE,
            body=body,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            client=client,
        )
    except httpx.HTTPError as exc:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"transport error contacting STS: {type(exc).__name__}",
            evidence={"error": str(exc)},
        )

    if resp.status_code == 200:
        ident = _parse_caller_identity(resp.text)
        if ident:
            arn = ident.get("Arn", "?")
            return ProbeResult(
                name=name,
                tier=ProbeTier.SAFE,
                success=True,
                detail=f"credential is live; caller {arn}",
                evidence={
                    "status_code": resp.status_code,
                    "account": ident.get("Account", ""),
                    "arn": arn,
                    "user_id": ident.get("UserId", ""),
                },
            )
        # 200 but unparseable — treat as inconclusive, not live.
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail="STS returned 200 but no identity could be parsed",
            evidence={"status_code": resp.status_code},
        )

    # 403 InvalidClientTokenId / SignatureDoesNotMatch -> dead/invalid key.
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        detail=f"STS rejected the credential (HTTP {resp.status_code})",
        evidence={
            "status_code": resp.status_code,
            "aws_error": _aws_error_code(resp.text),
        },
    )


def _aws_error_code(xml_text: str) -> str:
    """Pull the <Code> out of an AWS error response, best-effort."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ""
    for el in root.iter():
        if _strip_ns(el.tag) == "Code" and el.text:
            return el.text.strip()
    return ""


# --------------------------------------------------------------------------- #
# rung 2 — GATED: iam:GetAccountAuthorizationDetails (bulk org/PII read)
# --------------------------------------------------------------------------- #
@gated
async def probe_account_authorization_details(
    consent: Consent,
    *,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> ProbeResult:
    """GATED rung: ``iam:GetAccountAuthorizationDetails``.

    Bulk-reads every IAM user/role/group/policy in the account — org-structure
    and PII disclosure. The ``@gated`` decorator enforces consent *before* this
    body runs, so it is unreachable from the safe tier and makes no request
    unless BOTH ``--prove`` and ``--i-am-authorized`` were supplied.
    """
    name = "iam:GetAccountAuthorizationDetails"
    body = "Action=GetAccountAuthorizationDetails&Version=2010-05-08"
    try:
        resp = await _post_signed(
            endpoint=_IAM_ENDPOINT,
            host=_IAM_HOST,
            region=_IAM_REGION,
            service=_IAM_SERVICE,
            body=body,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            client=client,
        )
    except httpx.HTTPError as exc:
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=False,
            detail=f"transport error contacting IAM: {type(exc).__name__}",
            evidence={"error": str(exc)},
        )

    if resp.status_code == 200:
        counts = _count_auth_details(resp.text)
        return ProbeResult(
            name=name,
            tier=ProbeTier.GATED,
            success=True,
            detail=(
                "READ the full account authorization detail: "
                f"{counts['users']} users, {counts['roles']} roles, "
                f"{counts['groups']} groups, {counts['policies']} policies"
            ),
            evidence={"status_code": resp.status_code, **counts},
        )

    return ProbeResult(
        name=name,
        tier=ProbeTier.GATED,
        success=False,
        detail=f"IAM denied the bulk read (HTTP {resp.status_code})",
        evidence={
            "status_code": resp.status_code,
            "aws_error": _aws_error_code(resp.text),
        },
    )


def _count_auth_details(xml_text: str) -> dict[str, int]:
    """Count the principals/policies in a GetAccountAuthorizationDetails body.

    Counts are non-secret aggregates only — no names/ARNs are stored, so the
    gated read's evidence cannot itself leak the enumerated PII.
    """
    counts = {"users": 0, "roles": 0, "groups": 0, "policies": 0}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return counts
    tag_to_key = {
        "UserDetailList": "users",
        "RoleDetailList": "roles",
        "GroupDetailList": "groups",
        "Policies": "policies",
    }
    for el in root.iter():
        key = tag_to_key.get(_strip_ns(el.tag))
        if key is not None:
            counts[key] = len(list(el))
    return counts


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #
def _na(finding: Finding, scope: str, detail: str) -> LadderResult:
    return LadderResult(
        finding=finding,
        provider="aws",
        verdict=Verdict.NA,
        rungs=[
            ProbeResult(
                name="aws:precondition",
                tier=ProbeTier.SAFE,
                success=False,
                detail=detail,
            )
        ],
        authorized_scope=scope,
    )


@register("AWS")
async def aws_ladder(
    finding: Finding,
    consent: Consent,
    *,
    client: httpx.AsyncClient | None = None,
) -> LadderResult:
    """Run the ordered AWS capability ladder for one finding.

    Refuses to ladder without an authorized scope (recorded in the bundle).
    Climbs the SAFE rung first; the GATED rung is attempted only via the
    safety boundary and only after a live credential is proven. Returns a
    :class:`LadderResult` and never raises across this boundary.

    The paired secret access key (and optional session token) are read from
    the finding's ``extra_data`` — TruffleHog pairs them there — and are held
    only transiently; nothing raw is stored on the result.
    """
    # Whole-ladder gate: refuse to probe without a named, authorized scope.
    scope = consent.require_ladder_scope()

    access_key = finding.raw.strip()
    secret_key = _extra_lookup(finding.extra_data, _SECRET_KEYS)
    session_token = _extra_lookup(finding.extra_data, _TOKEN_KEYS)

    if not access_key:
        return _na(finding, scope, "no access-key id present on the finding")
    if not secret_key:
        return _na(
            finding,
            scope,
            "no paired AWS secret access key in ExtraData; AWS SigV4 requires both halves to probe",
        )

    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE): who-am-I. Decides live/dead.
    identity = await probe_caller_identity(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        client=client,
    )
    rungs.append(identity)

    if not identity.success:
        # Live verification failed: the key is dead/invalid -> DENIED.
        return LadderResult(
            finding=finding,
            provider="aws",
            verdict=Verdict.DENIED,
            rungs=rungs,
            authorized_scope=scope,
        )

    # Rung 2 (GATED): bulk IAM authorization-detail read. Reachable only with
    # full consent; @gated raises GatedProbeBlocked otherwise, which we record
    # as a blocked rung rather than letting it escape.
    verdict = Verdict.VALID
    try:
        bulk = await probe_account_authorization_details(
            consent,
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            client=client,
        )
        rungs.append(bulk)
        if bulk.success:
            # A gated, state-observing PII read was actually exercised.
            verdict = Verdict.PROVEN
    except Exception as exc:  # never raise across the public boundary
        # The common case is safety.GatedProbeBlocked (no consent). Record it
        # as a blocked rung; the credential is still VALID from rung 1.
        reason = getattr(exc, "reason", str(exc))
        rungs.append(
            ProbeResult(
                name="iam:GetAccountAuthorizationDetails",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated probe blocked: {reason}",
                evidence={"blocked_reason": reason, "key_prefix": redact(access_key)},
            )
        )

    return LadderResult(
        finding=finding,
        provider="aws",
        verdict=verdict,
        rungs=rungs,
        authorized_scope=scope,
    )
