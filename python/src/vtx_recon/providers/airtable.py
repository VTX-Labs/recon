"""Capability ladder for Airtable Personal Access Tokens (``pat...``).

An Airtable PAT is a two-part ``pat<14 chars>.<64 hex>`` bearer credential
scoped to a set of OAuth-style scopes (e.g. ``data.records:read``,
``schema.bases:read``) and a set of bases. This ladder climbs three rungs,
identity first, never exercising a write:

* **whoami** (SAFE) — ``GET /v0/meta/whoami`` is the whoami + list-scopes
  call: it returns the token's user id and the scopes granted to the PAT.
  Proves the token authenticates and exactly how deep it can reach.
  Read-only, idempotent, non-billable.
* **list-bases** (SAFE) — ``GET /v0/meta/bases`` enumerates every base the
  token can reach (ids, names, permission level), measuring the blast radius
  across workspaces without touching any data. Read-only.
* **list-base-records** (GATED) — ``GET /v0/{base_id}/{table}?maxRecords=1``
  reads actual record contents from a reachable base: the underlying
  business data (which may contain third-party PII) the program cares about.
  It is GATED because it reads arbitrary stored data, and because its URL
  needs a ``{base_id}`` and ``{table}`` the engine cannot fill, it never
  auto-fires — it is emitted as a MANUAL safe-curl note (the secret rendered
  as ``$KEY``) only after the gated consent boundary is satisfied.

Every rung is ordered (identity first, then depth), READ-ONLY by default,
and never raises across the public boundary: failures become a
:class:`ProbeResult` with ``success=False`` so one dead key cannot crash a
batch run. The raw token is held only transiently for the HTTP call and only
non-secret values are ever placed in :attr:`ProbeResult.evidence`.

Docs: https://airtable.com/developers/web/api/introduction

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["airtable_ladder"]

# A single shared timeout: probes must be quick and must never hang a batch.
_TIMEOUT = httpx.Timeout(10.0)

# The exact safe curl an operator runs by hand for the gated record read. The
# live secret stays a ``$KEY`` placeholder and the unfillable ``BASE_ID`` /
# ``TABLE`` are left for the operator to substitute (from the prior
# ``list-bases`` rung and the base schema).
_LIST_BASE_RECORDS_CURL = (
    "curl -sS -X GET "
    "-H 'Authorization: Bearer $KEY' "
    "'https://api.airtable.com/v0/BASE_ID/TABLE?maxRecords=1'"
)


def _network_failure(name: str, tier: ProbeTier, exc: Exception) -> ProbeResult:
    """Turn an httpx/transport error into a non-success rung (never raise)."""
    return ProbeResult(
        name=name,
        tier=tier,
        success=False,
        detail=f"probe could not complete: {type(exc).__name__}",
        evidence={"error": type(exc).__name__},
    )


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("AirtablePersonalAccessToken")
async def airtable_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Airtable ladder: SAFE whoami -> SAFE bases -> GATED record read.

    The record read is GATED and MANUAL: it needs a ``{base_id}`` and
    ``{table}`` the engine cannot fill, so it never fires a live call even
    with consent.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    key = finding.raw

    identity = await _airtable_whoami(key)
    rungs.append(identity)

    # Only climb deeper if the token authenticated at all (ordered ladder).
    if identity.success:
        rungs.append(await _airtable_list_bases(key))

        # The record read is GATED. The @gated wrapper enforces consent BEFORE
        # any work; if consent is missing it raises GatedProbeBlocked, captured
        # here as a `blocked` rung. If consent IS granted the rung still does
        # NOT fire a live call — its URL needs a {base_id} and {table} the
        # engine cannot fill — so it returns a MANUAL safe-curl note instead.
        # The ladder never raises across the public boundary.
        try:
            rungs.append(await _airtable_list_base_records(consent, key))
        except GatedProbeBlocked as blocked:
            rungs.append(
                ProbeResult(
                    name="airtable.list-base-records",
                    tier=ProbeTier.GATED,
                    success=False,
                    blocked=True,
                    detail=f"gated record read blocked: {blocked.reason}",
                    evidence={
                        "reason": blocked.reason,
                        "manual": True,
                        "safe_curl": _LIST_BASE_RECORDS_CURL,
                    },
                )
            )

    return LadderResult(
        finding=finding,
        provider="airtable",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


async def _airtable_whoami(key: str) -> ProbeResult:
    """SAFE: ``GET /v0/meta/whoami`` is the whoami + list-scopes call.

    Confirms the token authenticates and returns its user id and the scopes
    granted to the PAT. Read-only, idempotent, non-billable.
    """
    name = "airtable.whoami"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.airtable.com/v0/meta/whoami",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"token rejected (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    scopes = [s for s in (body.get("scopes") or []) if isinstance(s, str)]
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=(
            f"authenticated as user {body.get('id')} "
            f"(scopes: {', '.join(scopes) if scopes else '(none reported)'})"
        ),
        evidence={
            "status": resp.status_code,
            "user_id": body.get("id"),
            "email": body.get("email"),
            "scopes": scopes,
        },
    )


async def _airtable_list_bases(key: str) -> ProbeResult:
    """SAFE: ``GET /v0/meta/bases`` enumerates every reachable base.

    The blast radius across workspaces (ids, names, permission level) without
    touching any data. Read-only listing of reachable resources.
    """
    name = "airtable.list-bases"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.airtable.com/v0/meta/bases",
                headers={"Authorization": f"Bearer {key}"},
            )
    except httpx.HTTPError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    if resp.status_code != 200:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"could not list bases (HTTP {resp.status_code})",
            evidence={"status": resp.status_code},
        )

    try:
        body = resp.json()
    except ValueError as exc:
        return _network_failure(name, ProbeTier.SAFE, exc)

    bases = body.get("bases") if isinstance(body, dict) else None
    bases = bases if isinstance(bases, list) else []
    # Summarise reach, do not dump: keep ids/names/permission levels only.
    names = [b.get("name") for b in bases if isinstance(b, dict) and b.get("name")]
    base_ids = [b.get("id") for b in bases if isinstance(b, dict) and b.get("id")]
    permission_levels = sorted(
        {
            b.get("permissionLevel")
            for b in bases
            if isinstance(b, dict) and b.get("permissionLevel")
        }
    )

    detail = f"token reaches {len(bases)} base(s)"
    if names:
        detail += ": " + ", ".join(str(n) for n in names[:10])
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=True,
        detail=detail,
        evidence={
            "status": resp.status_code,
            "base_count": len(bases),
            "base_ids": base_ids[:25],
            "base_names": names[:25],
            "permission_levels": permission_levels,
        },
    )


@gated
async def _airtable_list_base_records(consent: Consent, key: str) -> ProbeResult:
    """GATED + MANUAL: read actual record contents from a reachable base.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope
    it raises :class:`GatedProbeBlocked` and nothing happens. Even *with*
    consent this rung never fires a live request: its URL needs a ``{base_id}``
    (from the prior ``list-bases`` rung) and a ``{table}`` (from the base
    schema) the engine cannot fill, so it emits the copy-pasteable safe curl
    (secret as ``$KEY``) instead. This reads arbitrary stored data — the
    underlying business records, which may contain third-party PII — which is
    exactly why it is gated.
    """
    return ProbeResult(
        name="airtable.list-base-records",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL: needs a BASE_ID (from the list-bases rung) and a TABLE name "
            f"(from the base schema); run this by hand once you have them: {_LIST_BASE_RECORDS_CURL}"
        ),
        evidence={"manual": True, "safe_curl": _LIST_BASE_RECORDS_CURL},
    )
