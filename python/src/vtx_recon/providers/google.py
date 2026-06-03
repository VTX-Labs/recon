"""Capability ladder for Google AI / Gemini API keys (``AIza...``).

A Google AI Studio / Gemini key authenticates via the ``x-goog-api-key``
header against the Generative Language API (``generativelanguage.googleapis.com``,
``v1beta``). This module proves *depth of access* with an ordered ladder of
READ-ONLY rungs, then — only behind the safety boundary — offers the gated,
impactful rungs that cost the target money, read/write PII, or create state.

SAFE rungs (run by default, read-only, non-billable, idempotent):

  1. ``ListModels``        ``GET v1beta/models``          — key authenticates.
  2. ``ListFiles``         ``GET v1beta/files``           — Files API readable.
  3. ``ListCachedContents````GET v1beta/cachedContents``  — cache readable.
  4. ``ListCorpora``       ``GET v1beta/corpora``         — semantic-retrieval
                                                           corpora readable
                                                           (data-read proof).

If a rung returns ``403`` with an API-key/referer restriction, the safe tier
makes ONE more read-only attempt with a spoofed ``Referer`` header
(``ListModels`` again) to demonstrate that an HTTP-referer-restricted key can
still be exercised from a forged origin. This is still a read-only ``GET`` —
it never escalates tier.

GATED rungs (UNREACHABLE without BOTH ``--prove`` and
``--i-am-authorized "<scope>"``; see :mod:`vtx_recon.safety`):

  * ``GenerateContent``       ``POST v1beta/models/...:generateContent`` —
                              billable inference, exercises real impact.
  * ``UploadFile``            ``POST .../upload/v1beta/files`` — creates a
                              resource (state change).
  * ``MapsBillableProbe``     a billable Google Maps Platform call.
  * ``FirebaseAnonSignup``    Identity Toolkit ``accounts:signUp`` — creates
                              an anonymous auth user (state change).

The public entry point is :func:`google_ladder`; it never raises across its
boundary — every failure (dead key, network error, blocked gated rung) is
captured as a :class:`ProbeResult` / reflected in the :class:`Verdict`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, ProbeTier, gated
from . import register

__all__ = ["google_ladder"]

# Generative Language API base. v1beta is where models/files/cachedContents/
# corpora live, per the confirmed API facts.
_GLA_BASE = "https://generativelanguage.googleapis.com/v1beta"
_API_KEY_HEADER = "x-goog-api-key"
# A forged origin used only to demonstrate that an HTTP-referer-restricted
# key is still exercisable. Never a real target domain.
_SPOOFED_REFERER = "https://localhost/"
# A cheap, widely available model for the (gated) generateContent probe.
_GATED_MODEL = "models/gemini-1.5-flash-latest"
_TIMEOUT = httpx.Timeout(15.0)


def _headers(raw_key: str, *, referer: str | None = None) -> dict[str, str]:
    """Build request headers, keeping the raw key out of any evidence."""
    headers = {_API_KEY_HEADER: raw_key}
    if referer is not None:
        headers["Referer"] = referer
    return headers


def _is_referer_restricted(resp: httpx.Response) -> bool:
    """True if a 403 looks like an API-key / HTTP-referer restriction.

    Google returns 403 with a ``API_KEY_HTTP_REFERRER_BLOCKED`` reason (or
    text mentioning referer/referrer) when a browser-key restriction rejects
    the request. We only attempt the read-only referer bypass for those.
    """
    if resp.status_code != 403:
        return False
    body = resp.text.lower()
    return "referer" in body or "referrer" in body or "api_key_http" in body


async def _safe_list(
    client: httpx.AsyncClient,
    *,
    name: str,
    path: str,
    raw_key: str,
) -> ProbeResult:
    """Run one read-only ``GET`` list rung and capture non-secret evidence.

    Never raises: transport/timeout errors are folded into a failed
    :class:`ProbeResult` so the ladder keeps climbing.
    """
    url = f"{_GLA_BASE}/{path}"
    try:
        resp = await client.get(url, headers=_headers(raw_key))
    except httpx.HTTPError as exc:
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"request failed: {type(exc).__name__}",
            evidence={"path": path, "error": str(exc)},
        )

    evidence: dict[str, object] = {"path": path, "status": resp.status_code}
    if resp.is_success:
        # Count items without storing payloads (they may carry data).
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        count = _count_items(payload)
        if count is not None:
            evidence["item_count"] = count
        return ProbeResult(
            name=name,
            tier=ProbeTier.SAFE,
            success=True,
            detail=f"{name} OK ({resp.status_code})"
            + (f", {count} item(s)" if count is not None else ""),
            evidence=evidence,
        )

    evidence["referer_restricted"] = _is_referer_restricted(resp)
    return ProbeResult(
        name=name,
        tier=ProbeTier.SAFE,
        success=False,
        detail=f"{name} denied ({resp.status_code})",
        evidence=evidence,
    )


def _count_items(payload: object) -> int | None:
    """Count entries in a Generative Language list response, if shaped so."""
    if not isinstance(payload, dict):
        return None
    for key in ("models", "files", "cachedContents", "corpora"):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return None


async def _referer_bypass(client: httpx.AsyncClient, *, raw_key: str) -> ProbeResult:
    """Read-only attempt to use a referer-restricted key from a forged origin.

    Re-runs ``ListModels`` with a spoofed ``Referer``. Success demonstrates
    that an HTTP-referer restriction does not actually protect the key. Still
    a ``GET`` — strictly read-only, SAFE tier.
    """
    url = f"{_GLA_BASE}/models"
    try:
        resp = await client.get(url, headers=_headers(raw_key, referer=_SPOOFED_REFERER))
    except httpx.HTTPError as exc:
        return ProbeResult(
            name="RefererBypass",
            tier=ProbeTier.SAFE,
            success=False,
            detail=f"request failed: {type(exc).__name__}",
            evidence={"spoofed_referer": _SPOOFED_REFERER, "error": str(exc)},
        )
    success = resp.is_success
    return ProbeResult(
        name="RefererBypass",
        tier=ProbeTier.SAFE,
        success=success,
        detail=(
            "referer restriction bypassed read-only via forged Referer"
            if success
            else f"referer bypass refused ({resp.status_code})"
        ),
        evidence={"spoofed_referer": _SPOOFED_REFERER, "status": resp.status_code},
    )


# --------------------------------------------------------------------------
# GATED rungs. These are billable / state-changing / PII-touching and are
# UNREACHABLE unless consent is fully granted: the @gated decorator calls the
# safety guard before the body runs, so no network call is issued otherwise.
# They are defined here for completeness and to drive PROVEN tiering, but the
# safe ladder NEVER invokes them — the CLI does, only with --prove + scope.
# --------------------------------------------------------------------------


@gated
async def gated_generate_content(
    consent: Consent,
    client: httpx.AsyncClient,
    raw_key: str,
) -> ProbeResult:
    """GATED: billable Gemini inference (``generateContent``)."""
    url = f"{_GLA_BASE}/{_GATED_MODEL}:generateContent"
    body = {"contents": [{"parts": [{"text": "ping"}]}]}
    try:
        resp = await client.post(url, headers=_headers(raw_key), json=body)
    except httpx.HTTPError as exc:
        return ProbeResult(
            name="GenerateContent",
            tier=ProbeTier.GATED,
            success=False,
            detail=f"request failed: {type(exc).__name__}",
            evidence={"model": _GATED_MODEL, "error": str(exc)},
        )
    return ProbeResult(
        name="GenerateContent",
        tier=ProbeTier.GATED,
        success=resp.is_success,
        detail=f"generateContent {'succeeded' if resp.is_success else 'refused'} "
        f"({resp.status_code})",
        evidence={"model": _GATED_MODEL, "status": resp.status_code},
    )


@gated
async def gated_upload_file(
    consent: Consent,
    client: httpx.AsyncClient,
    raw_key: str,
) -> ProbeResult:
    """GATED: creates a resource via the Files API (state change)."""
    url = "https://generativelanguage.googleapis.com/upload/v1beta/files"
    try:
        resp = await client.post(
            url,
            headers=_headers(raw_key),
            content=b"vtx-recon-authorized-probe",
        )
    except httpx.HTTPError as exc:
        return ProbeResult(
            name="UploadFile",
            tier=ProbeTier.GATED,
            success=False,
            detail=f"request failed: {type(exc).__name__}",
            evidence={"error": str(exc)},
        )
    return ProbeResult(
        name="UploadFile",
        tier=ProbeTier.GATED,
        success=resp.is_success,
        detail=f"file upload {'succeeded' if resp.is_success else 'refused'} ({resp.status_code})",
        evidence={"status": resp.status_code},
    )


@gated
async def gated_maps_billable_probe(
    consent: Consent,
    client: httpx.AsyncClient,
    raw_key: str,
) -> ProbeResult:
    """GATED: a billable Google Maps Platform call (Geocoding)."""
    url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": "1600 Amphitheatre Parkway", "key": raw_key}
    try:
        resp = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        return ProbeResult(
            name="MapsBillableProbe",
            tier=ProbeTier.GATED,
            success=False,
            detail=f"request failed: {type(exc).__name__}",
            evidence={"error": str(exc)},
        )
    ok = False
    if resp.is_success:
        try:
            ok = resp.json().get("status") == "OK"
        except ValueError:
            ok = False
    return ProbeResult(
        name="MapsBillableProbe",
        tier=ProbeTier.GATED,
        success=ok,
        detail=f"Maps billable call {'billed/OK' if ok else 'refused'} ({resp.status_code})",
        evidence={"status": resp.status_code},
    )


@gated
async def gated_firebase_anon_signup(
    consent: Consent,
    client: httpx.AsyncClient,
    raw_key: str,
) -> ProbeResult:
    """GATED: Identity Toolkit anonymous signup (creates an auth user)."""
    url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
    try:
        resp = await client.post(url, params={"key": raw_key}, json={"returnSecureToken": True})
    except httpx.HTTPError as exc:
        return ProbeResult(
            name="FirebaseAnonSignup",
            tier=ProbeTier.GATED,
            success=False,
            detail=f"request failed: {type(exc).__name__}",
            evidence={"error": str(exc)},
        )
    return ProbeResult(
        name="FirebaseAnonSignup",
        tier=ProbeTier.GATED,
        success=resp.is_success,
        detail=f"anonymous signup {'succeeded' if resp.is_success else 'refused'} "
        f"({resp.status_code})",
        evidence={"status": resp.status_code},
    )


# Ordered safe ladder: (rung name, v1beta path). Climbed top to bottom.
_SAFE_RUNGS: tuple[tuple[str, str], ...] = (
    ("ListModels", "models"),
    ("ListFiles", "files"),
    ("ListCachedContents", "cachedContents"),
    ("ListCorpora", "corpora"),
)

# Gated rungs are NOT part of the safe ladder. Exposed for the CLI/tests to
# introspect tier without invoking them.
GATED_RUNGS = (
    gated_generate_content,
    gated_upload_file,
    gated_maps_billable_probe,
    gated_firebase_anon_signup,
)


def _verdict(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    PROVEN: a GATED rung actually succeeded (real impact exercised).
    VALID:  the key authenticated and >=1 SAFE rung confirmed access.
    DENIED: the key was reachable but every probed capability was refused.
    """
    if any(r.tier is ProbeTier.GATED and r.success for r in rungs):
        return Verdict.PROVEN
    if any(r.tier is ProbeTier.SAFE and r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("GoogleAI", "Google", "Gemini", "GCP")
async def google_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Climb the Google AI / Gemini capability ladder for a finding.

    Runs the ordered SAFE rungs unconditionally (after asserting an authorized
    scope). GATED rungs are *not* called here — they are reachable only via
    the CLI with full consent and the :mod:`vtx_recon.safety` guard. Never
    raises across this boundary: the worst case is a DENIED verdict.
    """
    # The ladder (even its safe tier) refuses to run without a named scope.
    scope = consent.require_ladder_scope()

    rungs: list[ProbeResult] = []
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        referer_restricted = False
        for name, path in _SAFE_RUNGS:
            rung = await _safe_list(client, name=name, path=path, raw_key=finding.raw)
            rungs.append(rung)
            if not rung.success and rung.evidence.get("referer_restricted"):
                referer_restricted = True

        # Read-only referer-bypass attempt only if a rung was referer-blocked.
        if referer_restricted:
            rungs.append(await _referer_bypass(client, raw_key=finding.raw))

    return LadderResult(
        finding=finding,
        provider="google",
        verdict=_verdict(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
