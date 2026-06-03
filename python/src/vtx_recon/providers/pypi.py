"""Capability ladder for PyPI upload API tokens (macaroons).

A TruffleHog ``PyPI`` finding is an upload token shaped
``pypi-AgEIcHlwaS5vcmcCJ...`` (a base64 macaroon). PyPI tokens are
**UPLOAD-ONLY**: there is NO read-only / whoami / token-introspection
endpoint, so there is no honest SAFE identity rung to climb. The single,
unavoidable capability the token grants is *publishing a distribution* to the
legacy upload endpoint, which is full supply-chain impact (publish or
overwrite a package the world ``pip install``s). That makes the only rung a
GATED one:

* **publish-package** (GATED / MANUAL) — ``POST https://upload.pypi.org/legacy/``
  with HTTP Basic auth (username ``__token__``, password = the ``pypi-``
  token). A successful upload proves the token can publish/overwrite packages.
  Because the action is irreversible publish-impact AND the request body is a
  multipart distribution artifact (file + metadata) the engine cannot
  synthesise from ``{key}`` alone, this rung is MANUAL by design: even under
  full consent it never auto-fires a live upload. It renders a copy-pasteable
  safe curl (the secret kept as ``$KEY``) and returns a non-success result, so
  the "no artifact published" attestation always holds. Without consent the
  gated boundary blocks it before any work and we record a ``blocked`` rung.

The auth is HTTP Basic: ``__token__`` is a fixed, public constant, so the raw
token alone fully constructs the credential — ``curl -u __token__:$KEY`` keeps
the secret as the ``$KEY`` shell variable. What keeps the rung MANUAL is the
publish *body* (the distribution artifact), not the credential.

The ladder is ordered (here, a single rung), never raises across the public
boundary — failures become a :class:`ProbeResult` with ``success=False`` so
one dead key cannot crash a batch run — and never publishes anything or
persists the raw secret. Only non-secret values are ever placed in
:attr:`ProbeResult.evidence`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["pypi_ladder"]

# The safe, copy-pasteable curl an operator runs by hand to exercise the gated
# publish. The secret stays the ``$KEY`` shell variable (PyPI's Basic auth is
# username ``__token__``, password = the token, so ``-u __token__:$KEY``) and
# the distribution artifact ``DIST_FILE`` is left for the operator to
# substitute. This is what the gated rung prints instead of publishing
# anything.
_PUBLISH_PACKAGE_CURL = (
    "curl -sS -X POST https://upload.pypi.org/legacy/ "
    "-u __token__:$KEY "
    "-F ':action=file_upload' -F 'protocol_version=1' "
    "-F 'content=@DIST_FILE'"
)


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere -> DENIED.

    NOTE: the only PyPI rung is manual and never fires a live call, so it is
    never ``success=True``. The verdict is therefore always DENIED — the ladder
    cannot prove live publish access without uploading an artifact, which it
    refuses to do.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


@register("PyPI")
async def pypi_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """PyPI ladder: a single GATED publish rung.

    PyPI tokens have no read-only surface, so there is no SAFE rung to gate the
    climb behind — the ladder reaches the gated boundary directly. The
    ``@gated`` wrapper enforces consent BEFORE any work; if consent is missing
    it raises :class:`GatedProbeBlocked`, captured here as a ``blocked`` rung.
    Even WITH full consent the rung never fires a live upload (publish is
    irreversible and the multipart artifact body cannot be filled from
    ``{key}``), so it renders a safe curl. The ladder never raises across the
    public boundary.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []
    # finding.raw holds the token; it is never placed in evidence — the
    # credential only ever appears in the operator's curl as the ``$KEY`` var.

    # The single GATED/MANUAL publish rung. Reachable only via the @gated
    # wrapper: without full consent it raises GatedProbeBlocked, recorded as a
    # blocked rung (the safe curl is still surfaced as evidence). With consent
    # it still only renders a safe curl. The ladder never raises across its
    # boundary.
    try:
        rungs.append(await _pypi_publish_package(consent))
    except GatedProbeBlocked as blocked:
        rungs.append(
            ProbeResult(
                name="publish-package",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated publish blocked: {blocked.reason}",
                evidence={
                    "reason": blocked.reason,
                    "manual": True,
                    "billable": False,
                    "safe_curl": _PUBLISH_PACKAGE_CURL,
                },
            )
        )

    return LadderResult(
        finding=finding,
        provider="pypi",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


@gated
async def _pypi_publish_package(consent: Consent) -> ProbeResult:
    """GATED + MANUAL: ``POST https://upload.pypi.org/legacy/`` publishes.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and nothing happens. Even WITH full
    consent we do NOT fire the POST — publishing is irreversible supply-chain
    impact and the multipart upload body (the distribution artifact +
    metadata) is data the engine cannot fill from ``{key}`` alone. So this rung
    is MANUAL by design: it renders the safe curl (Basic auth ``__token__:$KEY``)
    and returns a non-success result, never uploading an artifact (a real
    upload returns 200, or a 400 metadata-rejection that still confirms the
    credential publishes).
    """
    return ProbeResult(
        name="publish-package",
        tier=ProbeTier.GATED,
        success=False,
        blocked=False,
        detail=(
            "MANUAL GATED: PyPI upload is never auto-run (irreversible "
            "supply-chain impact; a 200 publishes, a 400 metadata-rejection "
            "still confirms the token publishes). Run the safe curl by hand "
            f"only when authorized: {_PUBLISH_PACKAGE_CURL}"
        ),
        evidence={
            "manual": True,
            "billable": False,
            "safe_curl": _PUBLISH_PACKAGE_CURL,
            "success_status": [200],
        },
    )
