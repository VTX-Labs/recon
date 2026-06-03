"""Algolia capability ladder — prove depth of access from a leaked Admin API key.

A TruffleHog ``AlgoliaAdminKey`` finding is a 32-hex API key. Algolia, however,
authenticates with TWO halves: the API key AND the application's
**Application ID**, sent together in ``X-Algolia-API-Key`` /
``X-Algolia-Application-Id``. The App ID is NOT contained in the 32-hex key and
TruffleHog does not pair it on the finding, so the engine cannot fill the
``{appid}`` placeholder that every Algolia endpoint requires. Per the ladder
conventions, a rung whose URL/headers need any placeholder other than ``{key}``
MUST be MANUAL: vtx-recon never fires a live request it cannot fully address.
Each rung therefore records the exact, copy-pasteable **safe curl** (with the
secret kept as ``$KEY`` and the App ID as ``$APP_ID``) for an operator to run by
hand once they supply the App ID.

Rungs (ordered by blast radius):

  1. ``get-own-key-acl`` — SAFE/MANUAL. ``GET /1/keys/{key}`` is the key's own
     whoami: it returns the ACL (addObject, deleteIndex, settings, listIndexes),
     index scope, validity and rate limits — exactly how powerful the leaked key
     is. Read-only, non-billable.
  2. ``list-all-keys`` — SAFE/MANUAL. ``GET /1/keys`` only succeeds for an
     admin-capable key, so success proves admin privileges: the deepest auth
     proof short of writing. Read-only, non-billable.
  3. ``list-indices`` — SAFE/MANUAL. ``GET /1/indexes`` enumerates every index
     (record counts, sizes) the key can reach. Read-only, non-billable.
  4. ``clear-index`` — GATED/MANUAL. ``POST /1/indexes/{index}/clear`` deletes
     all records from an index — destructive, state-changing — the worst-case
     write impact an admin key enables. Routed through ``@gated`` so it is
     structurally unreachable without BOTH ``--prove`` and an authorized scope;
     even with consent it is rendered as a manual safe-curl note and never
     auto-fired (the engine cannot fill ``{appid}``/``{index}``).

The ladder never raises across its public boundary: every outcome is a
:class:`ProbeResult`, and a key that authenticates nowhere here (because no rung
can run automatically) is reported with the manual curls so a human can complete
the proof.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import shlex

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..safety import Consent, GatedProbeBlocked, ProbeTier, gated
from . import register

__all__ = ["algolia_ladder"]

# Placeholder the engine fills with the live secret. ANY other placeholder
# (notably {appid} / {index}) cannot be filled -> the rung must be MANUAL.
# Because every Algolia rung is MANUAL, this ladder makes NO live HTTP call, so
# there is no httpx client / timeout / ``_network_failure`` path here.
_KEY_PLACEHOLDER = "{key}"

# The exact URL/headers for the destructive clear, reused by both the gated body
# and the blocked-rung note so the two render identical safe curls.
_CLEAR_INDEX_URL = "https://{appid}.algolia.net/1/indexes/{index}/clear"
_CLEAR_INDEX_HEADERS = {
    "X-Algolia-API-Key": "{key}",
    "X-Algolia-Application-Id": "{appid}",
    "Content-Type": "application/json",
}


def _verdict_from(rungs: list[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    * A successful GATED rung that actually ran (not blocked) -> PROVEN.
    * Any successful SAFE rung -> VALID (authenticates + depth shown).
    * The key authenticated nowhere (all manual / refused) -> DENIED.
    """
    if any(r.success and r.tier is ProbeTier.GATED and not r.blocked for r in rungs):
        return Verdict.PROVEN
    if any(r.success for r in rungs):
        return Verdict.VALID
    return Verdict.DENIED


def _safe_curl(method: str, url: str, headers: dict[str, str]) -> str:
    """Build a copy-pasteable curl with NO secret material.

    The live key is replaced by ``$KEY`` and the unfillable ``{appid}`` /
    ``{index}`` placeholders are rendered as ``$APP_ID`` / ``$INDEX`` for the
    operator to substitute. Safe to print and to store in evidence.
    """

    def render(s: str) -> str:
        return (
            s.replace(_KEY_PLACEHOLDER, "$KEY")
            .replace("{appid}", "$APP_ID")
            .replace("{index}", "$INDEX")
        )

    parts = ["curl", "-sS", "-X", method]
    for header_name, header_value in headers.items():
        parts.append("-H")
        parts.append(shlex.quote(f"{header_name}: {render(header_value)}"))
    parts.append(shlex.quote(render(url)))
    return " ".join(parts)


def _manual_rung(
    name: str,
    tier: ProbeTier,
    method: str,
    url: str,
    headers: dict[str, str],
    proves: str,
) -> ProbeResult:
    """Render a MANUAL rung: no live call (a non-``{key}`` placeholder is
    present), record the safe curl so an operator can run it by hand.
    """
    curl = _safe_curl(method, url, headers)
    return ProbeResult(
        name=name,
        tier=tier,
        success=False,
        blocked=False,
        detail=(
            f"MANUAL (App ID required; engine cannot fill {{appid}}): {proves} Run by hand: {curl}"
        ),
        evidence={"manual": True, "safe_curl": curl},
    )


# --------------------------------------------------------------------------- #
# rung 1 — SAFE/MANUAL: get-own-key-acl
# --------------------------------------------------------------------------- #
def _algolia_get_own_key_acl() -> ProbeResult:
    """SAFE: ``GET /1/keys/{key}`` — whoami for the key itself.

    Returns its ACL, index scope, validity and rate limits: exactly how
    powerful the leaked key is. Read-only, non-billable. MANUAL because the
    host carries ``{appid}``.
    """
    return _manual_rung(
        "get-own-key-acl",
        ProbeTier.SAFE,
        "GET",
        "https://{appid}.algolia.net/1/keys/{key}",
        {
            "X-Algolia-API-Key": "{key}",
            "X-Algolia-Application-Id": "{appid}",
            "Accept": "application/json",
        },
        (
            "Whoami for the key itself — returns its ACL (addObject, deleteIndex, "
            "settings, listIndexes), index scope, validity and rate limits; reveals "
            "exactly how powerful the leaked key is. Read-only, non-billable."
        ),
    )


# --------------------------------------------------------------------------- #
# rung 2 — SAFE/MANUAL: list-all-keys
# --------------------------------------------------------------------------- #
def _algolia_list_all_keys() -> ProbeResult:
    """SAFE: ``GET /1/keys`` — only an admin-capable key can list ALL of the
    application's API keys, so success proves admin privileges (the deepest
    auth proof short of writing). Read-only, non-billable. MANUAL (App ID).
    """
    return _manual_rung(
        "list-all-keys",
        ProbeTier.SAFE,
        "GET",
        "https://{appid}.algolia.net/1/keys",
        {
            "X-Algolia-API-Key": "{key}",
            "X-Algolia-Application-Id": "{appid}",
            "Accept": "application/json",
        },
        (
            "Only an admin-capable key can list ALL of the application's API keys — "
            "success proves admin privileges, the deepest auth proof short of writing. "
            "Read-only, non-billable."
        ),
    )


# --------------------------------------------------------------------------- #
# rung 3 — SAFE/MANUAL: list-indices
# --------------------------------------------------------------------------- #
def _algolia_list_indices() -> ProbeResult:
    """SAFE: ``GET /1/indexes`` — enumerates every index with record counts and
    sizes (requires the listIndexes ACL): which searchable datasets the key can
    reach. Read-only, non-billable. MANUAL (App ID).
    """
    return _manual_rung(
        "list-indices",
        ProbeTier.SAFE,
        "GET",
        "https://{appid}.algolia.net/1/indexes",
        {
            "X-Algolia-API-Key": "{key}",
            "X-Algolia-Application-Id": "{appid}",
            "Accept": "application/json",
        },
        (
            "Enumerates every index with record counts and sizes (requires listIndexes "
            "ACL) — which searchable datasets the key can reach. Read-only, non-billable."
        ),
    )


# --------------------------------------------------------------------------- #
# rung 4 — GATED/MANUAL: clear-index
# --------------------------------------------------------------------------- #
@gated
async def _algolia_clear_index(consent: Consent) -> ProbeResult:
    """GATED: ``POST /1/indexes/{index}/clear`` deletes all records from an
    index (destructive, state-changing; requires the deleteIndex ACL) — the
    worst-case write impact an admin key enables.

    Decorated with :func:`vtx_recon.safety.gated`: the safety boundary runs
    *before* this body, so without BOTH ``--prove`` and an authorized scope it
    raises :class:`GatedProbeBlocked` and the public ladder records a
    ``blocked`` rung. Even WITH consent this rung never auto-fires — the URL
    needs ``{appid}`` and ``{index}``, which the engine cannot fill — so it
    only renders the safe-curl note for an operator to run by hand.
    """
    return _manual_rung(
        "clear-index",
        ProbeTier.GATED,
        "POST",
        _CLEAR_INDEX_URL,
        _CLEAR_INDEX_HEADERS,
        (
            "Deletes all records from an index (destructive, state-changing; requires "
            "deleteIndex ACL) — the worst-case write impact an admin key enables."
        ),
    )


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #
@register("AlgoliaAdminKey")
async def algolia_ladder(finding: Finding, consent: Consent) -> LadderResult:
    """Algolia ladder: three SAFE manual rungs (key ACL -> all keys -> indices)
    then one GATED manual rung (clear index). Every rung is MANUAL because
    Algolia auth also needs the Application ID, which is not in the 32-hex key,
    so the ladder makes no live HTTP call.
    """
    scope = consent.require_ladder_scope()
    rungs: list[ProbeResult] = []

    # Rung 1 (SAFE): the key's own ACL — its whoami.
    rungs.append(_algolia_get_own_key_acl())

    # Every rung is MANUAL (no live call possible), so we cannot "climb on
    # success"; instead we surface every rung's safe curl so the operator has
    # the full ordered ladder to run by hand once they supply the App ID.
    rungs.append(_algolia_list_all_keys())
    rungs.append(_algolia_list_indices())

    # Rung 4 (GATED): destructive clear. The @gated wrapper enforces consent
    # BEFORE the body; without it GatedProbeBlocked is raised and captured here
    # as a blocked rung so the ladder never raises across the public boundary.
    try:
        rungs.append(await _algolia_clear_index(consent))
    except GatedProbeBlocked as blocked:
        curl = _safe_curl("POST", _CLEAR_INDEX_URL, _CLEAR_INDEX_HEADERS)
        rungs.append(
            ProbeResult(
                name="clear-index",
                tier=ProbeTier.GATED,
                success=False,
                blocked=True,
                detail=f"gated rung blocked: {blocked.reason}",
                evidence={"manual": True, "safe_curl": curl, "reason": blocked.reason},
            )
        )

    return LadderResult(
        finding=finding,
        provider="algolia",
        verdict=_verdict_from(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )
