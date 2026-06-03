"""Tests for the Algolia capability ladder.

Algolia auth needs BOTH the 32-hex key AND the Application ID, which is not in
the finding, so EVERY rung is MANUAL — the ladder makes NO live HTTP call. The
tests run inside ``respx.mock`` (which rejects any unmocked request) to PROVE no
network traffic ever leaves the ladder. They assert:

* every rung is a MANUAL safe-curl note; the three SAFE rungs (key ACL, all
  keys, indices) plus the GATED clear-index never fire, so the verdict is
  DENIED (the engine cannot prove live access on its own);
* each safe_curl keeps the secret as ``$KEY`` (never the raw key);
* the GATED clear-index rung is recorded ``blocked`` without consent and stays a
  manual note even WITH consent;
* a no-scope consent raises ScopeRequired;
* the raw key is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import algolia
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SAFE_CONSENT = Consent(prove=False, authorized_scope="acme h1 program #4242")
FULL_CONSENT = Consent(prove=True, authorized_scope="acme h1 program #4242")

FAKE_KEY = "deadbeefdeadbeefdeadbeefdeadbeef"


def _finding(detector: str = "AlgoliaAdminKey", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await algolia.algolia_ladder(_finding(), Consent.denied())


@respx.mock
async def test_algolia_all_rungs_are_manual_no_network_denied() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await algolia.algolia_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "algolia"
    # No rung can run automatically, so the engine cannot prove live access.
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == [
        "get-own-key-acl",
        "list-all-keys",
        "list-indices",
        "clear-index",
    ]
    safe = [r for r in result.rungs if r.tier is ProbeTier.SAFE]
    assert [r.name for r in safe] == ["get-own-key-acl", "list-all-keys", "list-indices"]
    for rung in result.rungs:
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
        assert FAKE_KEY not in rung.evidence["safe_curl"]


@respx.mock
async def test_algolia_gated_clear_index_blocked_without_consent() -> None:
    result = await algolia.algolia_ladder(_finding(), SAFE_CONSENT)

    clear = next(r for r in result.rungs if r.name == "clear-index")
    assert clear.tier is ProbeTier.GATED
    assert clear.blocked is True
    assert clear.success is False
    assert "$KEY" in clear.evidence["safe_curl"]


@respx.mock
async def test_algolia_gated_clear_index_with_consent_stays_manual() -> None:
    result = await algolia.algolia_ladder(_finding(), FULL_CONSENT)

    # Even with full consent the rung is manual (needs App ID + index), so it
    # never auto-fires and the verdict stays DENIED.
    assert result.verdict is Verdict.DENIED
    clear = next(r for r in result.rungs if r.name == "clear-index")
    assert clear.blocked is False
    assert clear.success is False
    assert clear.evidence["manual"] is True


async def test_algolia_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await algolia._algolia_clear_index(SAFE_CONSENT)
    assert algolia._algolia_clear_index.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_algolia_result_is_redacted() -> None:
    result = await algolia.algolia_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("AlgoliaAdminKey") is algolia.algolia_ladder
    assert get_ladder("algoliaadminkey") is algolia.algolia_ladder
