"""Tests for the PyPI capability ladder.

PyPI upload tokens have NO read-only surface — the only capability is publishing
a distribution, which is irreversible supply-chain impact — so the ladder is a
single GATED/MANUAL rung and makes NO live HTTP call. The tests run inside
``respx.mock`` (which rejects any unmocked request) to PROVE no network traffic
ever leaves the ladder. They assert:

* the single ``publish-package`` rung is GATED and blocked (no network) without
  consent, recorded with a ``$KEY`` safe curl;
* WITH full consent it still never fires a live upload — it stays a manual note;
* the verdict is always DENIED (no rung can succeed);
* a no-scope consent raises ScopeRequired;
* the raw token is never present in the public, redacted result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import pypi
from vtx_recon.safety import Consent, GatedProbeBlocked, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "pypi" + "-EXAMPLEFAKEKEYNOTREAL" + "EXAMPLEFAKEKEYNOTREAL000"


def _finding(detector: str = "PyPI", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await pypi.pypi_ladder(_finding(), Consent.denied())


@respx.mock
async def test_pypi_gated_publish_blocked_without_consent_no_network() -> None:
    # respx.mock with NO routes: any HTTP request would raise. None should fire.
    result = await pypi.pypi_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "pypi"
    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["publish-package"]

    publish = result.rungs[0]
    assert publish.tier is ProbeTier.GATED
    assert publish.blocked is True
    assert publish.success is False
    assert publish.evidence["manual"] is True
    curl = publish.evidence["safe_curl"]
    assert "$KEY" in curl
    assert "__token__" in curl
    assert FAKE_KEY not in curl


@respx.mock
async def test_pypi_gated_publish_with_consent_stays_manual() -> None:
    result = await pypi.pypi_ladder(_finding(), FULL_CONSENT)

    assert result.verdict is Verdict.DENIED
    publish = result.rungs[0]
    assert publish.blocked is False
    assert publish.success is False
    assert publish.evidence["manual"] is True
    assert "$KEY" in publish.evidence["safe_curl"]


async def test_pypi_gated_probe_raises_without_consent() -> None:
    """Direct unit check of the boundary: the @gated probe itself refuses."""
    with pytest.raises(GatedProbeBlocked):
        await pypi._pypi_publish_package(SAFE_CONSENT)
    assert pypi._pypi_publish_package.__vtx_tier__ is ProbeTier.GATED


@respx.mock
async def test_pypi_result_is_redacted() -> None:
    result = await pypi.pypi_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("PyPI") is pypi.pypi_ladder
    assert get_ladder("pypi") is pypi.pypi_ladder
