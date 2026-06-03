"""Tests for the Grafana capability ladder.

Grafana is a FULLY MANUAL provider: every rung's URL embeds the ``{host}``
instance placeholder the engine cannot fill, so NO rung ever issues a live call.
respx is installed in assert-all mode to *prove* no network request leaves the
process. The tests assert:

* the ladder makes zero network calls and lands on DENIED;
* every rung is a SAFE/MANUAL ``$KEY`` safe-curl note (raw token never present);
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import grafana
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

# glsa_<32 base62>_<8 hex>; random padding, not a real token.
FAKE_KEY = "glsa_" + "EXAMPLEFAKEKEYNOTREAL00000000000" + "_deadbeef"


def _finding(raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name="Grafana", verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await grafana.grafana_ladder(_finding(), Consent.denied())


@respx.mock(assert_all_called=False)
async def test_all_rungs_manual_no_network_denied() -> None:
    # No routes registered; respx raises on any real request, proving no call.
    result = await grafana.grafana_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "grafana"
    # Every rung is manual -> nothing succeeds -> DENIED.
    assert result.verdict is Verdict.DENIED
    assert len(respx.calls) == 0

    assert [r.name for r in result.rungs] == [
        "current-user",
        "user-permissions",
        "list-datasources",
    ]
    for rung in result.rungs:
        assert rung.tier is ProbeTier.SAFE
        assert rung.success is False
        assert rung.evidence["manual"] is True
        assert "$KEY" in rung.evidence["safe_curl"]
        assert FAKE_KEY not in rung.evidence["safe_curl"]


@respx.mock(assert_all_called=False)
async def test_full_consent_still_manual_no_network() -> None:
    # Even with full consent, a fully-manual provider issues no live call.
    result = await grafana.grafana_ladder(_finding(), FULL_CONSENT)
    assert result.verdict is Verdict.DENIED
    assert len(respx.calls) == 0


async def test_no_raw_secret_in_public_result() -> None:
    result = await grafana.grafana_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("Grafana") is grafana.grafana_ladder
    assert get_ladder("grafana") is grafana.grafana_ladder
