"""Tests for the Travis CI capability ladder.

All HTTP is MOCKED with respx — these tests NEVER touch a real API. They assert:

* a valid token climbs two SAFE rungs (whoami -> list-repos) to VALID, using the
  ``Authorization: token {key}`` + ``Travis-API-Version: 3`` headers and parsed
  evidence;
* a dead token (403) yields DENIED and stops after the whoami rung;
* the GATED+MANUAL ``trigger-build`` rung is recorded blocked with a ``$KEY``
  safe curl and never fires a live POST;
* the ladder refuses to run without an authorized scope;
* the raw token never appears in the public result.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import travisci
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

SCOPE = "acme h1 program #4242"
SAFE_CONSENT = Consent(prove=False, authorized_scope=SCOPE)
FULL_CONSENT = Consent(prove=True, authorized_scope=SCOPE)

FAKE_KEY = "abcdef0123456789ABCDEF01"

_USER = "https://api.travis-ci.com/user"
_REPOS = "https://api.travis-ci.com/repos"


def _finding(detector: str = "TravisCI", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


async def test_ladder_requires_authorized_scope() -> None:
    with pytest.raises(ScopeRequired):
        await travisci.travisci_ladder(_finding(), Consent.denied())


@respx.mock
async def test_travisci_valid_token_climbs_two_safe_rungs() -> None:
    user = respx.get(_USER).mock(
        return_value=httpx.Response(200, json={"id": 42, "login": "victim", "name": "Victim User"})
    )
    respx.get(_REPOS).mock(
        return_value=httpx.Response(
            200,
            json={"repositories": [{"slug": "victim/app"}, {"slug": "victim/api"}]},
        )
    )

    result = await travisci.travisci_ladder(_finding(), SAFE_CONSENT)

    assert result.provider == "travisci"
    assert result.verdict is Verdict.VALID
    assert [r.name for r in result.rungs] == [
        "travisci.whoami",
        "travisci.list-repos",
        "travisci.trigger-build",
    ]

    req = user.calls.last.request
    assert req.url.host == "api.travis-ci.com"
    assert req.url.path == "/user"
    assert req.headers["Authorization"] == f"token {FAKE_KEY}"
    assert req.headers["Travis-API-Version"] == "3"

    whoami = result.rungs[0]
    assert whoami.tier is ProbeTier.SAFE
    assert whoami.evidence["login"] == "victim"
    assert whoami.evidence["id"] == 42
    repos = result.rungs[1]
    assert repos.evidence["repo_count"] == 2
    assert repos.evidence["slugs"] == ["victim/app", "victim/api"]

    # GATED+MANUAL trigger-build: blocked note, $KEY-only safe curl.
    trigger = result.rungs[2]
    assert trigger.tier is ProbeTier.GATED
    assert trigger.blocked is True
    assert trigger.success is False
    assert trigger.evidence["manual"] is True
    assert "$KEY" in trigger.evidence["safe_curl"]
    assert FAKE_KEY not in trigger.evidence["safe_curl"]


@respx.mock
async def test_travisci_dead_token_is_denied_and_stops_early() -> None:
    user = respx.get(_USER).mock(
        return_value=httpx.Response(403, json={"error_type": "login_required"})
    )
    repos = respx.get(_REPOS).mock(return_value=httpx.Response(200, json={"repositories": []}))

    result = await travisci.travisci_ladder(_finding(raw="deadtoken00000000000000"), SAFE_CONSENT)

    assert result.verdict is Verdict.DENIED
    assert [r.name for r in result.rungs] == ["travisci.whoami"]
    assert user.called
    assert not repos.called


@respx.mock
async def test_travisci_trigger_build_manual_even_with_consent() -> None:
    respx.get(_USER).mock(return_value=httpx.Response(200, json={"id": 1, "login": "v"}))
    respx.get(_REPOS).mock(return_value=httpx.Response(200, json={"repositories": []}))

    result = await travisci.travisci_ladder(_finding(), FULL_CONSENT)

    # Manual rung: verdict stays VALID (no gated success), no live build queued.
    assert result.verdict is Verdict.VALID
    trigger = next(r for r in result.rungs if r.name == "travisci.trigger-build")
    assert trigger.blocked is True
    assert trigger.success is False
    assert "$KEY" in trigger.evidence["safe_curl"]


@respx.mock
async def test_travisci_no_raw_secret_in_public_result() -> None:
    respx.get(_USER).mock(return_value=httpx.Response(200, json={"id": 1, "login": "v"}))
    respx.get(_REPOS).mock(return_value=httpx.Response(200, json={"repositories": []}))
    result = await travisci.travisci_ladder(_finding(), SAFE_CONSENT)
    assert FAKE_KEY not in repr(result.to_public())


def test_provider_is_registered() -> None:
    from vtx_recon.providers import get_ladder

    assert get_ladder("TravisCI") is travisci.travisci_ladder
    assert get_ladder("travisci") is travisci.travisci_ladder
