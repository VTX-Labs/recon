"""Tests for the GitHub capability ladder.

HTTP is fully MOCKED via ``httpx.MockTransport`` (no respx, no network, no
real GitHub). The async ladder is driven synchronously with ``asyncio.run``
so the suite needs neither ``pytest-asyncio`` nor a live event-loop plugin.

Coverage:
  * a valid classic token climbs the safe rungs (identity -> scopes ->
    dangerous-scope flag -> private repos -> orgs) to VALID;
  * a dead token is DENIED and stops after the identity rung;
  * a fine-grained token is detected behaviourally (no X-OAuth-Scopes);
  * the GATED rung is BLOCKED without consent and stays read-only;
  * with full consent the GATED rung runs and the verdict becomes PROVEN;
  * the ladder refuses to run with no authorized scope (ScopeRequired);
  * the provider is registered for its detector names;
  * no raw secret leaks into the serialised evidence.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import get_ladder
from vtx_recon.providers import github as gh
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

VALID_TOKEN = "ghp" + "_" + "A" * 36
FINEGRAINED_TOKEN = "github_pat" + "_" + "B" * 22 + "_" + "C" * 30
DEAD_TOKEN = "ghp" + "_" + "DEAD" * 9

AUTHORIZED = Consent(prove=False, authorized_scope="h1:example-program")
CONSENTED = Consent(prove=True, authorized_scope="h1:example-program")


# --- mock transport ----------------------------------------------------------


def _make_transport(handler):
    """Wrap a request handler in an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def _install(monkeypatch, handler):
    """Patch httpx.AsyncClient so the provider uses our MockTransport.

    The provider does ``httpx.AsyncClient(base_url=..., timeout=...)``; we
    inject ``transport=`` while preserving the other kwargs.
    """
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.setdefault("transport", _make_transport(handler))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gh.httpx, "AsyncClient", factory)


def _json(payload, status=200, headers=None):
    return httpx.Response(status, json=payload, headers=headers or {})


def _run(coro):
    return asyncio.run(coro)


# --- handlers ----------------------------------------------------------------


def _classic_handler(request: httpx.Request) -> httpx.Response:
    """A live classic token with dangerous scopes, private repos, and orgs."""
    path = request.url.path
    # The token must be carried as a bearer on every request.
    assert request.headers["authorization"] == f"Bearer {VALID_TOKEN}"
    if path == "/user":
        return _json(
            {"login": "octocat", "id": 583231},
            headers={"X-OAuth-Scopes": "repo, read:org, admin:org, gist"},
        )
    if path == "/user/repos":
        return _json(
            [
                {"full_name": "octocat/secret-api", "private": True},
                {"full_name": "acme/internal-infra", "private": True},
            ]
        )
    if path == "/user/orgs":
        return _json([{"login": "acme"}, {"login": "octo-org"}])
    return _json({"message": "unexpected"}, status=404)


def _finegrained_handler(request: httpx.Request) -> httpx.Response:
    """A live fine-grained token: authenticates but exposes NO scope header."""
    path = request.url.path
    if path == "/user":
        # Note: deliberately no X-OAuth-Scopes header.
        return _json({"login": "fg-bot", "id": 999})
    if path == "/user/repos":
        return _json([{"full_name": "fg-bot/private-one", "private": True}])
    if path == "/user/orgs":
        return _json([])
    return _json({"message": "unexpected"}, status=404)


def _dead_handler(request: httpx.Request) -> httpx.Response:
    """A dead token: every endpoint returns 401 Bad credentials."""
    return _json({"message": "Bad credentials"}, status=401)


def _consented_handler(request: httpx.Request) -> httpx.Response:
    """Like the classic handler, plus the gated PUT succeeds (204)."""
    if request.method == "PUT" and request.url.path.startswith("/user/starred/"):
        return httpx.Response(204)
    return _classic_handler(request)


# --- tests -------------------------------------------------------------------


def test_registered_for_detectors():
    """The provider wires itself into the registry on import."""
    for name in gh.DETECTORS:
        assert get_ladder(name) is gh.github_ladder
    # Case-insensitive routing, as the registry promises.
    assert get_ladder("github") is gh.github_ladder


def test_valid_classic_token_climbs_safe_rungs(monkeypatch):
    """A live classic token reaches VALID and proves depth via safe rungs."""
    _install(monkeypatch, _classic_handler)
    finding = Finding(detector_name="Github", verified=True, raw=VALID_TOKEN)

    result = _run(gh.github_ladder(finding, AUTHORIZED))

    assert result.provider == "github"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == "h1:example-program"

    rungs = {r.name: r for r in result.rungs}
    assert rungs["identity"].success
    assert rungs["identity"].evidence["login"] == "octocat"

    assert rungs["classic_scopes"].success
    assert rungs["classic_scopes"].evidence["token_type"] == "classic"
    assert set(rungs["classic_scopes"].evidence["scopes"]) >= {"repo", "admin:org"}

    assert rungs["dangerous_scopes"].success
    assert set(rungs["dangerous_scopes"].evidence["dangerous"]) >= {"repo", "admin:org"}

    assert rungs["private_repos"].success
    assert rungs["private_repos"].evidence["private_repo_count"] == 2

    assert rungs["org_membership"].success
    assert rungs["org_membership"].evidence["orgs"] == ["acme", "octo-org"]

    # The gated rung was present but BLOCKED (no consent), and did not run.
    assert rungs["gated_write_probe"].tier is ProbeTier.GATED
    assert rungs["gated_write_probe"].blocked is True
    assert rungs["gated_write_probe"].success is False


def test_finegrained_token_detected_behaviourally(monkeypatch):
    """No X-OAuth-Scopes header on an authenticated token => fine-grained."""
    _install(monkeypatch, _finegrained_handler)
    finding = Finding(detector_name="Github", verified=True, raw=FINEGRAINED_TOKEN)

    result = _run(gh.github_ladder(finding, AUTHORIZED))

    assert result.verdict is Verdict.VALID
    rungs = {r.name: r for r in result.rungs}
    assert rungs["classic_scopes"].evidence["token_type"] == "fine-grained"
    # Dangerous-scope flagging is n/a for fine-grained tokens (no textual scopes).
    assert rungs["dangerous_scopes"].success is False
    assert rungs["dangerous_scopes"].evidence["dangerous"] == []
    # Behavioural depth still works: private repo is reachable.
    assert rungs["private_repos"].evidence["private_repo_count"] == 1


def test_dead_token_is_denied(monkeypatch):
    """A 401 on /user yields DENIED and stops the ladder after identity."""
    _install(monkeypatch, _dead_handler)
    finding = Finding(detector_name="Github", verified=False, raw=DEAD_TOKEN)

    result = _run(gh.github_ladder(finding, AUTHORIZED))

    assert result.verdict is Verdict.DENIED
    # Only the identity rung ran; no further safe rungs were attempted.
    assert [r.name for r in result.rungs] == ["identity"]
    assert result.rungs[0].success is False
    assert result.rungs[0].evidence["status"] == 401


def test_gated_rung_blocked_without_consent(monkeypatch):
    """Without --prove + scope the gated rung is blocked and makes no PUT."""
    seen_methods: list[str] = []

    def spy_handler(request: httpx.Request) -> httpx.Response:
        seen_methods.append(request.method)
        return _classic_handler(request)

    _install(monkeypatch, spy_handler)
    finding = Finding(detector_name="Github", verified=True, raw=VALID_TOKEN)

    # Authorized scope present (so laddering runs) but --prove absent.
    result = _run(gh.github_ladder(finding, AUTHORIZED))

    gated = next(r for r in result.rungs if r.name == "gated_write_probe")
    assert gated.blocked is True
    assert gated.success is False
    assert "prove" in gated.evidence["reason"].lower()
    # Structural proof of read-only: no state-changing method was issued.
    assert "PUT" not in seen_methods
    assert set(seen_methods) <= {"GET"}
    # Verdict stays VALID (never escalates to PROVEN without a gated run).
    assert result.verdict is Verdict.VALID


def test_gated_rung_runs_with_full_consent_yields_proven(monkeypatch):
    """With both --prove and an authorized scope the gated rung runs -> PROVEN."""
    seen: list[tuple[str, str]] = []

    def spy_handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return _consented_handler(request)

    _install(monkeypatch, spy_handler)
    finding = Finding(detector_name="Github", verified=True, raw=VALID_TOKEN)

    result = _run(gh.github_ladder(finding, CONSENTED))

    gated = next(r for r in result.rungs if r.name == "gated_write_probe")
    assert gated.blocked is False
    assert gated.success is True
    assert result.verdict is Verdict.PROVEN
    # The gated PUT was actually exercised under consent.
    assert any(method == "PUT" for method, _ in seen)


def test_ladder_refuses_without_authorized_scope(monkeypatch):
    """The whole ladder refuses to run with no authorized scope."""
    _install(monkeypatch, _classic_handler)
    finding = Finding(detector_name="Github", verified=True, raw=VALID_TOKEN)

    with pytest.raises(ScopeRequired):
        _run(gh.github_ladder(finding, Consent.denied()))


def test_no_raw_secret_in_serialised_evidence(monkeypatch):
    """The serialised bundle must never contain the raw token."""
    _install(monkeypatch, _classic_handler)
    finding = Finding(detector_name="Github", verified=True, raw=VALID_TOKEN)

    result = _run(gh.github_ladder(finding, AUTHORIZED))
    blob = json.dumps(result.to_public())

    assert VALID_TOKEN not in blob
    # The redacted prefix form is what should appear instead.
    assert result.finding.to_public()["redacted"].startswith("ghp_")
