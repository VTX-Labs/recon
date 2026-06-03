"""Tests for the generic declarative capability ladder.

Every HTTP call is served by a mocked ``httpx.MockTransport`` — NO real API
is ever contacted, and TruffleHog is never invoked.

Every shipped provider now has a dedicated ladder module, so ``BUILTIN_SPECS``
is empty and the generic runner is a pure *runtime extensibility* layer. These
tests therefore register their own throwaway spec (``examplecorp``) and drive
the runner against it through every branch:

  * a valid key climbing its SAFE rungs                  -> VALID
  * a dead key (auth refused on every rung)              -> DENIED
  * a GATED rung blocked without consent (no network)    -> blocked rung
  * a GATED rung exercised WITH consent                  -> PROVEN
  * a MANUAL rung never calling the network              -> safe curl only
  * an unknown detector                                  -> N/A
  * scope is required to ladder at all
  * secrets are redacted in stored evidence; safe curl never leaks the key
  * a billable SAFE rung is rejected at spec-build time
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from vtx_recon.models import Finding, Verdict
from vtx_recon.providers import clear_registry, get_ladder, register
from vtx_recon.providers.generic import (
    BUILTIN_SPECS,
    ProviderSpec,
    RungSpec,
    generic_ladder,
    load_specs_from_yaml,
    register_spec,
    spec_for_detector,
)
from vtx_recon.safety import Consent, ProbeTier, ScopeRequired

# A scope that satisfies the ladder's require_ladder_scope() gate.
SCOPE = "h1-program: example (SOW-123)"
# A throwaway provider whose secret shape is ``ec_<alphanum>``.
FAKE_KEY = "ec_" + "A1b2C3d4E5f6G7h8I9j0"
HOST = "api.example.test"


def _example_spec() -> ProviderSpec:
    """A self-contained spec exercising SAFE + GATED runner paths."""
    return ProviderSpec(
        name="examplecorp",
        detectors=("ExampleCorpToken",),
        key_regex=r"^ec_[A-Za-z0-9]+",
        docs="throwaway provider for generic-runner tests",
        rungs=(
            RungSpec(
                name="whoami",
                method="GET",
                url=f"https://{HOST}/v1/me",
                tier=ProbeTier.SAFE,
                headers={"Authorization": "Bearer {key}"},
                success_status=(200,),
                detail="identity probe (read-only)",
            ),
            RungSpec(
                name="charge",
                method="POST",
                url=f"https://{HOST}/v1/charge",
                tier=ProbeTier.GATED,
                headers={"Authorization": "Bearer {key}", "Content-Type": "application/json"},
                billable=True,
                detail="GATED: a billable charge.",
            ),
        ),
    )


@pytest.fixture(autouse=True)
def _register_example_spec() -> Iterator[None]:
    """Register the throwaway spec + route its detector to the generic ladder."""
    clear_registry()
    spec = register_spec(_example_spec())
    register(*spec.detectors)(generic_ladder)
    yield
    clear_registry()


def _client(handler) -> httpx.AsyncClient:
    """An AsyncClient whose every request is served by ``handler``."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _finding(detector: str = "ExampleCorpToken", raw: str = FAKE_KEY) -> Finding:
    return Finding(detector_name=detector, verified=True, raw=raw)


# --------------------------------------------------------------------------
# Valid key climbs the SAFE rung -> VALID
# --------------------------------------------------------------------------


async def test_valid_key_climbs_safe_rung_to_valid() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.host == HOST
        assert request.url.path == "/v1/me"
        assert request.headers["Authorization"] == f"Bearer {FAKE_KEY}"
        return httpx.Response(200, json={"id": "user_1"})

    consent = Consent(authorized_scope=SCOPE)  # no --prove: gated stays blocked
    async with _client(handler) as client:
        result = await generic_ladder(_finding(), consent, client=client)

    # Only the SAFE rung touched the network; the GATED one was blocked.
    assert [r.url.path for r in seen] == ["/v1/me"]
    assert result.provider == "examplecorp"
    assert result.verdict is Verdict.VALID
    assert result.authorized_scope == SCOPE

    safe = next(r for r in result.rungs if r.name == "whoami")
    assert safe.success is True
    assert safe.blocked is False
    assert safe.tier is ProbeTier.SAFE


# --------------------------------------------------------------------------
# Dead key -> DENIED
# --------------------------------------------------------------------------


async def test_dead_key_denied() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid"})

    consent = Consent(authorized_scope=SCOPE)
    async with _client(handler) as client:
        result = await generic_ladder(_finding(), consent, client=client)

    assert result.verdict is Verdict.DENIED
    safe = next(r for r in result.rungs if r.name == "whoami")
    assert safe.success is False
    assert safe.evidence["status_code"] == 401


# --------------------------------------------------------------------------
# GATED rung is blocked without consent — and makes NO network call
# --------------------------------------------------------------------------


async def test_gated_rung_blocked_without_consent() -> None:
    gated_hits = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal gated_hits
        if request.url.path == "/v1/charge":
            gated_hits += 1  # must never happen
        return httpx.Response(200, json={"id": "user_1"})

    # prove=False -> gated blocked even though scope is present.
    consent = Consent(prove=False, authorized_scope=SCOPE)
    async with _client(handler) as client:
        result = await generic_ladder(_finding(), consent, client=client)

    assert gated_hits == 0, "a GATED billable endpoint must never be contacted without consent"

    gated = next(r for r in result.rungs if r.name == "charge")
    assert gated.tier is ProbeTier.GATED
    assert gated.blocked is True
    assert gated.success is False
    assert "$KEY" in gated.evidence["safe_curl"]
    assert FAKE_KEY not in gated.evidence["safe_curl"]
    assert result.verdict is Verdict.VALID


async def test_gated_blocked_with_partial_consent_prove_only() -> None:
    """--prove without scope cannot even start the ladder (scope gate)."""
    consent = Consent(prove=True, authorized_scope=None)
    with pytest.raises(ScopeRequired):
        await generic_ladder(_finding(), consent)


# --------------------------------------------------------------------------
# GATED rung exercised WITH full consent -> PROVEN
# --------------------------------------------------------------------------


async def test_gated_rung_proven_with_full_consent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/me":
            return httpx.Response(200, json={"id": "user_1"})
        if request.url.path == "/v1/charge":
            assert request.method == "POST"
            return httpx.Response(200, json={"charged": True})
        return httpx.Response(404)

    consent = Consent(prove=True, authorized_scope=SCOPE)
    async with _client(handler) as client:
        result = await generic_ladder(_finding(), consent, client=client)

    gated = next(r for r in result.rungs if r.name == "charge")
    assert gated.blocked is False
    assert gated.success is True
    assert result.verdict is Verdict.PROVEN


# --------------------------------------------------------------------------
# MANUAL rung never touches the network
# --------------------------------------------------------------------------


async def test_manual_rung_emits_safe_curl_without_network() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    # A spec whose only rung is MANUAL (needs a path-embedded id we cannot fill).
    clear_registry()
    spec = register_spec(
        ProviderSpec(
            name="manualcorp",
            detectors=("ManualCorpToken",),
            key_regex=r"^mc_[A-Za-z0-9]+",
            rungs=(
                RungSpec(
                    name="account-fetch",
                    method="GET",
                    url=f"https://{HOST}/v1/account/{{key}}",
                    tier=ProbeTier.SAFE,
                    manual=True,
                    detail="MANUAL: needs a paired secret.",
                ),
            ),
        )
    )
    register(*spec.detectors)(generic_ladder)

    raw = "mc_" + "0" * 20
    consent = Consent(authorized_scope=SCOPE)
    async with _client(handler) as client:
        result = await generic_ladder(_finding("ManualCorpToken", raw), consent, client=client)

    assert calls == 0, "a MANUAL rung must not make any network request"
    assert result.provider == "manualcorp"
    manual = result.rungs[0]
    assert manual.evidence["manual"] is True
    assert "curl" in manual.detail
    # The safe curl is key-free even when the id is in the URL path.
    assert raw not in manual.evidence["safe_curl"]
    assert "$KEY" in manual.evidence["safe_curl"]


# --------------------------------------------------------------------------
# Unknown detector -> N/A with a helpful note, no exception
# --------------------------------------------------------------------------


async def test_unknown_detector_is_na() -> None:
    consent = Consent(authorized_scope=SCOPE)
    result = await generic_ladder(_finding("TotallyUnknownDetector", "whatever-value"), consent)
    assert result.verdict is Verdict.NA
    assert result.provider == "generic"
    assert result.rungs[0].name == "no-spec"


# --------------------------------------------------------------------------
# Scope is required to ladder at all
# --------------------------------------------------------------------------


async def test_ladder_requires_scope() -> None:
    with pytest.raises(ScopeRequired):
        await generic_ladder(_finding(), Consent())


# --------------------------------------------------------------------------
# Redaction: stored evidence never contains the raw key
# --------------------------------------------------------------------------


async def test_evidence_redacts_secret() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "user_1"})

    consent = Consent(authorized_scope=SCOPE)
    async with _client(handler) as client:
        result = await generic_ladder(_finding(), consent, client=client)

    public = result.to_public()
    blob = repr(public)
    assert FAKE_KEY not in blob
    safe = next(r for r in result.rungs if r.name == "whoami")
    assert safe.evidence["key"].startswith("ec_")
    assert "*" in safe.evidence["key"]


# --------------------------------------------------------------------------
# Transport error becomes a ProbeResult, not an exception
# --------------------------------------------------------------------------


async def test_transport_error_is_captured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    consent = Consent(authorized_scope=SCOPE)
    async with _client(handler) as client:
        result = await generic_ladder(_finding(), consent, client=client)

    assert result.verdict is Verdict.DENIED
    safe = next(r for r in result.rungs if r.name == "whoami")
    assert safe.success is False
    assert safe.evidence["error"] == "ConnectError"


# --------------------------------------------------------------------------
# Declarative spec layer: registration, key-shape fallback, YAML, validation
# --------------------------------------------------------------------------


def test_no_builtin_specs_ship() -> None:
    # Every provider is now a dedicated module; nothing ships inline.
    assert BUILTIN_SPECS == ()


def test_registered_spec_routes_to_generic_ladder() -> None:
    # The autouse fixture registered examplecorp -> generic_ladder.
    assert get_ladder("ExampleCorpToken") is generic_ladder


def test_spec_lookup_falls_back_to_key_shape() -> None:
    # Unknown detector, but the value looks like an examplecorp key.
    spec = spec_for_detector("MysteryDetector", FAKE_KEY)
    assert spec is not None
    assert spec.name == "examplecorp"


def test_safe_curl_never_contains_raw_key() -> None:
    spec = spec_for_detector("ExampleCorpToken")
    assert spec is not None
    rung = next(r for r in spec.rungs if r.name == "whoami")
    curl = rung.safe_curl()
    assert "$KEY" in curl
    assert FAKE_KEY not in curl
    # render_headers (in-memory only) does substitute the live value.
    assert rung.render_headers(FAKE_KEY)["Authorization"] == f"Bearer {FAKE_KEY}"


def test_billable_safe_rung_is_rejected() -> None:
    with pytest.raises(ValueError, match="billable"):
        RungSpec(
            name="oops",
            method="POST",
            url="https://example.test/charge",
            tier=ProbeTier.SAFE,
            billable=True,
        )


def test_load_specs_from_yaml_builds_and_registers() -> None:
    yaml_text = """
- name: examplecorp2
  detectors: [ExampleCorp2Token]
  key_regex: "^ec2_[A-Za-z0-9]+"
  docs: "demo"
  rungs:
    - name: whoami
      method: GET
      url: https://api.example.test/v1/me
      tier: safe
      headers:
        Authorization: "Bearer {key}"
      success_status: [200]
      detail: "identity probe"
    - name: charge
      method: POST
      url: https://api.example.test/v1/charge
      tier: gated
      billable: true
      headers:
        Authorization: "Bearer {key}"
"""
    specs = load_specs_from_yaml(yaml_text)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.name == "examplecorp2"
    assert spec.rungs[0].tier is ProbeTier.SAFE
    assert spec.rungs[1].tier is ProbeTier.GATED
    assert spec.rungs[1].billable is True
    # Registered by detector name for spec lookup.
    assert spec_for_detector("ExampleCorp2Token") is spec


def test_load_billable_safe_yaml_rung_fails_at_load() -> None:
    bad_yaml = """
- name: badcorp
  detectors: [BadCorp]
  rungs:
    - name: charge
      method: POST
      url: https://api.bad.test/charge
      tier: safe
      billable: true
"""
    with pytest.raises(ValueError, match="billable"):
        load_specs_from_yaml(bad_yaml, register=False)
