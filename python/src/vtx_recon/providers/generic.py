"""Generic, declarative capability ladder for long-tail providers.

Most providers do not need bespoke Python. A provider's identity probe is
almost always "send the key in a header to one read-only endpoint and look
at the status / body". This module turns that pattern into *data* — a
:class:`ProviderSpec` — so adding OpenAI, Anthropic, SendGrid, Twilio, npm,
Discord, etc. is a few lines of declaration, not a new code path. This is
the rot-resistant extensibility layer: specs can be shipped in code
(:data:`BUILTIN_SPECS`) or loaded from YAML at runtime
(:func:`load_specs_from_yaml`) without touching the engine.

How a spec becomes a ladder
---------------------------
:func:`run_spec_ladder` walks a spec's ``rungs`` in order:

  * **SAFE** rungs (read-only, non-billable, idempotent — e.g. ``GET
    /v1/models``, ``GET /v2/account``) run by default and prove *depth of
    access*. They go through :func:`vtx_recon.safety.guard` too, but for a
    SAFE tier that is a documented no-op.
  * **GATED** rungs (billable / PII-reading / state-changing — e.g. an
    OpenAI ``chat/completions`` call, a SendGrid mail send) are routed
    through the same :func:`~vtx_recon.safety.guard`. They are
    **structurally unreachable** without BOTH ``--prove`` and
    ``--i-am-authorized "<scope>"``: the guard raises *before* any network
    I/O, and the runner records a blocked :class:`ProbeResult` instead.

When a finding has no automated rung (or a rung is declared
``manual=True``), the ladder emits a MANUAL :class:`ProbeResult` whose
``detail`` is the exact, copy-pasteable **safe curl** an operator can run by
hand. The secret is redacted in the stored evidence; the live curl string
is built only in memory and the raw value is replaced with a ``$KEY``
placeholder so nothing secret is ever persisted.

Nothing in here raises across the public boundary: every entry point returns
a :class:`LadderResult` / :class:`ProbeResult`. A blocked gated rung, a dead
key, a network error, and an unknown provider are all *data*, never
exceptions.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..models import Finding, LadderResult, ProbeResult, Verdict
from ..redact import redact, redact_mapping
from ..safety import Consent, GatedProbeBlocked, ProbeTier, guard
from . import register

__all__ = [
    "BUILTIN_SPECS",
    "ProviderSpec",
    "RungSpec",
    "generic_ladder",
    "load_specs_from_yaml",
    "register_spec",
    "run_spec_ladder",
    "spec_for_detector",
]

# Bound every probe so a hung endpoint cannot stall a ladder.
_HTTP_TIMEOUT = 10.0
# Header name under which the literal secret is substituted, so a spec can
# place the key in an arbitrary header via the ``{key}`` placeholder.
_KEY_PLACEHOLDER = "{key}"


@dataclass(frozen=True)
class RungSpec:
    """One declarative rung of a generic capability ladder.

    A rung is "send ``method`` to ``url`` with ``headers`` (with ``{key}``
    substituted) and decide success". Everything needed to probe and to
    print a safe manual curl lives here as data.

    Attributes:
        name: Stable rung identifier, e.g. ``"list-models"``.
        method: HTTP method, e.g. ``"GET"``.
        url: Absolute URL to probe.
        tier: :class:`ProbeTier.SAFE` (runs by default) or
            :class:`ProbeTier.GATED` (requires full consent).
        headers: Header template; any ``{key}`` token is replaced with the
            raw secret at call time and with ``$KEY`` in stored/printed forms.
        billable: Hint that the rung costs the target money. Billable rungs
            MUST be ``GATED``; declaring a billable SAFE rung is rejected.
        success_status: HTTP status codes that count as the capability being
            present. Defaults to ``2xx``.
        success_body_regex: Optional regex; if set, the response body must
            also match for the rung to count as a success.
        detail: Human-readable description of what the rung proves.
        manual: If ``True``, the rung is never auto-run; the ladder instead
            emits the exact safe curl for an operator to run by hand.
    """

    name: str
    method: str
    url: str
    tier: ProbeTier = ProbeTier.SAFE
    headers: Mapping[str, str] = field(default_factory=dict)
    billable: bool = False
    success_status: tuple[int, ...] = ()
    success_body_regex: str | None = None
    detail: str = ""
    manual: bool = False

    def __post_init__(self) -> None:
        # Enforce in code: a money-spending rung can never be SAFE.
        if self.billable and self.tier is not ProbeTier.GATED:
            raise ValueError(
                f"rung {self.name!r} is billable but tier is {self.tier.value!r}; "
                "billable probes must be GATED"
            )

    def is_success(self, status: int, body: str) -> bool:
        """Decide if a response proves this capability is present."""
        if self.success_status:
            if status not in self.success_status:
                return False
        elif not (200 <= status < 300):
            return False
        if self.success_body_regex is not None:
            return re.search(self.success_body_regex, body) is not None
        return True

    def render_headers(self, raw_key: str) -> dict[str, str]:
        """Header dict with ``{key}`` replaced by the live secret (in memory)."""
        return {k: v.replace(_KEY_PLACEHOLDER, raw_key) for k, v in self.headers.items()}

    def render_url(self, raw_key: str) -> str:
        """URL with ``{key}`` replaced by the live secret (in memory).

        Some providers (e.g. Twilio) carry the identifier in the path, not a
        header, so the placeholder can appear in the URL too.
        """
        return self.url.replace(_KEY_PLACEHOLDER, raw_key)

    def safe_curl(self) -> str:
        """A copy-pasteable curl with the secret replaced by ``$KEY``.

        Never contains the raw value: the placeholder stays ``$KEY`` wherever
        ``{key}`` appears (header *or* URL) so an operator substitutes their
        own copy. Safe to print and to store.
        """
        parts = ["curl", "-sS", "-X", self.method]
        for header_name, header_value in self.headers.items():
            shown = header_value.replace(_KEY_PLACEHOLDER, "$KEY")
            parts += ["-H", _shquote(f"{header_name}: {shown}")]
        parts.append(_shquote(self.url.replace(_KEY_PLACEHOLDER, "$KEY")))
        return " ".join(parts)


@dataclass(frozen=True)
class ProviderSpec:
    """A declarative provider: how to recognise its key and ladder it.

    Attributes:
        name: Provider display name, e.g. ``"openai"``.
        detectors: TruffleHog ``DetectorName`` values this spec serves; used
            to register the generic ladder for those detectors.
        key_regex: Pattern a raw secret must match for this spec to apply
            (e.g. ``r"^sk-[A-Za-z0-9]"`` for OpenAI). Used by
            :func:`spec_for_detector` fallback matching.
        rungs: Ordered rungs. SAFE rungs first by convention; the runner
            stops climbing once a rung errors at the transport level.
        docs: Optional human note recorded in evidence.
    """

    name: str
    detectors: tuple[str, ...] = ()
    key_regex: str | None = None
    rungs: tuple[RungSpec, ...] = ()
    docs: str = ""

    def matches_key(self, raw_key: str) -> bool:
        """True if ``raw_key`` looks like this provider's secret."""
        if not self.key_regex:
            return False
        return re.search(self.key_regex, raw_key) is not None


# --------------------------------------------------------------------------
# Built-in specs.
#
# Every provider now ships as a dedicated ladder module (see providers/*.py), so
# there are no built-in declarative specs. The generic spec runner below remains
# available as a runtime extensibility layer: operators can register their own
# providers at runtime via load_specs_from_yaml() / register_spec() without
# touching the engine. An empty BUILTIN_SPECS means the generic ladder is a pure
# fallback — it only fires for detectors an operator wires in themselves.
# --------------------------------------------------------------------------
BUILTIN_SPECS: tuple[ProviderSpec, ...] = ()


# --------------------------------------------------------------------------
# Spec registry (separate from the ladder registry in providers/__init__).
# --------------------------------------------------------------------------

# Detector name (lowercased) -> spec. Lets the generic ladder find its spec.
_SPECS_BY_DETECTOR: dict[str, ProviderSpec] = {}


def register_spec(spec: ProviderSpec) -> ProviderSpec:
    """Index ``spec`` by each of its detector names and return it.

    Re-registering a detector overwrites the previous spec (last wins),
    matching the ladder registry's semantics.
    """
    for detector in spec.detectors:
        _SPECS_BY_DETECTOR[detector.lower()] = spec
    return spec


def spec_for_detector(detector_name: str, raw_key: str = "") -> ProviderSpec | None:
    """Find a spec for a detector name, falling back to key-shape matching.

    First tries an exact (case-insensitive) detector match. If none and a
    ``raw_key`` is supplied, scans specs whose ``key_regex`` matches the key
    shape — so a leak labelled with an unfamiliar detector still ladders if
    its value looks like a known provider's key.
    """
    spec = _SPECS_BY_DETECTOR.get(detector_name.lower())
    if spec is not None:
        return spec
    if raw_key:
        for candidate in _SPECS_BY_DETECTOR.values():
            if candidate.matches_key(raw_key):
                return candidate
    return None


def _register_builtins() -> None:
    for spec in BUILTIN_SPECS:
        register_spec(spec)


_register_builtins()


# --------------------------------------------------------------------------
# YAML loading — the runtime extensibility layer.
# --------------------------------------------------------------------------


def load_specs_from_yaml(text: str, *, register: bool = True) -> list[ProviderSpec]:
    """Parse provider specs from YAML and (by default) register them.

    The YAML is a list of provider mappings, each with ``name``,
    ``detectors``, optional ``key_regex``/``docs``, and a list of ``rungs``.
    A rung mapping mirrors :class:`RungSpec`. ``tier`` is ``"safe"`` or
    ``"gated"`` (default safe). Unknown rung keys are ignored so future
    fields do not break old loaders.

    This never performs network I/O; it only builds (and optionally
    registers) immutable specs. A malformed rung raises ``ValueError`` at
    load time (e.g. a billable SAFE rung), which is the right place to fail
    — long before any probe runs.
    """
    import yaml

    raw = yaml.safe_load(text) or []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("provider YAML must be a list of provider mappings")

    specs: list[ProviderSpec] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise ValueError("each provider entry must be a mapping")
        rungs = tuple(_rung_from_mapping(r) for r in entry.get("rungs", []))
        spec = ProviderSpec(
            name=str(entry["name"]),
            detectors=tuple(str(d) for d in entry.get("detectors", ())),
            key_regex=entry.get("key_regex"),
            rungs=rungs,
            docs=str(entry.get("docs", "")),
        )
        specs.append(spec)
        if register:
            register_spec(spec)
    return specs


def _rung_from_mapping(data: Mapping[str, Any]) -> RungSpec:
    tier_raw = str(data.get("tier", "safe")).lower()
    tier = ProbeTier.GATED if tier_raw == "gated" else ProbeTier.SAFE
    success_status = tuple(int(s) for s in data.get("success_status", ()))
    return RungSpec(
        name=str(data["name"]),
        method=str(data.get("method", "GET")).upper(),
        url=str(data["url"]),
        tier=tier,
        headers={str(k): str(v) for k, v in dict(data.get("headers", {})).items()},
        billable=bool(data.get("billable", False)),
        success_status=success_status,
        success_body_regex=data.get("success_body_regex"),
        detail=str(data.get("detail", "")),
        manual=bool(data.get("manual", False)),
    )


# --------------------------------------------------------------------------
# The runner — turns a spec into ordered ProbeResults, then a Verdict.
# --------------------------------------------------------------------------


async def run_spec_ladder(
    spec: ProviderSpec,
    finding: Finding,
    consent: Consent,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[ProbeResult]:
    """Run a spec's rungs in order and return one :class:`ProbeResult` each.

    SAFE rungs run by default. GATED rungs go through
    :func:`vtx_recon.safety.guard`; if consent is not fully granted the
    guard raises and we record a *blocked* rung (``blocked=True``,
    ``success=False``) without any network call. MANUAL rungs never call the
    network — they record the safe curl. Never raises: transport errors and
    blocks become ProbeResults.

    ``client`` is injectable so tests pass a mocked transport; in production
    the caller (or this function) owns a real :class:`httpx.AsyncClient`.
    """
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
    try:
        return [await _run_rung(rung, spec, finding, consent, client) for rung in spec.rungs]
    finally:
        if owns_client:
            await client.aclose()


async def _run_rung(
    rung: RungSpec,
    spec: ProviderSpec,
    finding: Finding,
    consent: Consent,
    client: httpx.AsyncClient,
) -> ProbeResult:
    """Execute (or block, or describe) a single rung. Never raises."""
    probe_name = f"{spec.name}.{rung.name}"

    # Enforce the safety boundary for GATED rungs BEFORE any I/O. For SAFE
    # rungs guard() is a no-op; for GATED it raises without consent.
    try:
        guard(consent, tier=rung.tier, probe_name=probe_name)
    except GatedProbeBlocked as blocked:
        return ProbeResult(
            name=rung.name,
            tier=rung.tier,
            success=False,
            blocked=True,
            detail=f"GATED rung blocked by safety boundary: {blocked.reason}.",
            evidence={"safe_curl": rung.safe_curl(), "billable": rung.billable},
        )

    # MANUAL rungs: never auto-run; hand the operator the exact safe curl.
    if rung.manual:
        return ProbeResult(
            name=rung.name,
            tier=rung.tier,
            success=False,
            blocked=False,
            detail=f"MANUAL: no safe automated probe; run this by hand: {rung.safe_curl()}",
            evidence={"safe_curl": rung.safe_curl(), "manual": True},
        )

    return await _send(rung, finding, client)


async def _send(
    rung: RungSpec,
    finding: Finding,
    client: httpx.AsyncClient,
) -> ProbeResult:
    """Issue the HTTP probe for a (already consent-checked) rung. Never raises."""
    headers = rung.render_headers(finding.raw)
    url = rung.render_url(finding.raw)
    try:
        response = await client.request(rung.method, url, headers=headers)
    except httpx.HTTPError as exc:  # transport / timeout / DNS — never escape.
        return ProbeResult(
            name=rung.name,
            tier=rung.tier,
            success=False,
            detail=f"probe could not reach {rung.url}: {type(exc).__name__}",
            evidence={"error": type(exc).__name__, "safe_curl": rung.safe_curl()},
        )

    body = response.text or ""
    ok = rung.is_success(response.status_code, body)
    detail = rung.detail or (
        "capability confirmed" if ok else f"capability refused (HTTP {response.status_code})"
    )
    # Evidence carries only non-secret signal; redact_mapping at serialise
    # time is defence-in-depth, and we never store the raw key or full body.
    evidence: dict[str, object] = {
        "status_code": response.status_code,
        "key": redact(finding.raw),
        "safe_curl": rung.safe_curl(),
        "body_snippet": body[:200],
    }
    return ProbeResult(
        name=rung.name,
        tier=rung.tier,
        success=ok,
        detail=detail,
        evidence=redact_mapping(evidence),
    )


def _verdict_from_rungs(rungs: Sequence[ProbeResult]) -> Verdict:
    """Derive the impact tier from the rungs that ran.

    PROVEN: a GATED rung actually ran and succeeded (impact exercised).
    VALID:  at least one SAFE rung succeeded (depth of access proved).
    DENIED: rungs ran but none succeeded (key dead or fully unprivileged).
    N/A:    nothing actionable ran (only manual/blocked rungs, or no rungs).
    """
    ran = [r for r in rungs if not r.blocked and "manual" not in r.evidence]
    if any(r.tier is ProbeTier.GATED and r.success for r in ran):
        return Verdict.PROVEN
    if any(r.tier is ProbeTier.SAFE and r.success for r in ran):
        return Verdict.VALID
    if ran:
        return Verdict.DENIED
    return Verdict.NA


async def generic_ladder(
    finding: Finding,
    consent: Consent,
    *,
    client: httpx.AsyncClient | None = None,
) -> LadderResult:
    """Capability ladder for any spec-described provider. Never raises.

    Refuses to ladder without a named authorized scope (records it in the
    result), finds the spec for the finding, runs its rungs, and tiers the
    impact. An unknown provider (no spec) yields a single MANUAL-style note
    and an ``N/A`` verdict rather than an error.
    """
    # The whole ladder — even its safe tier — requires a named scope. This
    # raises ScopeRequired, which is a deliberate, documented public error
    # (the caller must name the engagement); it is not a probe failure.
    scope = consent.require_ladder_scope()

    spec = spec_for_detector(finding.detector_name, finding.raw)
    if spec is None:
        note = ProbeResult(
            name="no-spec",
            tier=ProbeTier.SAFE,
            success=False,
            detail=(
                f"no generic spec for detector {finding.detector_name!r}; "
                "add one in BUILTIN_SPECS or via load_specs_from_yaml()."
            ),
            evidence={"detector": finding.detector_name, "manual": True},
        )
        return LadderResult(
            finding=finding,
            provider="generic",
            verdict=Verdict.NA,
            rungs=[note],
            authorized_scope=scope,
        )

    rungs = await run_spec_ladder(spec, finding, consent, client=client)
    return LadderResult(
        finding=finding,
        provider=spec.name,
        verdict=_verdict_from_rungs(rungs),
        rungs=rungs,
        authorized_scope=scope,
    )


def _shquote(value: str) -> str:
    """Minimal single-quote shell quoting for the printable safe curl."""
    return "'" + value.replace("'", "'\\''") + "'"


# Register the generic ladder for every detector any built-in spec serves, so
# a Finding with one of those detector names routes straight here. New YAML
# specs registered at runtime are reachable via spec_for_detector(); to also
# wire a new detector into the ladder registry call register(...)(generic_ladder).
_builtin_detectors = tuple(d for spec in BUILTIN_SPECS for d in spec.detectors)
register(*_builtin_detectors)(generic_ladder)
