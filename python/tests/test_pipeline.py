"""Integration: key detection + the orchestration layer the CLI calls."""

from __future__ import annotations

import pytest

from vtx_recon.detect import detect_key
from vtx_recon.models import Verdict
from vtx_recon.pipeline import build_bundle, finding_from_key, ladder_finding
from vtx_recon.providers import get_ladder, registered_detectors
from vtx_recon.safety import Consent, ScopeRequired


def test_detect_key_maps_prefixes() -> None:
    assert detect_key("ghp_" + "a" * 36).detector == "GitHub"
    assert detect_key("github_pat_" + "x" * 20).detector == "GitHub"
    assert detect_key("AIza" + "b" * 35).detector == "GoogleAI"
    assert detect_key("AKIA" + "C" * 16).detector == "AWS"
    assert detect_key("xoxb-abc").detector == "Slack"
    assert detect_key("glpat-abc").detector == "GitLab"
    assert detect_key("sk_live_" + "d" * 20).detector == "Stripe"
    assert detect_key("sk-ant-xyz").detector == "Anthropic"


def test_detect_key_unknown_and_empty() -> None:
    assert detect_key("not-a-known-key") is None
    assert detect_key("") is None


def test_anthropic_beats_openai_prefix() -> None:
    assert detect_key("sk-ant-api03-abc").detector == "Anthropic"


def test_all_core_providers_registered() -> None:
    # Regression guard: github + aws must be registered (they were silently
    # missing before the providers/__init__ import fix).
    for detector in ("github", "aws", "googleai", "slack", "gitlab", "stripe"):
        assert get_ladder(detector) is not None, f"{detector} ladder not registered"
    assert "github" in registered_detectors()
    assert "aws" in registered_detectors()


def test_finding_from_key_detection_and_override() -> None:
    assert finding_from_key("AIza" + "z" * 35).detector_name == "GoogleAI"
    assert finding_from_key("whatever", "Slack").detector_name == "Slack"
    assert finding_from_key("mystery-token").detector_name == "generic"


async def test_ladder_finding_unknown_provider_is_na() -> None:
    finding = finding_from_key("mystery", "TotallyUnknownProvider")
    result = await ladder_finding(finding, Consent(authorized_scope="test"))
    assert result.verdict is Verdict.NA


async def test_ladder_finding_requires_scope() -> None:
    finding = finding_from_key("ghp_" + "a" * 36)
    with pytest.raises(ScopeRequired):
        await ladder_finding(finding, Consent.denied())


def test_build_bundle_attestation() -> None:
    from vtx_recon.models import Finding, LadderResult

    result = LadderResult(
        finding=Finding(detector_name="x", verified=False),
        provider="x",
        verdict=Verdict.NA,
        authorized_scope="test",
    )
    bundle = build_bundle([result], Consent(authorized_scope="test"), "0.1.0", now=1_700_000_000)
    assert bundle.no_state_changed is True
    assert bundle.to_public()["authorized_scope"] == "test"
