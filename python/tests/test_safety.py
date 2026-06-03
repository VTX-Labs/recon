"""The safety boundary is the most important guarantee in vtx-recon, so it
gets the most thorough test: a GATED probe must be unreachable unless BOTH
--prove and --i-am-authorized were supplied, and the block must happen before
any probe body runs (fail-closed)."""

from __future__ import annotations

import pytest

from vtx_recon.safety import (
    Consent,
    GatedProbeBlocked,
    ProbeTier,
    ScopeRequired,
    gated,
    guard,
)


def test_safe_probe_always_allowed() -> None:
    # guard() is a no-op for SAFE regardless of consent.
    guard(Consent.denied(), tier=ProbeTier.SAFE, probe_name="list_models")


@pytest.mark.parametrize(
    "consent",
    [
        Consent.denied(),
        Consent(prove=True, authorized_scope=None),  # prove only
        Consent(prove=True, authorized_scope="   "),  # blank scope
        Consent(prove=False, authorized_scope="program-x"),  # scope only
    ],
)
def test_gated_blocked_without_full_consent(consent: Consent) -> None:
    with pytest.raises(GatedProbeBlocked):
        guard(consent, tier=ProbeTier.GATED, probe_name="stripe_account_read")


def test_gated_allowed_with_full_consent() -> None:
    consent = Consent(prove=True, authorized_scope="bugbounty:acme")
    assert consent.gated_allowed is True
    # Should not raise.
    guard(consent, tier=ProbeTier.GATED, probe_name="gemini_generate")


async def test_gated_decorator_blocks_before_body_runs() -> None:
    ran = False

    @gated
    async def dangerous(consent: Consent) -> str:
        nonlocal ran
        ran = True  # must never execute when blocked
        return "did something billable"

    # The decorator tags the tier without invoking the probe.
    assert dangerous.__vtx_tier__ is ProbeTier.GATED

    with pytest.raises(GatedProbeBlocked):
        await dangerous(Consent.denied())
    assert ran is False, "gated body executed despite being blocked"

    # With full consent the body runs.
    out = await dangerous(Consent(prove=True, authorized_scope="acme"))
    assert out == "did something billable"
    assert ran is True


async def test_gated_decorator_fails_closed_without_visible_consent() -> None:
    @gated
    async def dangerous(value: int) -> int:  # no Consent in signature
        return value

    # No Consent reachable -> treated as denied -> blocked.
    with pytest.raises(GatedProbeBlocked):
        await dangerous(1)


def test_require_ladder_scope() -> None:
    with pytest.raises(ScopeRequired):
        Consent.denied().require_ladder_scope()
    with pytest.raises(ScopeRequired):
        Consent(prove=True, authorized_scope=None).require_ladder_scope()
    # Returns the normalised scope when present.
    assert Consent(authorized_scope="  acme  ").require_ladder_scope() == "acme"


def test_consent_is_immutable() -> None:
    import dataclasses

    consent = Consent(prove=True, authorized_scope="acme")
    with pytest.raises(dataclasses.FrozenInstanceError):
        consent.prove = False  # type: ignore[misc]


def test_blocking_reason_messages() -> None:
    assert Consent.denied().blocking_reason() is not None
    assert Consent(prove=True).blocking_reason() is not None
    assert Consent(authorized_scope="x").blocking_reason() is not None
    assert Consent(prove=True, authorized_scope="x").blocking_reason() is None
