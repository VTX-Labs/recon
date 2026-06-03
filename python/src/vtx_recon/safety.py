"""The safety boundary — the most important module in vtx-recon.

vtx-recon proves *depth of access* by running ordered, READ-ONLY probes
(the "capability ladder"). Some probes, however, are unavoidably dangerous:
they cost the target money, read PII, change state, or create resources
(e.g. Gemini ``generateContent`` / file upload, a billable Google Maps
call, Firebase anonymous signup, a Stripe account read). Those are "gated".

This module enforces — *in code, not just docs* — that a gated probe is
**unreachable** unless the operator has supplied BOTH:

  1. ``--prove``                       -> :attr:`Consent.prove` is ``True``
  2. ``--i-am-authorized "<scope>"``   -> :attr:`Consent.authorized_scope`
                                          is a non-empty string

The guarantee is structural: a :class:`ProbeTier.GATED` probe that runs
without satisfying consent raises :class:`GatedProbeBlocked` *before* any
network call. There is no flag, env var, or config that can run a gated
probe with only one of the two conditions met — both are required, every
time, and the authorized scope is recorded into the evidence bundle.

Capability laddering as a whole also refuses to run without an authorized
scope; see :func:`Consent.require_ladder_scope`.

AUTHORIZED USE ONLY. See TERMS.md.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, ParamSpec, TypeVar

__all__ = [
    "Consent",
    "GatedProbeBlocked",
    "ProbeTier",
    "SafetyError",
    "ScopeRequired",
    "gated",
    "guard",
]


class ProbeTier(str, Enum):
    """How dangerous a probe is.

    ``SAFE`` probes are read-only, non-billable, and idempotent: listing
    models, ``GetCallerIdentity``, ``auth.test``, reading token scopes.
    They run by default and the safe tier is structurally unable to reach
    a gated endpoint.

    ``GATED`` probes are billable / PII-reading / state-changing /
    resource-creating. They are blocked unless consent is fully granted.
    """

    SAFE = "safe"
    GATED = "gated"


class SafetyError(RuntimeError):
    """Base class for every safety-boundary violation."""


class ScopeRequired(SafetyError):
    """Raised when capability laddering is attempted with no authorized scope.

    The capability ladder (even its safe tier) refuses to run unless the
    operator has named the engagement they are authorized to test, so that
    name can be written into the evidence bundle.
    """


class GatedProbeBlocked(SafetyError):
    """Raised when a GATED probe is invoked without full consent.

    This is the hard boundary. It is raised *before* the probe body runs,
    so no billable / state-changing network call is ever made.
    """

    def __init__(self, probe_name: str, reason: str) -> None:
        self.probe_name = probe_name
        self.reason = reason
        super().__init__(
            f"Gated probe {probe_name!r} blocked: {reason}. "
            "Gated probes are billable, PII-reading, state-changing, or "
            "resource-creating and require BOTH --prove and "
            '--i-am-authorized "<scope>".'
        )


@dataclass(frozen=True)
class Consent:
    """The operator's authorization, captured once and passed everywhere.

    Immutable on purpose: a probe cannot mutate its own consent to escalate
    its tier mid-run.

    Attributes:
        prove: ``True`` only if ``--prove`` was passed. Required (but not
            sufficient) to reach a gated probe.
        authorized_scope: The exact ``--i-am-authorized "<scope>"`` string
            naming the engagement (e.g. a HackerOne program slug or signed
            statement-of-work id). Recorded verbatim in the evidence bundle.
            ``None`` means no scope was supplied.
    """

    prove: bool = False
    authorized_scope: str | None = None

    @property
    def has_scope(self) -> bool:
        """True if a non-empty authorized scope was supplied."""
        return bool(self.authorized_scope and self.authorized_scope.strip())

    @property
    def gated_allowed(self) -> bool:
        """True only if BOTH gating conditions are satisfied.

        This is the single source of truth for whether gated probes may run.
        """
        return self.prove and self.has_scope

    def blocking_reason(self) -> str | None:
        """Why gated probes are blocked, or ``None`` if they're allowed."""
        if not self.prove and not self.has_scope:
            return "neither --prove nor --i-am-authorized was supplied"
        if not self.prove:
            return "--prove was not supplied"
        if not self.has_scope:
            return "--i-am-authorized <scope> was not supplied"
        return None

    def require_ladder_scope(self) -> str:
        """Return the authorized scope, or raise if laddering may not run.

        Call this at the start of *any* capability ladder (safe or gated):
        the whole pipeline refuses to ladder without a named, authorized
        scope so the engagement is always attributable in the evidence
        bundle.
        """
        if not self.has_scope:
            raise ScopeRequired(
                "Capability laddering requires an authorized scope. "
                'Re-run with --i-am-authorized "<engagement scope>".'
            )
        # Narrowed by has_scope; strip to normalise what we record.
        assert self.authorized_scope is not None
        return self.authorized_scope.strip()

    @classmethod
    def denied(cls) -> Consent:
        """A consent that blocks every gated probe (the safe default)."""
        return cls(prove=False, authorized_scope=None)


P = ParamSpec("P")
R = TypeVar("R")


def guard(consent: Consent, *, tier: ProbeTier, probe_name: str) -> None:
    """Enforce the safety boundary for a probe about to run.

    For :attr:`ProbeTier.SAFE` this is a no-op. For
    :attr:`ProbeTier.GATED` it raises :class:`GatedProbeBlocked` unless
    ``consent.gated_allowed`` is true. Call this *before* doing any I/O.

    This is the function form of the boundary; :func:`gated` is the
    decorator form built on top of it.
    """
    if tier is ProbeTier.SAFE:
        return
    if not consent.gated_allowed:
        reason = consent.blocking_reason() or "consent not granted"
        raise GatedProbeBlocked(probe_name, reason)


def gated(
    func_or_name: Callable[P, Awaitable[R]] | str,
) -> Callable[P, Awaitable[R]] | Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Mark an async probe as GATED and enforce consent before it runs.

    Usable two ways:

    * **bare** ``@gated`` — the probe name reported in
      :class:`GatedProbeBlocked` is the wrapped function's ``__qualname__``;
    * **named** ``@gated("provider.action")`` — an explicit, stable probe
      name is reported instead (handy when the qualname is private/mangled).

    Either way the decorated coroutine must accept a :class:`Consent` instance,
    either as the keyword argument ``consent=`` or as its first positional
    argument. Before the wrapped body executes, :func:`guard` is called with
    :attr:`ProbeTier.GATED`; if consent is not fully granted the call raises
    :class:`GatedProbeBlocked` and the body never runs — so no billable or
    state-changing request is issued.

    The function is also tagged ``__vtx_tier__ = ProbeTier.GATED`` so the
    provider registry and tests can assert a probe's tier without invoking
    it.

    Example:
        >>> @gated
        ... async def stripe_account_read(consent: Consent) -> dict: ...
        >>> @gated("sendgrid.send_mail")
        ... async def sendgrid_send_mail(consent: Consent, key: str) -> dict: ...
    """

    def _decorate(
        func: Callable[P, Awaitable[R]], probe_name: str | None
    ) -> Callable[P, Awaitable[R]]:
        name = probe_name or func.__qualname__

        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            consent = _extract_consent(args, kwargs)
            guard(consent, tier=ProbeTier.GATED, probe_name=name)
            return await func(*args, **kwargs)

        # Make the tier introspectable without calling the probe.
        wrapper.__vtx_tier__ = ProbeTier.GATED  # type: ignore[attr-defined]
        return wrapper

    # Named form: @gated("provider.action") -> returns the real decorator.
    if isinstance(func_or_name, str):
        explicit_name = func_or_name

        def decorator(func: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
            return _decorate(func, explicit_name)

        return decorator

    # Bare form: @gated -> decorate directly.
    return _decorate(func_or_name, None)


def _extract_consent(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Consent:
    """Find the Consent a gated probe was called with.

    Looks for ``consent=`` first, then the first positional ``Consent``.
    A gated probe with no reachable consent defaults to the *denied*
    consent, so a misuse fails closed (blocked) rather than open.
    """
    candidate = kwargs.get("consent")
    if isinstance(candidate, Consent):
        return candidate
    for arg in args:
        if isinstance(arg, Consent):
            return arg
    # Fail closed: no consent visible -> treat as denied, which blocks.
    return Consent.denied()
