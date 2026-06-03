"""Provider registry â€” per-provider capability ladders plug in here.

Each provider module (e.g. ``providers/google.py``, ``providers/aws.py``)
defines an async ladder function and registers it for one or more TruffleHog
``DetectorName`` values via :func:`register`. The CLI looks a finding's
detector up with :func:`get_ladder` to decide how to ladder it.

A ladder is an async callable::

    async def ladder(finding: Finding, consent: Consent) -> LadderResult: ...

It MUST call ``consent.require_ladder_scope()`` before probing, run its
ordered SAFE rungs unconditionally, and reach any GATED rung only through
the :mod:`vtx_recon.safety` boundary (the ``@gated`` decorator or
``guard(...)``). This package intentionally ships no ladders yet â€” they are
added by later modules.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from ..models import Finding, LadderResult
from ..safety import Consent

__all__ = [
    "Ladder",
    "clear_registry",
    "get_ladder",
    "register",
    "registered_detectors",
]

# A provider ladder: (finding, consent) -> LadderResult.
Ladder = Callable[[Finding, Consent], Awaitable[LadderResult]]

# DetectorName (lowercased) -> ladder. TruffleHog detector names are the keys
# so a Finding routes straight to its provider.
_REGISTRY: dict[str, Ladder] = {}


def register(*detector_names: str) -> Callable[[Ladder], Ladder]:
    """Register a ladder for one or more TruffleHog detector names.

    Use as a decorator on a provider's ladder function::

        @register("AWS")
        async def aws_ladder(finding, consent): ...

    Detector names are matched case-insensitively. Re-registering a name
    overwrites the previous ladder (last definition wins).
    """

    def decorator(ladder: Ladder) -> Ladder:
        for name in detector_names:
            _REGISTRY[name.lower()] = ladder
        return ladder

    return decorator


def get_ladder(detector_name: str) -> Ladder | None:
    """Return the registered ladder for a detector, or None if none exists."""
    return _REGISTRY.get(detector_name.lower())


def registered_detectors() -> tuple[str, ...]:
    """Return the detector names that currently have a ladder, sorted."""
    return tuple(sorted(_REGISTRY))


def clear_registry() -> None:
    """Empty the registry. Intended for tests only."""
    _REGISTRY.clear()


def _load_builtin_providers() -> None:
    """Import every bundled provider module so its @register side-effects fire.

    Each provider module registers its ladder(s) on import, so
    ``import vtx_recon.providers`` is enough to fully populate the registry; the
    CLI never has to know individual module names. Kept at the bottom so the
    ``register`` symbol exists before the imports run.
    """
    # gcp loaded AFTER google: both register the "GCP" detector and the registry
    # is last-write-wins, so the dedicated service-account-key ladder must import
    # last to win. Done via importlib (not a top-of-block `from . import`) so the
    # ordered import group above stays alphabetised for isort while this stays last.
    import importlib

    from . import airtable as _airtable  # noqa: F401
    from . import algolia as _algolia  # noqa: F401
    from . import anthropic as _anthropic  # noqa: F401
    from . import asana as _asana  # noqa: F401
    from . import aws as _aws  # noqa: F401
    from . import azure as _azure  # noqa: F401
    from . import bitbucket as _bitbucket  # noqa: F401
    from . import circleci as _circleci  # noqa: F401
    from . import cloudflare as _cloudflare  # noqa: F401
    from . import datadog as _datadog  # noqa: F401
    from . import digitalocean as _digitalocean  # noqa: F401
    from . import discord as _discord  # noqa: F401
    from . import dockerhub as _dockerhub  # noqa: F401
    from . import fastly as _fastly  # noqa: F401
    from . import figma as _figma  # noqa: F401
    from . import generic as _generic  # noqa: F401
    from . import github as _github  # noqa: F401
    from . import gitlab as _gitlab  # noqa: F401
    from . import google as _google  # noqa: F401
    from . import grafana as _grafana  # noqa: F401
    from . import heroku as _heroku  # noqa: F401
    from . import hubspot as _hubspot  # noqa: F401
    from . import intercom as _intercom  # noqa: F401
    from . import linear as _linear  # noqa: F401
    from . import mailchimp as _mailchimp  # noqa: F401
    from . import mailgun as _mailgun  # noqa: F401
    from . import netlify as _netlify  # noqa: F401
    from . import newrelic as _newrelic  # noqa: F401
    from . import notion as _notion  # noqa: F401
    from . import npm as _npm  # noqa: F401
    from . import openai as _openai  # noqa: F401
    from . import pagerduty as _pagerduty  # noqa: F401
    from . import paypal as _paypal  # noqa: F401
    from . import planetscale as _planetscale  # noqa: F401
    from . import postmark as _postmark  # noqa: F401
    from . import pusher as _pusher  # noqa: F401
    from . import pypi as _pypi  # noqa: F401
    from . import render as _render  # noqa: F401
    from . import sendgrid as _sendgrid  # noqa: F401
    from . import sentry as _sentry  # noqa: F401
    from . import shopify as _shopify  # noqa: F401
    from . import slack as _slack  # noqa: F401
    from . import snowflake as _snowflake  # noqa: F401
    from . import square as _square  # noqa: F401
    from . import stripe as _stripe  # noqa: F401
    from . import supabase as _supabase  # noqa: F401
    from . import terraform_cloud as _terraform_cloud  # noqa: F401
    from . import travisci as _travisci  # noqa: F401
    from . import twilio as _twilio  # noqa: F401
    from . import vercel as _vercel  # noqa: F401
    from . import zendesk as _zendesk  # noqa: F401

    importlib.import_module(".gcp", __name__)


_load_builtin_providers()
