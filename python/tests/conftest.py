"""Shared pytest fixtures for the vtx-recon test suite.

The provider registry is module-global state populated once at import time by
``vtx_recon.providers._load_builtin_providers``. A few tests (notably
``test_generic``) deliberately ``clear_registry()`` to exercise the runner in
isolation, which would otherwise leave the registry empty for every test that
runs afterwards — making registration assertions order-dependent.

Re-importing the provider modules does NOT re-run their ``@register`` side
effects (Python caches modules in ``sys.modules``), so we cannot simply reload.
Instead we snapshot the fully-populated registry once at session start and
restore that snapshot in place before every test. A test that clears or
overwrites the registry therefore cannot leak its state into the next module.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from vtx_recon.providers import _REGISTRY

# Snapshot the fully-populated builtin registry at import time, before any test
# has had a chance to clear it.
_BUILTIN_SNAPSHOT = dict(_REGISTRY)


@pytest.fixture(autouse=True)
def _restore_builtin_registry() -> Iterator[None]:
    """Restore the builtin provider registry before every test."""
    _REGISTRY.clear()
    _REGISTRY.update(_BUILTIN_SNAPSHOT)
    yield
