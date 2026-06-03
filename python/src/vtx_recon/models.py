"""Core data model for the find -> verify -> ladder -> tier -> bundle pipeline.

Every dataclass here is JSON-serialisable via :func:`dataclasses.asdict`.
Secrets are *never* stored raw on these objects: a :class:`Finding` carries
only a redacted form plus TruffleHog's own ``Redacted`` string. The raw
secret is held transiently in memory for probing and never written out.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from .redact import redact
from .safety import ProbeTier

__all__ = [
    "EvidenceBundle",
    "Finding",
    "LadderResult",
    "ProbeResult",
    "Verdict",
]


class Verdict(str, Enum):
    """Impact tier for a credential after capability laddering.

    PROVEN: a gated probe ran (with consent) and demonstrated real impact —
        billable access, PII read, or state change was actually exercised.
    VALID: the credential authenticates and safe probes proved depth of
        access, but no gated/impactful action was exercised.
    DENIED: the credential is live but every probed capability was refused
        (e.g. authenticates yet has no usable scopes).
    NA: not applicable — the credential could not be verified, or the
        provider has no ladder.
    """

    PROVEN = "PROVEN"
    VALID = "VALID"
    DENIED = "DENIED"
    NA = "N/A"


@dataclass
class Finding:
    """A single candidate secret, typically from TruffleHog.

    The raw secret lives only in :attr:`raw` (kept in memory for probing)
    and is excluded from serialisation by :meth:`to_public`. Use
    :attr:`redacted` / :attr:`detector_redacted` anywhere a value is shown.
    """

    detector_name: str
    verified: bool
    # Held transiently for probing; never persisted. Excluded from to_public().
    raw: str = field(repr=False, default="")
    # TruffleHog's own redacted form (its "Redacted" field), if provided.
    detector_redacted: str = ""
    # Extra detector context (e.g. the paired AWS account / region). May
    # itself contain secrets, so it is redacted before serialisation.
    extra_data: dict[str, object] = field(default_factory=dict)
    source: str = ""

    @property
    def redacted(self) -> str:
        """Our own prefix+mask of the raw secret (never the raw value)."""
        return self.detector_redacted or redact(self.raw)

    def to_public(self) -> dict[str, object]:
        """Serialisable view with no raw secret material."""
        from .redact import redact_mapping

        return {
            "detector_name": self.detector_name,
            "verified": self.verified,
            "redacted": self.redacted,
            "extra_data": redact_mapping(dict(self.extra_data)),
            "source": self.source,
        }


@dataclass
class ProbeResult:
    """The outcome of one capability-ladder probe (one rung)."""

    name: str
    tier: ProbeTier
    # True if the probe ran and the capability was confirmed present.
    success: bool
    # Short human-readable summary, e.g. "token has repo, read:org scopes".
    detail: str = ""
    # Non-secret evidence (status code, returned identity, scope list...).
    # Redacted on serialisation as defence in depth.
    evidence: dict[str, object] = field(default_factory=dict)
    # True if this rung was a gated probe that was blocked by the safety
    # boundary (consent not granted). Distinct from a probe that ran and
    # failed.
    blocked: bool = False

    def to_public(self) -> dict[str, object]:
        from .redact import redact_mapping

        return {
            "name": self.name,
            "tier": self.tier.value,
            "success": self.success,
            "blocked": self.blocked,
            "detail": self.detail,
            "evidence": redact_mapping(dict(self.evidence)),
        }


@dataclass
class LadderResult:
    """All rungs run for a single finding, plus the resulting impact tier."""

    finding: Finding
    provider: str
    verdict: Verdict
    rungs: list[ProbeResult] = field(default_factory=list)
    # The authorized scope under which this ladder was run (recorded for the
    # evidence bundle; required by the safety boundary to ladder at all).
    authorized_scope: str = ""

    def to_public(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "verdict": self.verdict.value,
            "authorized_scope": self.authorized_scope,
            "finding": self.finding.to_public(),
            "rungs": [r.to_public() for r in self.rungs],
        }


@dataclass
class EvidenceBundle:
    """A timestamped, court-ready record of an authorized engagement.

    Contains only redacted secrets and a "no state changed" attestation
    that is true unless a gated probe was actually exercised under consent.
    Render to JSON for machines and Markdown for a human report.
    """

    authorized_scope: str
    tool_version: str
    results: list[LadderResult] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    # Set False only when a PROVEN/gated probe actually changed state.
    no_state_changed: bool = True

    def to_public(self) -> dict[str, object]:
        return {
            "tool": "vtx-recon",
            "tool_version": self.tool_version,
            "authorized_scope": self.authorized_scope,
            "created_at": self.created_at,
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at)),
            "no_state_changed_attestation": self.no_state_changed,
            "results": [r.to_public() for r in self.results],
        }
