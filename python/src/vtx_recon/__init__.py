"""vtx-recon: an authorized-use secret-intelligence suite.

Pipeline: find (TruffleHog) -> verify -> capability ladder -> impact tier
(PROVEN / VALID / DENIED / N/A) -> court-ready evidence bundle.

vtx-recon is READ-ONLY by default. Every billable, PII-reading,
state-changing, or resource-creating probe is "gated" and is structurally
unreachable unless the caller passes BOTH ``--prove`` and
``--i-am-authorized "<scope>"``. See :mod:`vtx_recon.safety` for the
enforced boundary.

AUTHORIZED USE ONLY. Running these probes against systems you are not
explicitly authorized to test may violate the US CFAA, the UK Computer
Misuse Act, and equivalent laws. See TERMS.md.
"""

__all__ = ["__version__"]

# Keep in lockstep with [project].version in pyproject.toml.
__version__ = "0.2.0"
