"""Key-shape detection: map a bare secret to the TruffleHog ``DetectorName``
its capability ladder is registered under.

When the operator supplies ``--key <secret>`` directly (rather than piping a
TruffleHog ``--json`` stream), there is no detector name, so we infer it from
the credential's recognizable prefix/shape. The returned name is what the
provider registry keys on (see :mod:`vtx_recon.providers`).

Detection is deliberately conservative: it matches only well-known, distinctive
prefixes. An unknown shape returns ``None`` and the caller falls back to the
generic provider or asks the operator to pass ``--detector``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["KeyMatch", "detect_key"]


@dataclass(frozen=True)
class KeyMatch:
    """A detected provider for a bare key."""

    detector: str
    label: str


# Ordered: more specific prefixes first (Anthropic ``sk-ant-`` before the
# broader OpenAI ``sk-`` rule), so the specific match wins.
_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("Anthropic", "Anthropic key", re.compile(r"^sk-ant-")),
    ("GitHub", "GitHub fine-grained PAT", re.compile(r"^github_pat_")),
    ("GitHub", "GitHub token", re.compile(r"^gh[posru]_[A-Za-z0-9]{20,}$")),
    ("GoogleAI", "Google AI / Gemini key", re.compile(r"^AIza[0-9A-Za-z_-]{35}$")),
    ("AWS", "AWS access key id", re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")),
    ("Slack", "Slack token", re.compile(r"^xox[baprs]-")),
    ("GitLab", "GitLab PAT", re.compile(r"^glpat-")),
    ("Stripe", "Stripe secret key", re.compile(r"^(sk|rk)_(live|test)_[A-Za-z0-9]{10,}$")),
    ("SendGrid", "SendGrid key", re.compile(r"^SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$")),
    ("OpenAI", "OpenAI key", re.compile(r"^sk-(proj-)?[A-Za-z0-9_-]{20,}$")),
    ("DigitalOceanV2", "DigitalOcean token", re.compile(r"^(dop|doo|dor)_v1_[a-f0-9]{64}$")),
    ("NpmToken", "npm token", re.compile(r"^npm_[A-Za-z0-9]{36}$")),
    ("Notion", "Notion token", re.compile(r"^(secret_|ntn_)[A-Za-z0-9]{40,}$")),
    (
        "FigmaPersonalAccessToken",
        "Figma personal access token",
        re.compile(r"^figd_[A-Za-z0-9_-]{40,}$"),
    ),
    ("LinearAPI", "Linear API key", re.compile(r"^lin_api_[A-Za-z0-9]{40}$")),
    (
        "AirtablePersonalAccessToken",
        "Airtable personal access token",
        re.compile(r"^pat[A-Za-z0-9]{14}\.[a-f0-9]{64}$"),
    ),
    (
        "Grafana",
        "Grafana service account token",
        re.compile(r"^glsa_[A-Za-z0-9]{32}_[a-fA-F0-9]{8}$"),
    ),
    ("PlanetScale", "PlanetScale token", re.compile(r"^pscale_tkn_[A-Za-z0-9]{32,}$")),
    ("NewRelicPersonalApiKey", "New Relic personal API key", re.compile(r"^NRAK-[A-Z0-9]{27}$")),
    ("Square", "Square access token", re.compile(r"^EAAA[A-Za-z0-9_-]{60}$")),
    ("ShopifyToken", "Shopify access token", re.compile(r"^shpat_[a-fA-F0-9]{32}$")),
    (
        "TerraformCloudPersonalToken",
        "Terraform Cloud token",
        re.compile(r"^[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}$"),
    ),
    ("SentryToken", "Sentry token", re.compile(r"^sntryu_[a-f0-9]{64}$")),
    ("BitbucketAppPassword", "Bitbucket app password", re.compile(r"^ATBB[A-Za-z0-9]{30,}$")),
    ("Dockerhub", "Docker Hub token", re.compile(r"^dckr_pat_[A-Za-z0-9_-]{27,}$")),
    ("Mailchimp", "Mailchimp key", re.compile(r"^[0-9a-f]{32}-us[0-9]{1,2}$")),
    ("Render", "Render API key", re.compile(r"^rnd_[A-Za-z0-9]{14,}$")),
    ("CircleCI", "CircleCI token", re.compile(r"^CCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}$")),
]


def detect_key(key: str) -> KeyMatch | None:
    """Infer the detector for a bare secret, or ``None`` if the shape is unknown."""
    trimmed = key.strip()
    if not trimmed:
        return None
    for detector, label, pattern in _RULES:
        if pattern.match(trimmed):
            return KeyMatch(detector=detector, label=label)
    return None
