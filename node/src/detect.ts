/**
 * Key-shape detection: map a bare secret to the TruffleHog `DetectorName` that
 * its capability ladder is registered under.
 *
 * When the operator supplies `--key <secret>` directly (rather than piping a
 * TruffleHog `--json` stream), we have no detector name — so we infer it from
 * the credential's recognizable prefix/shape. The returned name is what the
 * provider registry keys on (see `providers/registry.ts`).
 *
 * Detection is deliberately conservative: it only matches well-known, distinctive
 * prefixes. An unknown shape returns `null`, and the caller can fall back to the
 * generic provider or ask the operator to pass `--detector`.
 */

export interface KeyMatch {
  /** The TruffleHog DetectorName the ladder registry is keyed on. */
  detector: string;
  /** A human label for output. */
  label: string;
}

interface Rule {
  detector: string;
  label: string;
  test: (key: string) => boolean;
}

const RULES: Rule[] = [
  { detector: "GitHub", label: "GitHub token", test: (k) => /^gh[posru]_[A-Za-z0-9]{20,}$/.test(k) },
  { detector: "GitHub", label: "GitHub fine-grained PAT", test: (k) => k.startsWith("github_pat_") },
  { detector: "GoogleAI", label: "Google AI / Gemini key", test: (k) => /^AIza[0-9A-Za-z_-]{35}$/.test(k) },
  { detector: "AWS", label: "AWS access key id", test: (k) => /^(AKIA|ASIA)[0-9A-Z]{16}$/.test(k) },
  { detector: "Slack", label: "Slack token", test: (k) => /^xox[baprs]-/.test(k) },
  { detector: "GitLab", label: "GitLab PAT", test: (k) => k.startsWith("glpat-") },
  { detector: "Stripe", label: "Stripe secret key", test: (k) => /^(sk|rk)_(live|test)_[A-Za-z0-9]{10,}$/.test(k) },
  { detector: "OpenAI", label: "OpenAI key", test: (k) => /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/.test(k) },
  { detector: "Anthropic", label: "Anthropic key", test: (k) => k.startsWith("sk-ant-") },
  { detector: "SendGrid", label: "SendGrid key", test: (k) => /^SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/.test(k) },
  { detector: "DigitalOceanV2", label: "DigitalOcean token", test: (k) => /^(dop|doo|dor)_v1_[a-f0-9]{64}$/.test(k) },
  { detector: "NpmToken", label: "npm token", test: (k) => /^npm_[A-Za-z0-9]{36}$/.test(k) },
  { detector: "Notion", label: "Notion token", test: (k) => /^(secret_|ntn_)[A-Za-z0-9]{40,}$/.test(k) },
  { detector: "FigmaPersonalAccessToken", label: "Figma personal access token", test: (k) => /^figd_[A-Za-z0-9_-]{40,}$/.test(k) },
  { detector: "LinearAPI", label: "Linear API key", test: (k) => /^lin_api_[A-Za-z0-9]{40}$/.test(k) },
  { detector: "AirtablePersonalAccessToken", label: "Airtable personal access token", test: (k) => /^pat[A-Za-z0-9]{14}\.[a-f0-9]{64}$/.test(k) },
  { detector: "Grafana", label: "Grafana service account token", test: (k) => /^glsa_[A-Za-z0-9]{32}_[a-fA-F0-9]{8}$/.test(k) },
  { detector: "PlanetScale", label: "PlanetScale token", test: (k) => /^pscale_tkn_[A-Za-z0-9]{32,}$/.test(k) },
  { detector: "NewRelicPersonalApiKey", label: "New Relic personal API key", test: (k) => /^NRAK-[A-Z0-9]{27}$/.test(k) },
  { detector: "Square", label: "Square access token", test: (k) => /^EAAA[A-Za-z0-9_-]{60}$/.test(k) },
  { detector: "ShopifyToken", label: "Shopify access token", test: (k) => /^shpat_[a-fA-F0-9]{32}$/.test(k) },
  { detector: "TerraformCloudPersonalToken", label: "Terraform Cloud token", test: (k) => /^[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}$/.test(k) },
  { detector: "SentryToken", label: "Sentry token", test: (k) => /^sntryu_[a-f0-9]{64}$/.test(k) },
  { detector: "BitbucketAppPassword", label: "Bitbucket app password", test: (k) => /^ATBB[A-Za-z0-9]{30,}$/.test(k) },
  { detector: "Dockerhub", label: "Docker Hub token", test: (k) => /^dckr_pat_[A-Za-z0-9_-]{27,}$/.test(k) },
  { detector: "Mailchimp", label: "Mailchimp key", test: (k) => /^[0-9a-f]{32}-us[0-9]{1,2}$/.test(k) },
  { detector: "Render", label: "Render API key", test: (k) => /^rnd_[A-Za-z0-9]{14,}$/.test(k) },
  { detector: "CircleCI", label: "CircleCI token", test: (k) => /^CCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}$/.test(k) },
];

/**
 * Infer the detector for a bare secret, or `null` if the shape is unknown.
 * Anthropic's `sk-ant-` is checked before the broader OpenAI `sk-` rule by
 * ordering, so the more specific prefix wins.
 */
export function detectKey(key: string): KeyMatch | null {
  const trimmed = key.trim();
  if (trimmed === "") {
    return null;
  }
  // Anthropic before OpenAI: both start with `sk-`, the former is more specific.
  const ordered = [...RULES].sort((a, b) => (a.detector === "Anthropic" ? -1 : b.detector === "Anthropic" ? 1 : 0));
  for (const rule of ordered) {
    if (rule.test(trimmed)) {
      return { detector: rule.detector, label: rule.label };
    }
  }
  return null;
}
