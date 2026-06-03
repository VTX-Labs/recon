/**
 * Provider package entry point.
 *
 * Importing this module wires every bundled provider into the registry as an
 * import side-effect (each provider module calls {@link register} on import),
 * so a single `import "./providers/index.js"` is enough to populate the
 * registry. The CLI never has to know individual module names.
 */

export {
  type Ladder,
  clearRegistry,
  getLadder,
  register,
  registeredDetectors,
} from "./registry.js";

export {
  HttpError,
  httpRequest,
  isSuccess,
  readJson,
  type FetchLike,
  type HttpRequestOptions,
} from "./http.js";

// --- import the bundled providers for their register() side-effects ---------
// Each of these registers its ladder(s) on import.
export { googleLadder, GATED_RUNGS } from "./google.js";
// gcp.ts must be imported AFTER google.ts: both serve the GCP detector; the registry is last-write-wins, so this dedicated service-account-key ladder wins.
export { gcpLadder } from "./gcp.js";
export { awsLadder, signRequest, probeCallerIdentity, probeAccountAuthorizationDetails } from "./aws.js";
export { azureLadder } from "./azure.js";
export { bitbucketLadder, bitbucketGatedCreateRepository, DETECTORS as BITBUCKET_DETECTORS } from "./bitbucket.js";
export { githubLadder, gatedWriteProbe, DETECTORS as GITHUB_DETECTORS } from "./github.js";
export { circleciLadder } from "./circleci.js";
export { datadogLadder, DETECTORS as DATADOG_DETECTORS } from "./datadog.js";
export { hubspotLadder, hubspotListContacts } from "./hubspot.js";
export { intercomLadder, intercomListContacts } from "./intercom.js";
export { linearLadder, linearListOrgUsers } from "./linear.js";
export { cloudflareLadder, cloudflareGatedEditDns, DETECTORS as CLOUDFLARE_DETECTORS } from "./cloudflare.js";
export { algoliaLadder, algoliaClearIndex } from "./algolia.js";
export { airtableLadder, airtableListBaseRecords } from "./airtable.js";
export { asanaLadder, asanaGatedListWorkspaceUsers, DETECTORS as ASANA_DETECTORS } from "./asana.js";
export { digitaloceanLadder, doCreateDropletGated } from "./digitalocean.js";
export { fastlyLadder, fastlyPurgeAll } from "./fastly.js";
export { figmaLadder } from "./figma.js";
export {
  slackLadder,
  slackGatedReadHistory,
  slackGatedPostMessage,
  DETECTORS as SLACK_DETECTORS,
} from "./slack.js";
export { gitlabLadder, DETECTORS as GITLAB_DETECTORS } from "./gitlab.js";
export {
  stripeLadder,
  stripeAccountRead,
  stripeChargesList,
  DETECTORS as STRIPE_DETECTORS,
} from "./stripe.js";
export {
  npmLadder,
  npmGatedPublish,
  DETECTORS as NPM_DETECTORS,
} from "./npm.js";
export {
  discordLadder,
  discordGatedReadHistory,
  discordGatedSendMessage,
  DETECTORS as DISCORD_DETECTORS,
} from "./discord.js";
export {
  twilioLadder,
  twilioGatedBalance,
  DETECTORS as TWILIO_DETECTORS,
} from "./twilio.js";
export { snowflakeLadder, snowflakeExfilTableData } from "./snowflake.js";
export { zendeskLadder, zendeskGatedListTickets, DETECTORS as ZENDESK_DETECTORS } from "./zendesk.js";
export { grafanaLadder, DETECTORS as GRAFANA_DETECTORS } from "./grafana.js";
export { dockerhubLadder, dockerhubDeleteRepository, DETECTORS as DOCKERHUB_DETECTORS } from "./dockerhub.js";
export { supabaseLadder } from "./supabase.js";
export { netlifyLadder, netlifyReadSiteEnv } from "./netlify.js";
export { notionLadder, notionSearchSharedContent } from "./notion.js";
export { newrelicLadder } from "./newrelic.js";
export { pagerdutyLadder, pagerdutyGatedCreateIncident, DETECTORS as PAGERDUTY_DETECTORS } from "./pagerduty.js";
export { paypalLadder, paypalGatedCreatePayout, DETECTORS as PAYPAL_DETECTORS } from "./paypal.js";
export { renderLadder, renderGatedReadEnvVars } from "./render.js";
export { vercelLadder, vercelReadProjectEnv } from "./vercel.js";
export { planetscaleLadder, planetscaleCreateBranch } from "./planetscale.js";
export { postmarkLadder, postmarkSendEmailGated } from "./postmark.js";
export { pypiLadder, pypiPublishPackageGated } from "./pypi.js";
export { travisciLadder } from "./travisci.js";
export { sentryLadder, sentryGatedReadIssues, DETECTORS as SENTRY_DETECTORS } from "./sentry.js";
export { shopifyLadder, shopifyGatedListCustomers, DETECTORS as SHOPIFY_DETECTORS } from "./shopify.js";
export { terraformcloudLadder, terraformcloudCreateRun } from "./terraform-cloud.js";
export { herokuLadder, herokuGatedReadConfigVars } from "./heroku.js";
export { mailgunLadder, mailgunGatedSendMessage, DETECTORS as MAILGUN_DETECTORS } from "./mailgun.js";
export { mailchimpLadder, mailchimpGatedAddMember, DETECTORS as MAILCHIMP_DETECTORS } from "./mailchimp.js";
export { pusherLadder, pusherTriggerEvent } from "./pusher.js";
export { squareLadder, squareCreatePayment } from "./square.js";
export { openaiLadder, openaiChatCompletion, DETECTORS as OPENAI_DETECTORS } from "./openai.js";
export { anthropicLadder, anthropicCreateMessage, DETECTORS as ANTHROPIC_DETECTORS } from "./anthropic.js";
export { sendgridLadder, sendgridSendMail, DETECTORS as SENDGRID_DETECTORS } from "./sendgrid.js";
export {
  genericLadder,
  runSpecLadder,
  loadSpecs,
  specForDetector,
  registerSpec,
  ProviderSpec,
  RungSpec,
  BUILTIN_SPECS,
  type ProviderSpecInput,
  type RungSpecInput,
} from "./generic.js";
