/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Publisher identity — WHO shipped a package, decided from facts only. This is a
 * client-adoption-risk signal: the SAME engine runs offline, in the registry and
 * in the hosted API, so verification must be an ENGINE signal, not a registry
 * overlay — otherwise the CLI and the registry would disagree on the score.
 *
 * A brand name inside a package name proves nothing ("safari-mcp" is not
 * Apple's), and the `repository` field in a manifest is self-declared — anyone
 * can point it at github.com/microsoft. So identity is established from signals
 * the publisher cannot forge:
 *
 *   1. SOURCE VERIFIED — npm/PyPI publish provenance (Sigstore / SLSA). The
 *      attestation cryptographically binds the published artifact to the exact
 *      repository and CI workflow that built it. This defeats a forged
 *      `repository` field outright.
 *   2. VENDOR VERIFIED — the package additionally belongs to a known vendor,
 *      established either by provenance pointing at a repo that vendor owns, or
 *      by the npm scope itself (only members of the @azure org can publish
 *      @azure/*, so the scope is an authorization fact, not a claim).
 *
 * Registry metadata over HTTP, a signature the registry already publishes, and
 * the reviewable org list below. A badge here says who published the code —
 * never that the code is safe.
 */

import type { Verification } from '../types.js';

/** GitHub/GitLab orgs whose repositories are that vendor's own. Reviewed as
 *  code: adding an entry is a policy decision, visible in the diff. */
export const VENDOR_ORGS = new Map<string, string>(
  Object.entries({
    modelcontextprotocol: 'Model Context Protocol', anthropics: 'Anthropic', openai: 'OpenAI',
    google: 'Google', googleapis: 'Google', 'google-gemini': 'Google', googlecloudplatform: 'Google Cloud',
    microsoft: 'Microsoft', azure: 'Microsoft Azure', 'azure-samples': 'Microsoft Azure',
    aws: 'AWS', awslabs: 'AWS', amazon: 'Amazon', elastic: 'Elastic', stripe: 'Stripe',
    cloudflare: 'Cloudflare', supabase: 'Supabase', notionhq: 'Notion', slackapi: 'Slack',
    atlassian: 'Atlassian', getsentry: 'Sentry', grafana: 'Grafana Labs', mongodb: 'MongoDB',
    'mongodb-js': 'MongoDB', redis: 'Redis', neondatabase: 'Neon', upstash: 'Upstash',
    vercel: 'Vercel', github: 'GitHub', docker: 'Docker', hashicorp: 'HashiCorp', datadog: 'Datadog',
    figma: 'Figma', canva: 'Canva', shopify: 'Shopify', paypal: 'PayPal', twilio: 'Twilio',
    jetbrains: 'JetBrains', 'gitlab-org': 'GitLab', apify: 'Apify', browserbase: 'Browserbase',
    mendableai: 'Firecrawl', 'tavily-ai': 'Tavily', 'exa-labs': 'Exa', 'chroma-core': 'Chroma',
    qdrant: 'Qdrant', 'pinecone-io': 'Pinecone', weaviate: 'Weaviate', snowflakedb: 'Snowflake',
    databricks: 'Databricks', confluentinc: 'Confluent', temporalio: 'Temporal', netlify: 'Netlify',
    heroku: 'Heroku', digitalocean: 'DigitalOcean', linear: 'Linear', asana: 'Asana',
    hubspot: 'HubSpot', salesforce: 'Salesforce', zapier: 'Zapier', 'n8n-io': 'n8n',
    oracle: 'Oracle', ibm: 'IBM', sap: 'SAP', adobe: 'Adobe', 'unity-technologies': 'Unity',
    epicgames: 'Epic Games', apple: 'Apple', mozilla: 'Mozilla', jfrog: 'JFrog',
    sonarsource: 'SonarSource', snyk: 'Snyk', semgrep: 'Semgrep', okta: 'Okta', auth0: 'Auth0',
    '1password': '1Password', bitwarden: 'Bitwarden', huggingface: 'Hugging Face',
    'langchain-ai': 'LangChain', 'run-llama': 'LlamaIndex', pydantic: 'Pydantic', posthog: 'PostHog',
    clickhouse: 'ClickHouse', 'opensearch-project': 'OpenSearch', apache: 'Apache', kubernetes: 'Kubernetes',
    puppeteer: 'Puppeteer', 'cypress-io': 'Cypress', browserstack: 'BrowserStack',
    nvidia: 'NVIDIA', meta: 'Meta', facebook: 'Meta', 'stability-ai': 'Stability AI',
    elevenlabs: 'ElevenLabs', deepgram: 'Deepgram', assemblyai: 'AssemblyAI', 'cohere-ai': 'Cohere',
    mistralai: 'Mistral AI', replicate: 'Replicate', 'modal-labs': 'Modal', planetscale: 'PlanetScale',
    cockroachdb: 'CockroachDB', timescale: 'Timescale', influxdata: 'InfluxData',
    prometheus: 'Prometheus', 'open-telemetry': 'OpenTelemetry', pulumi: 'Pulumi',
    argoproj: 'Argo', jenkinsci: 'Jenkins', circleci: 'CircleCI', sonatype: 'Sonatype',
    perplexityai: 'Perplexity', deepmind: 'Google DeepMind', intel: 'Intel', paloaltonetworks: 'Palo Alto Networks',
  }),
);

/** npm scopes an organisation owns. npm enforces publish rights per scope, so
 *  membership here is an authorization fact rather than a self-declaration. */
export const VENDOR_SCOPES = new Map<string, string>(
  Object.entries({
    modelcontextprotocol: 'Model Context Protocol', 'anthropic-ai': 'Anthropic', openai: 'OpenAI',
    'google-cloud': 'Google Cloud', googleapis: 'Google', azure: 'Microsoft Azure',
    'azure-rest': 'Microsoft Azure', microsoft: 'Microsoft', 'aws-sdk': 'AWS', elastic: 'Elastic',
    stripe: 'Stripe', cloudflare: 'Cloudflare', supabase: 'Supabase', notionhq: 'Notion',
    slack: 'Slack', atlassian: 'Atlassian', sentry: 'Sentry', grafana: 'Grafana Labs',
    mongodb: 'MongoDB', redis: 'Redis', neondatabase: 'Neon', upstash: 'Upstash', vercel: 'Vercel',
    github: 'GitHub', docker: 'Docker', hashicorp: 'HashiCorp', datadog: 'Datadog', figma: 'Figma',
    canva: 'Canva', shopify: 'Shopify', paypal: 'PayPal', twilio: 'Twilio', jetbrains: 'JetBrains',
    gitlab: 'GitLab', apify: 'Apify', browserbasehq: 'Browserbase', mendable: 'Firecrawl',
    tavily: 'Tavily', chroma: 'Chroma', qdrant: 'Qdrant', pinecone: 'Pinecone', weaviate: 'Weaviate',
    snowflake: 'Snowflake', databricks: 'Databricks', temporalio: 'Temporal', netlify: 'Netlify',
    linear: 'Linear', hubspot: 'HubSpot', salesforce: 'Salesforce', n8n: 'n8n', oracle: 'Oracle',
    ibm: 'IBM', sap: 'SAP', adobe: 'Adobe', unity: 'Unity', mozilla: 'Mozilla', jfrog: 'JFrog',
    sonarsource: 'SonarSource', snyk: 'Snyk', semgrep: 'Semgrep', okta: 'Okta', auth0: 'Auth0',
    '1password': '1Password', huggingface: 'Hugging Face', langchain: 'LangChain',
    llamaindex: 'LlamaIndex', pydantic: 'Pydantic', posthog: 'PostHog', clickhouse: 'ClickHouse',
    playwright: 'Microsoft', elevenlabs: 'ElevenLabs', deepgram: 'Deepgram', cohere: 'Cohere',
    mistralai: 'Mistral AI', replicate: 'Replicate', modal: 'Modal', planetscale: 'PlanetScale',
    timescale: 'Timescale', influxdata: 'InfluxData', opentelemetry: 'OpenTelemetry', pulumi: 'Pulumi',
  }),
);

const orgOf = (url: string | null | undefined): string => {
  const m = /(?:github|gitlab|bitbucket)\.[a-z.]+\/([^/]+)\//i.exec(String(url ?? ''));
  return m ? m[1]!.toLowerCase() : '';
};

const scopeOf = (spec: string): string =>
  String(spec).startsWith('@') ? String(spec).slice(1).split('/')[0]!.toLowerCase() : '';

export interface PublisherIdentity {
  publisher: string | null;
  vendor: string | null;
  verification: Verification;
  /**
   * The repository the package DECLARES, kept only when the registry also
   * publishes a build attestation for the scanned artifact. It is NOT proof of
   * ownership: nothing here fetches or parses the attestation subject, so this
   * URL is a claim by the publisher, not a fact about the signature.
   */
  declaredRepo: string | null;
}

/**
 * Decide publisher identity for one package, from the registry document the
 * `--online` scan already fetched. Byte-for-byte the same contract the hosted
 * API uses, so every mode agrees.
 *
 * @param registry npm or pypi
 * @param spec     package name (may carry an `@scope/`)
 * @param doc      the registry document already fetched for the scan
 * @param repoUrl  normalised repository URL from that document
 */
export function classifyPublisher(
  registry: 'npm' | 'pypi',
  spec: string,
  doc: unknown,
  repoUrl: string | null,
  /** The version actually scanned. Omitted ⇒ fall back to `dist-tags.latest`. */
  version?: string,
): PublisherIdentity {
  const d = doc as Record<string, any> | null; // eslint-disable-line @typescript-eslint/no-explicit-any
  const scope = scopeOf(spec);
  let declaredRepo: string | null = null;

  // 1. Provenance: does the registry publish a build attestation for the
  //    version we scanned? npm exposes it on dist; PyPI (PEP 740) on the file.
  if (registry === 'npm' && d) {
    // Read the attestation for the version we actually SCANNED. Reading
    // `dist-tags.latest` instead would report provenance for bytes nobody
    // examined: a pinned 1.0.0 with no attestation inherits the badge from a
    // 2.0.0 published later. Fall back to `latest` only when no version was
    // resolved, which preserves the previous behaviour exactly.
    const latest = typeof d['dist-tags']?.latest === 'string' ? d['dist-tags'].latest : null;
    const target = version && d.versions?.[version] ? version : latest;
    const dist = target ? d.versions?.[target]?.dist : null;
    if (dist?.attestations?.provenance) {
      // An attestation EXISTS for these bytes. Which repository it binds to is a
      // different question — the subject of the payload is never fetched, so all
      // that can honestly be recorded is the repository the package declares.
      declaredRepo = repoUrl ?? null;
    }
  } else if (registry === 'pypi' && Array.isArray(d?.urls)) {
    if (d!.urls.some((u: any) => u?.provenance || (Array.isArray(u?.attestations) && u.attestations.length))) {
      declaredRepo = repoUrl ?? null;
    }
  }

  const org = orgOf(declaredRepo ?? '');
  // 2. Vendor rests on the npm SCOPE alone. npm enforces publish rights per
  //    scope, so `@azure/x` is an authorization fact the publisher cannot forge.
  //    Deriving it from the repository URL instead — as this did until 1.13.0 —
  //    handed the badge to anyone who wrote `repository: github.com/microsoft/…`
  //    in package.json and published with --provenance, which is precisely the
  //    forgery this file's header says identity must not rest on. VENDOR_ORGS is
  //    kept below for the follow-up that reads the real attestation subject.
  const vendor = registry === 'npm' && scope ? VENDOR_SCOPES.get(scope) ?? null : null;

  // Human-readable publisher, preferred in order of how verifiable it is.
  const publisher = vendor ?? (org || null) ?? (scope ? `@${scope}` : null) ?? (orgOf(repoUrl ?? '') || null);

  // Strongest → weakest by what the client can verify: a vendor-authorized
  // publish, then cryptographic provenance, then a merely-declared-but-readable
  // public repository, then nothing locatable. The `repo` tier (self-declared
  // repository, no provenance) is where the bulk of the honest ecosystem sits —
  // it is inspectable, so it is a light discount, not the anonymous-publish gap.
  const verification: Verification = vendor
    ? 'vendor'
    : declaredRepo
      ? 'source'
      : repoUrl
        ? 'repo'
        : 'none';

  return { publisher: publisher ? String(publisher).slice(0, 80) : null, vendor, verification, declaredRepo };
}
