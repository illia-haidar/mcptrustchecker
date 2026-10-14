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
   * publishes a build attestation for the scanned artifact. On npm it is NOT
   * proof of ownership: the attestation subject is never fetched, so this URL is
   * a claim by the publisher, not a fact about the signature. On PyPI it is kept
   * only when it matches the repository the attestation names (or, when the
   * package names none, it IS that repository).
   */
  declaredRepo: string | null;
  /**
   * PyPI only: the repository the PEP 740 attestation of the scanned file names
   * — PyPI checked that binding when the file was uploaded. Set whether or not
   * the attestation counted; null when there is none or its publisher names no
   * repository that can be located.
   */
  attestedRepo: string | null;
  /** PyPI only: the attestation names a different repository than the package declares, so it was not counted. */
  attestationMismatch: boolean;
}

/**
 * The https URL of the repository one PEP 740 publisher (as PyPI's integrity
 * API reports it) binds a file to, or null when its kind names none that can be
 * located. Mirrors the verification policies of PyPI's own `pypi-attestations`:
 * GitHub → github.com/<repository>, GitLab → gitlab.com/<repository> (nested
 * groups allowed), CircleCI → its optional `vcs_origin` ("github.com/org/repo").
 * A Google publisher names a service account, not a repository.
 */
export function attestedRepoOf(publisher: unknown): string | null {
  const p = publisher && typeof publisher === 'object' ? (publisher as Record<string, unknown>) : null;
  const repo = typeof p?.repository === 'string' ? p.repository : '';
  if (p?.kind === 'GitHub' && /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repo)) {
    return `https://github.com/${repo}`;
  }
  if (p?.kind === 'GitLab' && /^[A-Za-z0-9_.-]{1,255}(?:\/[A-Za-z0-9_.-]{1,255}){1,20}$/.test(repo)) {
    return `https://gitlab.com/${repo}`;
  }
  const origin = typeof p?.vcs_origin === 'string' ? p.vcs_origin : '';
  if (p?.kind === 'CircleCI' && /^(?:github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/i.test(origin)) {
    return `https://${origin}`;
  }
  return null;
}

/**
 * The comparable identity of a repository URL: host plus repository path,
 * lower-cased (forges treat owner and repository names case-insensitively).
 * GitHub, Bitbucket and Codeberg name a repository by its first two path
 * segments, so `/tree/main/pkg` or `/blob/main/CHANGELOG.md` are views of it;
 * GitLab nests groups, so its project path runs up to the `/-/` separator.
 */
function repoKey(url: string): string | null {
  const m = /^https?:\/\/(?:www\.)?([^/?#]{1,253})((?:\/[^/?#]{1,255}){0,30})/i.exec(url);
  if (!m) return null;
  const host = m[1]!.toLowerCase();
  let segs = m[2]!.split('/').filter(Boolean);
  if (host === 'gitlab.com') {
    const route = segs.indexOf('-');
    if (route >= 0) segs = segs.slice(0, route);
  } else if (host === 'github.com' || host === 'bitbucket.org' || host === 'codeberg.org') {
    segs = segs.slice(0, 2);
  }
  if (segs.length) segs[segs.length - 1] = segs[segs.length - 1]!.replace(/\.git$/i, '');
  return `${host}/${segs.join('/')}`.toLowerCase();
}

/** Do two repository URLs name the same repository? */
function sameRepo(declared: string, attested: string): boolean {
  const d = repoKey(declared);
  const a = repoKey(attested);
  // A GitLab project cannot share its path with a group, so a declared URL
  // below the attested project path (an old-style `/tree/main` view) is it.
  return !!d && !!a && (d === a || (a.startsWith('gitlab.com/') && d.startsWith(`${a}/`)));
}

/** Forges whose URLs name an owner by the first path segment and a repository by the first two. */
const FORGES = new Set(['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org']);

/**
 * What a declared URL says about the repository: a repository on a forge, an
 * owner's page there (`github.com/owner`), or nothing at all — a website, the
 * `home_page` fallback, a self-hosted forge that cannot be compared. Only a
 * named repository can contradict an attestation.
 */
function declaredScope(url: string | null): { kind: 'repo' | 'owner' | 'none'; key: string } {
  const k = url ? repoKey(url) : null;
  if (!k) return { kind: 'none', key: '' };
  const slash = k.indexOf('/');
  const host = k.slice(0, slash);
  const segs = k.slice(slash + 1).split('/').filter(Boolean);
  if (!FORGES.has(host) || segs.length === 0) return { kind: 'none', key: '' };
  return segs.length === 1 ? { kind: 'owner', key: `${host}/${segs[0]}` } : { kind: 'repo', key: k };
}

/**
 * Read PyPI's PEP 740 provenance for the scanned file against the repository
 * the package declares. Only bundles that carry attestations and whose
 * publisher maps to a repository count; with several, the one matching the
 * declared repository wins. A package that names no repository (a website, or
 * nothing) takes the attested one; one that names only an owner's page must
 * agree with the attested owner.
 */
function readPypiAttestation(
  provenance: unknown,
  repoUrl: string | null,
): { repo: string | null; counted: boolean; mismatch: boolean; namesRepo: boolean } {
  const bundles = (provenance as { attestation_bundles?: unknown } | null)?.attestation_bundles;
  const repos: string[] = [];
  for (const b of Array.isArray(bundles) ? bundles.slice(0, 16) : []) {
    const bundle = b as { publisher?: unknown; attestations?: unknown } | null;
    if (!Array.isArray(bundle?.attestations) || bundle.attestations.length === 0) continue;
    const repo = attestedRepoOf(bundle.publisher);
    if (repo && !repos.includes(repo)) repos.push(repo);
  }
  const scope = declaredScope(repoUrl);
  const namesRepo = scope.kind === 'repo';
  if (repos.length === 0) return { repo: null, counted: false, mismatch: false, namesRepo };
  if (scope.kind === 'none') return { repo: repos[0]!, counted: true, mismatch: false, namesRepo };
  const hit =
    scope.kind === 'repo'
      ? repos.find((r) => sameRepo(repoUrl!, r))
      : repos.find((r) => (repoKey(r) ?? '').startsWith(`${scope.key}/`));
  return hit ? { repo: hit, counted: true, mismatch: false, namesRepo } : { repo: repos[0]!, counted: false, mismatch: true, namesRepo };
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
 * @param pypiProvenance PyPI only: the PEP 740 provenance of the file the scan
 *                 reads (the body of `/integrity/<name>/<version>/<file>/provenance`),
 *                 or null when PyPI has none for it (404). Omitted ⇒ not looked
 *                 up, which reads as no attestation.
 */
export function classifyPublisher(
  registry: 'npm' | 'pypi',
  spec: string,
  doc: unknown,
  repoUrl: string | null,
  /** The version actually scanned. Omitted ⇒ fall back to `dist-tags.latest`. */
  version?: string,
  pypiProvenance?: unknown,
): PublisherIdentity {
  const d = doc as Record<string, any> | null; // eslint-disable-line @typescript-eslint/no-explicit-any
  const scope = scopeOf(spec);
  let declaredRepo: string | null = null;
  let attestedRepo: string | null = null;
  let attestationMismatch = false;

  // 1. Provenance: does the registry publish a build attestation for the
  //    version we scanned? npm exposes it on dist; PyPI (PEP 740) per file,
  //    through its integrity API — never in the JSON document.
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
  } else if (registry === 'pypi') {
    // Until 1.16.1 this looked for `provenance` / `attestations` on the JSON
    // document's `urls[]`, which carry no such field, so no signed PyPI release
    // was ever seen. PyPI publishes the attestation with its publisher in plain
    // JSON (verified by PyPI at upload), so unlike the npm branch above — which
    // accepts the attestation without reading its subject — the repository it
    // names is checked against the one the package declares. A mismatch is not
    // counted (MTC-SUP-016 records it): a reader opening the declared repository
    // would be reading code the release was not built from. A publisher whose
    // repository cannot be located is not counted either.
    const att = readPypiAttestation(pypiProvenance, repoUrl);
    attestedRepo = att.repo;
    attestationMismatch = att.mismatch;
    // The repository a counted attestation is read against: the one the package
    // names, or — when it names only a website or an owner — the attested one.
    if (att.counted) declaredRepo = att.namesRepo ? repoUrl : att.repo;
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

  return {
    publisher: publisher ? String(publisher).slice(0, 80) : null,
    vendor,
    verification,
    declaredRepo,
    attestedRepo,
    attestationMismatch,
  };
}
