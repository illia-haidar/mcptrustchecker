/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Opt-in registry publishing.
 *
 * Publishing sends an **application**, never a verdict. The CLI transmits the
 * package identity (registry + spec, optionally the version) plus an explicit
 * consent flag; the hosted side re-scans that package with its own copy of this
 * engine, and only that server-side scan is ever written to the public registry.
 * A locally computed grade travels along as `localGrade` for comparison only —
 * it is informational and can never become the listed grade. That asymmetry is
 * the whole point: holding an API key must not let anyone publish "grade A" for
 * a malicious package.
 *
 * Nothing here is on by default, nothing here can change a scan's verdict, and
 * every failure is a warning on stderr. Uses only Node built-ins.
 */

import type { Grade, ScanReport } from './types.js';
import type { ResolvedTarget } from './acquire/index.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

/** Default hosted origin. Overridable for self-hosted deployments. */
export const DEFAULT_PUBLISH_URL = 'https://mcptrustchecker.com';

/** Path of the publish endpoint, appended to the origin. */
export const PUBLISH_PATH = '/api/v1/registry/publish';

/** Category slugs the registry accepts. Anything else falls back to `other`. */
export const PUBLISH_CATEGORIES = [
  'ai-agents',
  'ai-memory',
  'developer-tools',
  'api-development',
  'databases',
  'data-science',
  'analytics-monitoring',
  'cloud-devops',
  'security-testing',
  'web-search',
  'browser-automation',
  'files-storage',
  'productivity',
  'communication',
  'content-management',
  'design-media',
  'finance-commerce',
  'marketing-social',
  'business',
  'learning-docs',
  'gaming',
  'lifestyle',
  'other',
] as const;

export type PublishCategory = (typeof PUBLISH_CATEGORIES)[number];

/** A package identity that is eligible for publication. */
export interface PublishTarget {
  registry: 'npm' | 'pypi';
  spec: string;
  version?: string;
}

/** The exact JSON body sent to the publish endpoint. */
export interface PublishRequest {
  registry: 'npm' | 'pypi';
  spec: string;
  version?: string;
  category: PublishCategory;
  /** Always literal `true` — the server rejects anything else. */
  consent: true;
  client: { name: string; version: string };
  /** Informational only. The registry entry always comes from the server's own scan. */
  localGrade?: Grade;
}

/** What the endpoint answers with on success. */
export interface PublishResponse {
  status: 'queued' | 'already-listed';
  registry: string;
  spec: string;
  publicationId?: number;
  url?: string;
  message?: string;
}

export type PublishResult =
  | { ok: true; response: PublishResponse }
  | { ok: false; error: string; status?: number };

export interface PublishOptions {
  /** API key — the same key the hosted scan endpoints take. Required. */
  token: string;
  /** Origin of the deployment (default {@link DEFAULT_PUBLISH_URL}). */
  origin?: string;
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

/** npm/PyPI distribution name, optionally scoped. Mirrors the acquisition rules. */
const PACKAGE_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const HTTP_RE = /^https?:\/\//i;
const ARCHIVE_RE = /\.(tgz|tar\.gz|tar|zip|whl)$/i;

/** Longest name npm accepts; the registry column is sized to match. */
export const MAX_SPEC_LENGTH = 214;

/** Is `spec` a well-formed registry package name we may send? */
export function isValidSpec(spec: string): boolean {
  return spec.length > 0 && spec.length <= MAX_SPEC_LENGTH && PACKAGE_NAME.test(spec);
}

/** Coerce an arbitrary category value to a known slug (default `other`). */
export function normalizeCategory(value?: string): PublishCategory {
  const slug = (value ?? '').trim().toLowerCase();
  return (PUBLISH_CATEGORIES as readonly string[]).includes(slug) ? (slug as PublishCategory) : 'other';
}

/**
 * Does this origin string name a package in a registry, rather than something
 * local? A directory, an archive file, a manifest path and a URL all reach the
 * scanner through `origin` too, and none of them has a registry identity.
 */
function originIsRegistrySpec(origin: string): boolean {
  if (!origin || HTTP_RE.test(origin)) return false;
  if (ARCHIVE_RE.test(origin) || origin.toLowerCase().endsWith('.json')) return false;
  // A scoped package contains a slash but is not a path; anything else with a
  // separator is one.
  const scoped = /^@[a-z0-9-~][a-z0-9-._~]*\/[a-z0-9-~][a-z0-9-._~]*(@[^/\\]+)?$/i.test(origin);
  if (!scoped && (origin.includes('/') || origin.includes('\\'))) return false;
  return true;
}

/**
 * The package identity of a resolved target, or `undefined` when it has none.
 *
 * Publishable: a bare `name` / `@scope/name` package scan, and a client-config
 * entry whose runner installs a named package. Not publishable: a local
 * directory, a packed archive, a tools manifest, a live URL, a spawned stdio
 * command — those have no registry identity to list.
 */
export function publishableTarget(target: ResolvedTarget): PublishTarget | undefined {
  const surface = target.surface;
  const meta = surface.packageMeta;
  const registry = meta?.registry;
  const spec = meta?.name;
  if (!meta || !spec || (registry !== 'npm' && registry !== 'pypi')) return undefined;
  if (!isValidSpec(spec)) return undefined;

  const kind = surface.source?.kind;
  // A package surface may equally have come from a local folder or a .tgz —
  // only accept it when the origin the user typed is itself a registry spec.
  if (kind === 'package' && !originIsRegistrySpec(surface.source.origin)) return undefined;
  // Manifests, live endpoints and ad-hoc stdio spawns are never publishable.
  if (kind !== 'package' && kind !== 'client-config') return undefined;

  const version = typeof meta.version === 'string' && meta.version ? meta.version.slice(0, 64) : undefined;
  return { registry, spec, version };
}

/** Every distinct publishable identity in a batch, in resolution order. */
export function publishableTargets(targets: ResolvedTarget[]): PublishTarget[] {
  const seen = new Set<string>();
  const out: PublishTarget[] = [];
  for (const t of targets) {
    const p = publishableTarget(t);
    if (!p) continue;
    const key = `${p.registry}:${p.spec}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

export interface BuildPublishOptions {
  category?: string;
  /** The local scan of this target, if one ran — used ONLY for `localGrade`. */
  report?: ScanReport;
}

/**
 * Build the request body for one target. Returns `undefined` for a target with
 * no package identity, so callers can skip it silently.
 *
 * `localGrade` is deliberately the only score-shaped field in the body, and the
 * server treats it as a comment: the published grade always comes from the
 * server's own re-scan.
 */
export function buildPublishRequest(
  target: ResolvedTarget | PublishTarget,
  opts: BuildPublishOptions = {},
): PublishRequest | undefined {
  const identity =
    'surface' in target ? publishableTarget(target as ResolvedTarget) : (target as PublishTarget);
  if (!identity || !isValidSpec(identity.spec)) return undefined;
  const body: PublishRequest = {
    registry: identity.registry,
    spec: identity.spec,
    category: normalizeCategory(opts.category),
    consent: true,
    client: { name: TOOL_NAME, version: TOOL_VERSION },
  };
  if (identity.version) body.version = identity.version;
  const grade = opts.report?.score?.grade;
  if (grade) body.localGrade = grade;
  return body;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** Join an origin with the publish path, rejecting anything that isn't http(s). */
export function publishEndpoint(origin: string = DEFAULT_PUBLISH_URL): string | undefined {
  try {
    const u = new URL(origin);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return undefined;
    return `${u.origin}${PUBLISH_PATH}`;
  } catch {
    return undefined;
  }
}

/**
 * POST one publication. Never throws and never retries: a 4xx is a decision, a
 * transport error is an outage, and neither is worth a second request from a
 * scanner whose real job already finished.
 */
export async function publishScan(body: PublishRequest, opts: PublishOptions): Promise<PublishResult> {
  const url = publishEndpoint(opts.origin);
  if (!url) return { ok: false, error: `invalid publish URL "${opts.origin}"` };
  if (!opts.token) return { ok: false, error: 'no API key (set --token or MCPTRUSTCHECKER_TOKEN)' };

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${opts.token}`,
        'User-Agent': `${TOOL_NAME}/${TOOL_VERSION}`,
      },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = {};
    }
    if (!res.ok) {
      const message =
        (parsed && typeof parsed === 'object' && typeof (parsed as { error?: unknown }).error === 'string'
          ? (parsed as { error: string }).error
          : undefined) ?? `HTTP ${res.status}`;
      return { ok: false, error: message, status: res.status };
    }
    return { ok: true, response: parsed as PublishResponse };
  } catch (err) {
    const e = err as Error;
    return { ok: false, error: e.name === 'AbortError' ? 'request timed out' : e.message };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

