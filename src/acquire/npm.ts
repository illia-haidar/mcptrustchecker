/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Best-effort package-metadata resolution for the supply-chain stage. Network
 * access is opt-in (`--online`); everything degrades gracefully offline. Online,
 * a registry that says "not found" is evidence; a registry that cannot answer
 * is not, and throws {@link RegistryUnavailableError} instead of degrading.
 */

import type { PackageMeta } from '../types.js';
import { licenseFromNpmManifest, licenseFromPypiInfo } from '../util/license.js';
import { classifyPublisher } from './publisher.js';

/**
 * The registry could not answer — rate limit, server error, timeout, network
 * failure, an unreadable body, or a refusal other than "not found". It says
 * nothing about the package, so it must never be recorded as a property of it:
 * before 1.16.1 every such failure read as "the pinned version is not published"
 * (MTC-SUP-015) and the scan fell back to metadata coverage, which is how a PyPI
 * hiccup cost two published packages a grade. `retryable` is true for the
 * transient kinds (408, 425, 429, 5xx, network, timeout, truncated body), so a
 * queue can schedule the scan again; `code` lets a caller that only sees a plain
 * error object recognise it without the class. The wording ("the registry
 * answered HTTP 503", "could not be reached", "retry shortly") is what a scan
 * queue reading the CLI's stderr matches to tell a hiccup from a verdict.
 */
export class RegistryUnavailableError extends Error {
  readonly code = 'MTC_REGISTRY_UNAVAILABLE';
  readonly url: string;
  /** The UPSTREAM registry's HTTP status, or null when no response arrived (network error / timeout). */
  readonly registryStatus: number | null;
  /**
   * The status to answer a caller of a service built on this library with:
   * 503 for a retryable failure, 502 for a refusal. Express, Koa, http-errors and
   * the hosted API read `err.status` as their OWN response status, so the
   * registry's code must not sit here — a registry 429 would turn into the
   * service's own 429, a registry 401 into "your credentials were refused", an
   * unreadable 200 into a 200.
   */
  readonly status: 502 | 503;
  readonly retryable: boolean;
  constructor(url: string, registryStatus: number | null, detail: string, retryable: boolean) {
    super(
      retryable
        ? `${detail} for ${url} — a temporary registry failure, not a finding about the package; retry shortly`
        : `${detail} for ${url} — not a finding about the package`,
    );
    this.name = 'RegistryUnavailableError';
    this.url = url;
    this.registryStatus = registryStatus;
    this.status = retryable ? 503 : 502;
    this.retryable = retryable;
  }
}

/**
 * The runtime's reason a request failed, safe to pass on. "timed out",
 * "aborted" and "terminated" (undici's word for a socket closed mid-body) read
 * to a scan queue as the artifact's own time ceiling, so they are reworded —
 * the same scrub the artifact download applies.
 */
function scrubReason(err: unknown): string {
  const e = err as { message?: unknown; cause?: { code?: unknown } } | null;
  const code = typeof e?.cause?.code === 'string' ? ` (${e.cause.code.slice(0, 40)})` : '';
  const text = String(e?.message ?? err ?? 'network error').slice(0, 120) + code;
  return /timed out|aborted|terminated/i.test(text) ? 'the connection closed early' : text;
}

/** Statuses that mean "try again later", not "no such thing". */
function isTransientStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

/**
 * GET a registry JSON document. Returns the parsed body, or null when the
 * registry says the package / version does not exist (404, 410). Every other
 * failure throws {@link RegistryUnavailableError}: a missing document is
 * evidence, an unanswered request is not.
 */
async function getJson(url: string, timeoutMs = 8000): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    let res: Response;
    try {
      res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'mcptrustchecker' } });
    } catch (err) {
      const why = ctrl.signal.aborted ? `no answer within ${timeoutMs} ms` : scrubReason(err);
      throw new RegistryUnavailableError(url, null, `the registry could not be reached (${why})`, true);
    }
    if (res.status === 404 || res.status === 410) return null;
    if (!res.ok) {
      const transient = isTransientStatus(res.status);
      const detail = transient ? `the registry answered HTTP ${res.status}` : `the registry refused the request (HTTP ${res.status})`;
      throw new RegistryUnavailableError(url, res.status, detail, transient);
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch (err) {
      const why = ctrl.signal.aborted ? `no answer within ${timeoutMs} ms` : scrubReason(err);
      throw new RegistryUnavailableError(url, res.status, `the registry answered HTTP ${res.status} with an unreadable body (${why})`, true);
    }
    // `null` here would read as "not found": a document that is not an object is
    // a malformed answer, not a missing package.
    if (body === null || typeof body !== 'object') {
      throw new RegistryUnavailableError(url, res.status, `the registry answered HTTP ${res.status} with an unexpected document`, true);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

/** For an optional figure (weekly downloads): any failure is just "unknown". */
async function getJsonOptional(url: string): Promise<unknown> {
  try {
    return await getJson(url);
  } catch {
    return null;
  }
}

/** Is `v` an exact version (not a range/tag) we can resolve to one artifact? */
function isExactVersion(v?: string): v is string {
  return typeof v === 'string' && /^\d+\.\d+\.\d+/.test(v);
}

/**
 * Normalize the many shapes of a registry "repository" field to a plain https
 * URL, or null. Deterministic string handling — no AI. This is the SINGLE place
 * the engine decides "is there an inspectable public repo", so the CLI, registry
 * and hosted API all derive the same repoUrl and therefore the same verification
 * tier (`repo` vs `none`). Handles `git+`, `git://`, `git@host:owner/repo`,
 * trailing `.git`, and object `{ url }` forms.
 */
export function normalizeRepoUrl(raw: unknown): string | null {
  const candidate = raw && typeof raw === 'object' ? (raw as { url?: unknown }).url : raw;
  if (typeof candidate !== 'string' || !candidate.trim()) return null;
  const u = candidate
    .trim()
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^(ssh:\/\/)?git@([^:/]+)[:/]/, 'https://$2/')
    .replace(/\.git(#.*)?$/, '')
    .replace(/^http:\/\//, 'https://');
  if (!/^https:\/\/[a-z0-9.-]+\//i.test(u)) return null;
  return u.slice(0, 300);
}

/**
 * Best-effort source repository for a PyPI package. PyPI's `project_urls` is a
 * free-form map whose keys vary wildly (`Source`, `Repository`, `Source Code`,
 * `GitHub`, `Code`, `Homepage`…), so scan every key for a repository-ish label,
 * then accept a `Homepage`-style key only when it points at a known forge, and
 * finally fall back to `home_page`. Mirrors the hosted registry exactly — a
 * `Source`-only lookup wrongly demoted ~5k legitimately-public PyPI packages to
 * `none`.
 */
function pickPypiRepoUrl(info: Record<string, unknown>): string | null {
  const rawUrls = info?.project_urls;
  const urls: Record<string, string> =
    rawUrls && typeof rawUrls === 'object' ? (rawUrls as Record<string, string>) : {};
  const keys = Object.keys(urls);
  const key =
    keys.find((k) => /source|repository|github|code/i.test(k)) ??
    keys.find((k) => /home/i.test(k) && /github\.com|gitlab\.com|bitbucket\.org|codeberg\.org/i.test(urls[k] ?? ''));
  return normalizeRepoUrl(key ? urls[key] : info?.home_page);
}

/** Public code forges — a homepage/bugs URL here IS locatable source. */
const CODE_FORGE = /^https:\/\/(www\.)?(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht|gitea\.)/i;

/**
 * Best-effort source repository for an npm package. The explicit `repository`
 * field is strongest, but many legitimate packages (incl. official ones like
 * `@anthropic-ai/claude-code`) omit it and only set `homepage`/`bugs` pointing at
 * their GitHub. Those are accepted as source ONLY when they resolve to a known
 * code forge — a docs `homepage` is not a repository. `/issues|/discussions|/wiki`
 * suffixes (a `bugs.url`) are trimmed back to the repo root.
 */
export function pickNpmRepoUrl(pkg: Record<string, any>, v: Record<string, any> | undefined, pinned = false): string | null {
  // The packument's TOP-LEVEL repository/homepage/bugs mirror the LATEST
  // version. For an exact pinned version they are someone else's answer: a
  // scan of 1.3.0 inherited 1.7.0's repository and passed MTC-SUP-011 for a
  // release that declared none. A pin reads only its own manifest.
  const top = pinned ? undefined : pkg;
  const fromRepo = normalizeRepoUrl(v?.repository ?? top?.repository);
  if (fromRepo) return fromRepo;
  for (const cand of [v?.homepage, top?.homepage, v?.bugs?.url, top?.bugs?.url, v?.bugs, top?.bugs]) {
    const raw = typeof cand === 'string' ? cand : undefined;
    if (!raw) continue;
    const trimmed = raw.replace(/\/(issues|discussions|wiki|pulls?)(\/.*)?$/i, '');
    const norm = normalizeRepoUrl(trimmed);
    if (norm && CODE_FORGE.test(norm)) return norm;
  }
  return null;
}

/**
 * Fetch npm registry metadata for a package. Resolves `requested` when it names
 * an exact published version (so a pinned `pkg@1.0.0` is analyzed, not `latest`);
 * otherwise falls back to the `latest` dist-tag. Throws
 * {@link RegistryUnavailableError} when the registry cannot answer.
 */
export async function fetchNpmMeta(name: string, requested?: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'npm', name };
  const packument = (await getJson(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
  if (packument && typeof packument === 'object') {
    // `dist-tags.latest` is attacker-controlled: accept it ONLY as a string, so a
    // non-primitive (array/object) can't become `meta.version`. A non-string
    // version survives to the lockfile as `["1.0.0"]`, and after the JSON
    // round-trip the `meta.version === entry.packageVersion` check can never be
    // true — silently suppressing the MTC-TOFU-002 byte-level rug-pull finding.
    const latest = typeof packument['dist-tags']?.latest === 'string' ? (packument['dist-tags'].latest as string) : undefined;
    // `versions` is attacker-controlled; guard the `in` check so a non-object
    // (string/number) can't throw a raw TypeError. On the client-config path an
    // unguarded throw would unwind resolveTargets and make the CLI skip the whole
    // config — hiding every sibling server. Fail closed instead.
    const versions =
      packument.versions && typeof packument.versions === 'object' && !Array.isArray(packument.versions)
        ? (packument.versions as Record<string, any>) // eslint-disable-line @typescript-eslint/no-explicit-any
        : {};
    // A pinned exact version that the registry does NOT list must NEVER silently
    // fall back to `latest` — an attacker who controls the registry response
    // could drop the pinned version and serve a malicious `latest`, defeating the
    // byte pin (the requested version's artifact simply isn't resolved, and the
    // substitution is flagged so it can't pass as a clean scan of the pin).
    const wantExact = isExactVersion(requested);
    const requestedMissing = wantExact && !Object.prototype.hasOwnProperty.call(versions, requested);
    const version = wantExact ? requested : (latest ?? Object.keys(versions).pop());
    meta.version = version;
    if (requestedMissing) {
      meta.requestedVersionMissing = true;
      // Leave scripts/deps/artifact unresolved: there is no such published
      // version to read. tarballUrl stays undefined → no source fetch / byte pin.
      return meta;
    }
    const v = version ? packument.versions?.[version] : undefined;
    if (v) {
      meta.scripts = v.scripts ?? {};
      meta.dependencies = Object.keys(v.dependencies ?? {});
      // A pin reads only its own manifest; an unpinned scan may fall back to the
      // packument's top level (which mirrors latest — the version being read).
      meta.license = licenseFromNpmManifest(v) ?? (wantExact ? null : licenseFromNpmManifest(packument));
      meta.repositoryUrl = pickNpmRepoUrl(packument, v, wantExact);
      // The published artifact: URL + registry-declared hash (SRI, or legacy sha1 hex).
      meta.tarballUrl = typeof v.dist?.tarball === 'string' ? v.dist.tarball : null;
      meta.tarballIntegrity =
        typeof v.dist?.integrity === 'string'
          ? v.dist.integrity
          : typeof v.dist?.shasum === 'string'
            ? `sha1:${v.dist.shasum}`
            : null;
    }
    meta.publishedAt = version ? packument.time?.[version] ?? null : null;
    // Publisher identity + verification, from the same document — an ENGINE
    // signal so the CLI, registry and hosted API all agree on the client score.
    const identity = classifyPublisher('npm', name, packument, meta.repositoryUrl ?? null, version);
    meta.publisher = identity.publisher;
    meta.vendor = identity.vendor;
    meta.verification = identity.verification;
  }

  const encoded = encodeURIComponent(name).replace('%40', '@');
  const downloads = (await getJsonOptional(`https://api.npmjs.org/downloads/point/last-week/${encoded}`)) as
    | { downloads?: number }
    | null;
  meta.weeklyDownloads = downloads?.downloads ?? null;

  return meta;
}

/** The file name an artifact URL downloads (its last path segment), or null. */
function fileNameOf(url: string): string | null {
  const path = url.split(/[?#]/, 1)[0] ?? '';
  const base = path.slice(path.lastIndexOf('/') + 1);
  if (!base) return null;
  try {
    return decodeURIComponent(base);
  } catch {
    return base;
  }
}

/**
 * PyPI's PEP 740 provenance for ONE file: the parsed body of
 * `/integrity/<name>/<version>/<file>/provenance`, or null when PyPI has none
 * for that file (404). The name is taken from the artifact URL the scan
 * downloads, so the attestation read is the one for the bytes examined.
 *
 * PyPI's JSON document carries no provenance field on its files, which is why
 * no signed PyPI release was seen before 1.16.1. A failure to answer throws
 * {@link RegistryUnavailableError} exactly as the document fetch does — never
 * "unknown", which would drop the verification term and score a hiccup above an
 * honestly unsigned package.
 */
async function fetchPypiProvenance(name: string, version: string, fileUrl: string): Promise<unknown> {
  const file = fileNameOf(fileUrl);
  if (!file) return null;
  const url =
    `https://pypi.org/integrity/${encodeURIComponent(name)}/${encodeURIComponent(version)}/` +
    `${encodeURIComponent(file)}/provenance`;
  const doc = (await getJson(url)) as { attestation_bundles?: unknown } | null;
  // A 200 without the bundle list is a malformed answer, not "unsigned".
  if (doc !== null && !Array.isArray(doc.attestation_bundles)) {
    throw new RegistryUnavailableError(url, 200, 'the registry answered HTTP 200 with an unexpected document', true);
  }
  return doc;
}

/**
 * Fetch PyPI metadata for a package. When `requested` is an exact version, the
 * versioned JSON endpoint (`/pypi/<name>/<version>/json`) is used so a pinned
 * spec is analyzed rather than the newest release. Throws
 * {@link RegistryUnavailableError} when PyPI cannot answer (429, 5xx, timeout,
 * network) — only its 404 / 410 means the pinned version is missing.
 */
export async function fetchPypiMeta(name: string, requested?: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'pypi', name };
  const url = isExactVersion(requested)
    ? `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(requested)}/json`
    : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
  const data = (await getJson(url)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
  // Only 404 / 410 (null) mean "missing". A 200 whose document has no `info`
  // object is a malformed answer — retry it, never record a missing version.
  if (data !== null && (!data.info || typeof data.info !== 'object')) {
    throw new RegistryUnavailableError(url, 200, 'the registry answered HTTP 200 with an unexpected document', true);
  }
  if (data?.info) {
    // For an exact pin the version-specific endpoint is authoritative for the
    // version, so force the label to the REQUESTED version — never let an
    // attacker-controlled `info.version` relabel the pin to a different release
    // (the same silent-substitution hole the npm path refuses).
    meta.version = isExactVersion(requested)
      ? requested
      : typeof data.info.version === 'string'
        ? data.info.version
        : undefined;
    meta.license = licenseFromPypiInfo(data.info);
    meta.repositoryUrl = pickPypiRepoUrl(data.info);
    // The published artifact: prefer the sdist (real source layout) over a wheel.
    const files = Array.isArray(data.urls) ? data.urls : [];
    const artifact =
      files.find((f: any) => f?.packagetype === 'sdist' && typeof f.url === 'string') ??
      files.find((f: any) => f?.packagetype === 'bdist_wheel' && typeof f.url === 'string');
    if (artifact) {
      meta.tarballUrl = artifact.url;
      meta.tarballIntegrity =
        typeof artifact.digests?.sha256 === 'string' ? `sha256:${artifact.digests.sha256}` : null;
      meta.publishedAt = typeof artifact.upload_time_iso_8601 === 'string' ? artifact.upload_time_iso_8601 : null;
    }
    // Publisher identity + verification, same contract as npm and the hosted
    // API. PEP 740 attestations are read from PyPI's integrity API for the file
    // the scan reads: a wheel's attestation says nothing about the sdist's bytes.
    const provenance =
      meta.tarballUrl && meta.version ? await fetchPypiProvenance(name, meta.version, meta.tarballUrl) : null;
    const identity = classifyPublisher('pypi', name, data, meta.repositoryUrl ?? null, meta.version, provenance);
    meta.publisher = identity.publisher;
    meta.vendor = identity.vendor;
    meta.verification = identity.verification;
    if (identity.attestedRepo) meta.attestedRepositoryUrl = identity.attestedRepo;
    if (identity.attestationMismatch) meta.attestationRepoMismatch = true;
  } else if (isExactVersion(requested)) {
    // The exact version endpoint answered 404 / 410: the pinned version is not
    // resolvable (unpublished/yanked/hidden). Flag it rather than falling back.
    // A failure to answer never reaches here — getJson throws for it.
    meta.version = requested;
    meta.requestedVersionMissing = true;
  }
  return meta;
}
