/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Best-effort package-metadata resolution for the supply-chain stage. Network
 * access is opt-in (`--online`); everything degrades gracefully offline.
 */

import type { PackageMeta } from '../types.js';
import { classifyPublisher } from './publisher.js';

async function getJson(url: string, timeoutMs = 8000): Promise<unknown> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'mcptrustchecker' } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
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
export function pickNpmRepoUrl(pkg: Record<string, any>, v: Record<string, any> | undefined): string | null {
  const fromRepo = normalizeRepoUrl(v?.repository ?? pkg?.repository);
  if (fromRepo) return fromRepo;
  for (const cand of [v?.homepage, pkg?.homepage, v?.bugs?.url, pkg?.bugs?.url, v?.bugs, pkg?.bugs]) {
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
 * otherwise falls back to the `latest` dist-tag.
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
      meta.license = typeof v.license === 'string' ? v.license : v.license == null ? null : String(v.license);
      meta.repositoryUrl = pickNpmRepoUrl(packument, v);
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
  const downloads = (await getJson(`https://api.npmjs.org/downloads/point/last-week/${encoded}`)) as
    | { downloads?: number }
    | null;
  meta.weeklyDownloads = downloads?.downloads ?? null;

  return meta;
}

/**
 * Fetch PyPI metadata for a package. When `requested` is an exact version, the
 * versioned JSON endpoint (`/pypi/<name>/<version>/json`) is used so a pinned
 * spec is analyzed rather than the newest release.
 */
export async function fetchPypiMeta(name: string, requested?: string): Promise<PackageMeta> {
  const meta: PackageMeta = { registry: 'pypi', name };
  const url = isExactVersion(requested)
    ? `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(requested)}/json`
    : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
  const data = (await getJson(url)) as
    | Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    | null;
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
    meta.license = data.info.license || null;
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
    // Publisher identity + verification from the PyPI document (PEP 740
    // attestations), same contract as npm and the hosted API.
    const identity = classifyPublisher('pypi', name, data, meta.repositoryUrl ?? null);
    meta.publisher = identity.publisher;
    meta.vendor = identity.vendor;
    meta.verification = identity.verification;
  } else if (isExactVersion(requested)) {
    // The exact version endpoint returned nothing: the pinned version is not
    // resolvable (unpublished/yanked/hidden). Flag it rather than falling back.
    meta.version = requested;
    meta.requestedVersionMissing = true;
  }
  return meta;
}
