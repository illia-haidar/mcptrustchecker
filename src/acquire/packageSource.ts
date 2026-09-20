/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Read the *published bytes* of a registry package — fetch the npm/PyPI
 * artifact, verify it against the registry-declared hash, and extract its
 * implementation source in memory. This is what turns a bare-package scan from
 * a metadata check into a real source-level analysis: the same MTC-SRC engine
 * that runs on a local directory runs on the exact tarball users install.
 *
 * Security posture:
 *   - network only in `--online` mode, and only to the registry's own artifact
 *     host (allowlisted per registry) over https;
 *   - the download is size-capped and integrity-verified BEFORE it is parsed —
 *     a mismatched hash aborts the source read;
 *   - nothing is written to disk and nothing is executed;
 *   - the verified artifact's SHA-256 is recorded so the lockfile can pin the
 *     actual bytes (same version + different bytes on rescan = rug-pull signal).
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { PackageMeta, ServerSurface, SourceFile } from '../types.js';
import { SOURCE_EXTENSIONS } from '../data/sourcePatterns.js';
import { extractArchive, stripCommonRoot, type ArchiveEntry } from './archive.js';
import { packageMetaFromJson, SIDECAR_MANIFESTS, SOURCE_LIMITS } from './source.js';
import { surfaceFromManifest } from './manifest.js';
import { isBlockedHost } from './live.js';

/** Compressed-artifact download cap. */
const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024; // 50 MB
const DOWNLOAD_TIMEOUT_MS = 30_000;

/**
 * Hosts a registry is allowed to serve artifacts from. The tarball URL comes
 * from the registry response, so we pin it to the registry's own artifact CDN —
 * a compromised or spoofed metadata response can't point the scanner at an
 * arbitrary server.
 */
export type ArtifactSource = 'npm' | 'pypi' | 'github';

const TARBALL_HOSTS: Record<ArtifactSource, string[]> = {
  npm: ['registry.npmjs.org'],
  pypi: ['files.pythonhosted.org'],
  // GitHub's tarball endpoint answers on api.github.com and 302s to codeload.
  github: ['api.github.com', 'codeload.github.com'],
};

export interface PackageSourceResult {
  sourceFiles: SourceFile[];
  /** Root-level sidecar files (package.json, tools.json, …) by base name. */
  sidecars: Record<string, string>;
  /** SHA-256 (hex) of the verified compressed artifact. */
  tarballSha256: string;
}

/**
 * Error kinds for a failed source read, so the caller can tell a SECURITY
 * failure (bytes don't match the registry's declared hash, or the download was
 * redirected off the allowlisted host — hard evidence of tampering) apart from
 * a transient network failure (which must not be reported as an attack, but
 * also must not silently pass off as "verified").
 */
export type PackageSourceErrorKind = 'integrity' | 'untrusted-redirect' | 'network' | 'other';

export class PackageSourceError extends Error {
  readonly kind: PackageSourceErrorKind;
  constructor(kind: PackageSourceErrorKind, message: string) {
    super(message);
    this.name = 'PackageSourceError';
    this.kind = kind;
  }
}

/** Validate that an artifact URL is https on the registry's own artifact host. */
export function assertTrustedTarballUrl(url: string, registry: ArtifactSource): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new PackageSourceError('untrusted-redirect', `invalid artifact URL "${url}"`);
  }
  if (parsed.protocol !== 'https:') throw new PackageSourceError('untrusted-redirect', `artifact URL must be https (got ${parsed.protocol}//)`);
  if (!TARBALL_HOSTS[registry].includes(parsed.hostname) || isBlockedHost(parsed.hostname)) {
    throw new PackageSourceError(
      'untrusted-redirect',
      `artifact host "${parsed.hostname}" is not a trusted ${registry} artifact host (${TARBALL_HOSTS[registry].join(', ')}) — refusing to fetch`,
    );
  }
  return parsed;
}

/**
 * Verify a downloaded artifact against the registry-declared hash. Accepts SRI
 * (`sha512-<base64>`, `sha1-<base64>`) and `<algo>:<hex>` forms. Fails closed:
 * a declared hash that can't be parsed or doesn't match rejects the artifact.
 * `null`/absent means the registry declared none — the artifact is still used
 * (its own SHA-256 becomes the lockfile pin), which is the TOFU trade-off.
 */
export function verifyTarballIntegrity(buf: Buffer, expected: string | null | undefined): void {
  if (!expected) return;
  let algo: string;
  let digest: string;
  let encoding: 'hex' | 'base64';
  const sri = expected.match(/^([a-z0-9]+)-([A-Za-z0-9+/=]+)$/);
  const hexForm = expected.match(/^([a-z0-9]+):([0-9a-f]+)$/i);
  if (sri) {
    algo = sri[1]!;
    digest = sri[2]!;
    encoding = 'base64';
  } else if (hexForm) {
    algo = hexForm[1]!.toLowerCase();
    digest = hexForm[2]!.toLowerCase();
    encoding = 'hex';
  } else {
    throw new PackageSourceError('integrity', `unparseable integrity value "${expected.slice(0, 40)}" — refusing the artifact`);
  }
  let actual: string;
  try {
    actual = createHash(algo).update(buf).digest(encoding);
  } catch {
    throw new PackageSourceError('integrity', `unsupported integrity algorithm "${algo}" — refusing the artifact`);
  }
  const normActual = encoding === 'hex' ? actual.toLowerCase() : actual;
  if (normActual !== digest) {
    throw new PackageSourceError(
      'integrity',
      `artifact integrity mismatch: registry declared ${algo} ${digest.slice(0, 16)}… but the download hashed to ${normActual.slice(0, 16)}…`,
    );
  }
}

/**
 * Download with a hard byte cap enforced while streaming, and a timeout.
 * Redirects are followed MANUALLY (cap 5) and every hop is re-validated through
 * the same host allowlist — otherwise a 3xx from the registry could point the
 * scanner at an arbitrary host (SSRF), and its bytes would be scanned and pinned
 * as if they were the published source. Mirrors live.ts's guardedFetch posture.
 */
export async function downloadCapped(
  url: URL,
  registry: ArtifactSource,
  fetchImpl: typeof fetch = fetch,
): Promise<Buffer> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DOWNLOAD_TIMEOUT_MS);
  try {
    let current = assertTrustedTarballUrl(url.href, registry);
    let res: Response | undefined;
    for (let hop = 0; hop < 6; hop++) {
      res = await fetchImpl(current, {
        signal: ctrl.signal,
        redirect: 'manual',
        headers: { 'User-Agent': 'mcptrustchecker' },
      });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) throw new PackageSourceError('network', `artifact redirect (${res.status}) without a Location header`);
        // Re-run the redirect target through the full host allowlist.
        current = assertTrustedTarballUrl(new URL(loc, current).href, registry);
        continue;
      }
      break;
    }
    if (!res) throw new PackageSourceError('network', 'artifact download produced no response');
    if (res.status >= 300 && res.status < 400) throw new PackageSourceError('network', 'too many artifact redirects');
    if (!res.ok) throw new PackageSourceError('network', `artifact download failed: HTTP ${res.status}`);
    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > MAX_DOWNLOAD_BYTES) {
      throw new PackageSourceError(
        'network',
        `artifact is ${Math.round(declared / 1024 / 1024)} MB — over the ${MAX_DOWNLOAD_BYTES / 1024 / 1024} MB safety cap`,
      );
    }
    if (!res.body) throw new PackageSourceError('network', 'artifact download returned no body');
    const reader = res.body.getReader();
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_DOWNLOAD_BYTES) {
        ctrl.abort();
        throw new PackageSourceError('network', `artifact exceeded the ${MAX_DOWNLOAD_BYTES / 1024 / 1024} MB download cap`);
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  } finally {
    clearTimeout(timer);
  }
}

const SIDECAR_NAMES = new Set<string>(['package.json', ...SIDECAR_MANIFESTS]);

/**
 * Directories skipped inside a published artifact. Deliberately NARROWER than
 * the local-directory skip list: a repo checkout is scanned via its authored
 * source (dist/ is a build product to skip), but a published tarball often
 * ships ONLY dist/ — those compiled bytes ARE what `npx` runs, so they must be
 * read, not skipped.
 */
const ARCHIVE_SKIP_DIRS = new Set([
  'node_modules', '.git', 'coverage', '__pycache__', 'venv', '.venv',
  // Vendored/bundled third-party trees: their code is not the server's own, so an
  // eval/exec inside a copied dependency must not be attributed to the server.
  'vendor', 'third_party', 'third-party', 'bundled', '.cache', '.yarn',
]);

function isSourcePath(path: string): boolean {
  const parts = path.split('/');
  if (parts.some((p) => ARCHIVE_SKIP_DIRS.has(p))) return false;
  const base = parts[parts.length - 1]!;
  const dot = base.lastIndexOf('.');
  const ext = dot >= 0 ? base.slice(dot).toLowerCase() : '';
  return SOURCE_EXTENSIONS.has(ext);
}

/**
 * Split extracted entries into implementation source and root-level sidecars.
 * `stripCommonRoot` unwraps a SINGLE shared top directory (npm's `package/`, a
 * PyPI sdist's `name-version/`, a GitHub source-zip's `repo-main/`) and leaves
 * multi-root archives (wheels: `pkg/` + `pkg.dist-info/`) untouched — so a
 * root-level `package.json`/`tools.json` is found in every real layout. Output
 * is sorted by path so the scan is byte-identical regardless of archive order.
 */
export function classifyArchiveEntries(entries: ArchiveEntry[]): { sourceFiles: SourceFile[]; sidecars: Record<string, string> } {
  const sourceFiles: SourceFile[] = [];
  const sidecars: Record<string, string> = {};
  for (const e of stripCommonRoot(entries)) {
    if (!e.path.includes('/') && SIDECAR_NAMES.has(e.path)) sidecars[e.path] = e.data.toString('utf8');
    if (isSourcePath(e.path)) sourceFiles.push({ path: e.path, content: e.data.toString('utf8') });
  }
  // Code-unit sort (never localeCompare) so order is reproducible on every machine.
  sourceFiles.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { sourceFiles, sidecars };
}

/** The extraction predicate: implementation source + shallow sidecar files. */
export function wantedSourceEntry(path: string): boolean {
  const parts = path.split('/');
  // Sidecars only at the archive root or one level down (the pre-strip root dir).
  if (parts.length <= 2 && SIDECAR_NAMES.has(parts[parts.length - 1]!)) return true;
  return isSourcePath(path);
}

/**
 * Fetch, verify and extract the published source of a registry package.
 * Throws a descriptive error on any trust failure (bad host, over-cap, hash
 * mismatch); returns `null` when the metadata has no artifact URL to read.
 */
export async function fetchPackageSource(
  meta: PackageMeta,
  fetchImpl: typeof fetch = fetch,
): Promise<PackageSourceResult | null> {
  if (!meta.tarballUrl) return null;
  const registry = meta.registry === 'pypi' ? 'pypi' : 'npm';
  const url = assertTrustedTarballUrl(meta.tarballUrl, registry);
  const buf = await downloadCapped(url, registry, fetchImpl);
  verifyTarballIntegrity(buf, meta.tarballIntegrity);
  const tarballSha256 = createHash('sha256').update(buf).digest('hex');
  const entries = extractArchive(buf, url.pathname, wantedSourceEntry, SOURCE_LIMITS);
  return { ...classifyArchiveEntries(entries), tarballSha256 };
}

/**
 * Build a scan surface from a local packed artifact (.tgz / .tar.gz / .tar /
 * .zip / .whl) — the file a release pipeline actually ships. Reads the
 * implementation source and any package.json / sidecar manifest it contains;
 * never writes to disk, never executes anything.
 */
export function surfaceFromArchiveFile(path: string): ServerSurface {
  const buf = readFileSync(path);
  const entries = extractArchive(buf, path, wantedSourceEntry, SOURCE_LIMITS);
  const { sourceFiles, sidecars } = classifyArchiveEntries(entries);

  let manifest: unknown = {};
  for (const name of SIDECAR_MANIFESTS) {
    if (sidecars[name]) {
      try {
        manifest = JSON.parse(sidecars[name]!);
      } catch {
        /* ignore an unparseable sidecar manifest */
      }
      break;
    }
  }

  const surface = surfaceFromManifest(manifest, path, path);
  surface.source = { kind: 'package', origin: path };
  const fromPkg = sidecars['package.json'] ? packageMetaFromJson(sidecars['package.json']) : undefined;
  surface.packageMeta = {
    ...(fromPkg ?? { registry: 'unknown' as const }),
    ...(surface.packageMeta ?? {}),
    tarballSha256: createHash('sha256').update(buf).digest('hex'),
  };
  surface.sourceFiles = sourceFiles;
  return surface;
}
