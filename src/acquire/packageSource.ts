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
import type { PackageLayout, PackageMeta, ServerSurface, SkippedFile, SourceFile } from '../types.js';
import { SOURCE_EXTENSIONS } from '../data/sourcePatterns.js';
import { detectArchiveKind, extractTar, extractZip, gunzipBounded, stripCommonRoot, type ArchiveEntry } from './archive.js';
import { LAYOUT_FILES, packageMetaFromJson, SIDECAR_MANIFESTS, SOURCE_LIMITS, SOURCE_MAP_LIMITS } from './source.js';
import { sourceMapPathsFor } from '../util/sourceMap.js';
import { LICENSE_FILE } from '../util/license.js';
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
  /** Entry-point / license metadata and the files skipped by a size limit. */
  layout: PackageLayout;
  /** SHA-256 (hex) of the verified compressed artifact. */
  tarballSha256: string;
  /** Source maps of the generated files (attribution only, never scanned as code). */
  sourceMaps: SourceFile[];
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
  /**
   * The registry's final HTTP status for a refused download; null when no
   * complete answer arrived. Not `status`: a web framework reads that as its
   * own response status (see RegistryUnavailableError).
   */
  readonly registryStatus?: number | null;
  /**
   * The host could not hand the bytes over THIS time — 408, 425, 429, 5xx, a
   * network error, the download timer, a body cut short of its declared length.
   * It says nothing about the package, so a registry scan rethrows it as a
   * retryable error instead of recording it (see attachPublishedSource).
   */
  readonly transient: boolean;
  constructor(kind: PackageSourceErrorKind, message: string, opts: { status?: number | null; transient?: boolean } = {}) {
    super(message);
    this.name = 'PackageSourceError';
    this.kind = kind;
    if (opts.status !== undefined) this.registryStatus = opts.status;
    this.transient = opts.transient ?? false;
  }
}

/** Statuses that mean "try again later", not "no such artifact" (same set as npm.ts). */
function isTransientStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

/**
 * A download that never got a complete answer — a network error, or the
 * download timer firing before or during the body. Worded for a scan queue that
 * reads the CLI's stderr: "could not be reached" is a hiccup to retry, while
 * "timed out", "aborted" and "terminated" read there as the artifact's own
 * ceiling and spend one of its tries — so those words, which the runtime's own
 * messages carry, are never passed through.
 */
export function unreachable(err: unknown): PackageSourceError {
  const e = err as { name?: unknown; message?: unknown; cause?: { code?: unknown } } | null;
  let why: string;
  if (e?.name === 'AbortError' || e?.name === 'TimeoutError') {
    why = `no complete answer within ${DOWNLOAD_TIMEOUT_MS} ms`;
  } else {
    const code = typeof e?.cause?.code === 'string' ? ` (${e.cause.code.slice(0, 40)})` : '';
    const text = String(e?.message ?? err ?? 'network error').slice(0, 120) + code;
    // undici says "terminated" for a socket closed mid-body, "UND_ERR_ABORTED" …
    why = /timed out|aborted|terminated/i.test(text) ? 'the connection closed early' : text;
  }
  return new PackageSourceError('network', `artifact download failed: the registry could not be reached (${why})`, {
    status: null,
    transient: true,
  });
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
    if (!res.ok) {
      throw new PackageSourceError('network', `artifact download failed: HTTP ${res.status}`, {
        status: res.status,
        transient: isTransientStatus(res.status),
      });
    }
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
    // A body that ends short of its declared length is a dropped connection, not
    // the artifact: hashed, it would read as an integrity failure (tamper
    // evidence), and unpacked, as a corrupt archive. Only an identity-encoded
    // body is compared — a content-encoded one declares its compressed length.
    const encoding = (res.headers.get('content-encoding') ?? 'identity').trim().toLowerCase();
    if (declared > 0 && total < declared && encoding === 'identity') {
      throw new PackageSourceError(
        'network',
        `artifact download failed: the registry could not be reached to finish the body (${total} of ${declared} bytes arrived)`,
        { status: res.status, transient: true },
      );
    }
    return Buffer.concat(chunks);
  } finally {
    clearTimeout(timer);
  }
}

const SIDECAR_NAMES = new Set<string>([...LAYOUT_FILES, ...SIDECAR_MANIFESTS]);

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
export function classifyArchiveEntries(
  entries: ArchiveEntry[],
  skipped: SkippedFile[] = [],
  maps: ArchiveEntry[] = [],
): { sourceFiles: SourceFile[]; sidecars: Record<string, string>; layout: PackageLayout; sourceMaps: SourceFile[] } {
  const sourceFiles: SourceFile[] = [];
  const sidecars: Record<string, string> = {};
  const licenseFiles: string[] = [];
  const stripped = stripCommonRoot(entries);
  // The shared top directory that stripCommonRoot removed, so skipped paths read the same way.
  const root = stripped !== entries && entries[0] ? entries[0].path.slice(0, entries[0].path.indexOf('/') + 1) : '';
  for (const e of stripped) {
    if (!e.path.includes('/') && SIDECAR_NAMES.has(e.path)) sidecars[e.path] = e.data.toString('utf8');
    if (!e.path.includes('/') && LICENSE_FILE.test(e.path)) licenseFiles.push(e.path);
    if (isSourcePath(e.path)) sourceFiles.push({ path: e.path, content: e.data.toString('utf8') });
  }
  // Code-unit sort (never localeCompare) so order is reproducible on every machine.
  sourceFiles.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  // Maps sit beside the source, under the same shared root.
  const sourceMaps: SourceFile[] = maps
    .map((e) => ({ path: root && e.path.startsWith(root) ? e.path.slice(root.length) : e.path, content: e.data.toString('utf8') }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const files: Record<string, string> = {};
  for (const n of LAYOUT_FILES) if (sidecars[n] !== undefined) files[n] = sidecars[n]!;
  const layout: PackageLayout = {
    files,
    licenseFiles: licenseFiles.sort(),
    skipped: skipped
      .map((k) => ({ ...k, path: root && k.path.startsWith(root) ? k.path.slice(root.length) : k.path }))
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
  };
  return { sourceFiles, sidecars, layout, sourceMaps };
}

/** The extraction predicate: implementation source + shallow sidecar files. */
export function wantedSourceEntry(path: string): boolean {
  const parts = path.split('/');
  // Sidecars and license files only at the archive root or one level down (the pre-strip root dir).
  const base = parts[parts.length - 1]!;
  if (parts.length <= 2 && (SIDECAR_NAMES.has(base) || LICENSE_FILE.test(base))) return true;
  return isSourcePath(path);
}

/**
 * Extract an artifact's implementation source AND the source maps of its
 * generated files, decompressing once. The source read is exactly the bounded
 * {@link SOURCE_LIMITS} read every scan has always done; the maps are a second
 * read under their own {@link SOURCE_MAP_LIMITS}, restricted to the paths the
 * extracted files point at (`<file>.map`, or what `sourceMappingURL` names) — so
 * a large map can neither evict real source nor drag in unrelated `.map` files.
 */
export function extractPackageArchive(
  buf: Buffer,
  nameHint: string,
  skipped: SkippedFile[],
): { entries: ArchiveEntry[]; maps: ArchiveEntry[] } {
  const kind = detectArchiveKind(buf, nameHint);
  const body = kind === 'tgz' ? gunzipBounded(buf) : buf;
  const read = (wanted: (path: string) => boolean, limits: typeof SOURCE_LIMITS | typeof SOURCE_MAP_LIMITS, sk?: SkippedFile[]): ArchiveEntry[] =>
    kind === 'zip' ? extractZip(body, wanted, limits, sk) : extractTar(body, wanted, limits, sk);
  const entries = read(wantedSourceEntry, SOURCE_LIMITS, skipped);
  const want = new Set<string>();
  for (const e of entries) {
    if (!/\.[cm]?js$/i.test(e.path)) continue;
    const tail = e.data.subarray(Math.max(0, e.data.length - 2048)).toString('utf8');
    for (const p of sourceMapPathsFor(e.path, tail)) want.add(p);
  }
  // A map that is not read is not a coverage gap: the source itself was read.
  const maps = want.size ? read((p) => want.has(p), SOURCE_MAP_LIMITS) : [];
  return { entries, maps };
}

/**
 * Fetch, verify and extract the published source of a registry package.
 * Throws a descriptive error on any trust failure (bad host, over-cap, hash
 * mismatch); returns `null` when the metadata has no artifact URL to read.
 * Every download failure arrives as a {@link PackageSourceError}: one that got
 * no complete answer (network error, the download timer) is `transient`.
 */
export async function fetchPackageSource(
  meta: PackageMeta,
  fetchImpl: typeof fetch = fetch,
): Promise<PackageSourceResult | null> {
  if (!meta.tarballUrl) return null;
  const registry = meta.registry === 'pypi' ? 'pypi' : 'npm';
  const url = assertTrustedTarballUrl(meta.tarballUrl, registry);
  let buf: Buffer;
  try {
    buf = await downloadCapped(url, registry, fetchImpl);
  } catch (err) {
    throw err instanceof PackageSourceError ? err : unreachable(err);
  }
  verifyTarballIntegrity(buf, meta.tarballIntegrity);
  const tarballSha256 = createHash('sha256').update(buf).digest('hex');
  const skipped: SkippedFile[] = [];
  const { entries, maps } = extractPackageArchive(buf, url.pathname, skipped);
  return { ...classifyArchiveEntries(entries, skipped, maps), tarballSha256 };
}

/**
 * Build a scan surface from a local packed artifact (.tgz / .tar.gz / .tar /
 * .zip / .whl) — the file a release pipeline actually ships. Reads the
 * implementation source and any package.json / sidecar manifest it contains;
 * never writes to disk, never executes anything.
 */
export function surfaceFromArchiveFile(path: string): ServerSurface {
  const buf = readFileSync(path);
  const skipped: SkippedFile[] = [];
  const { entries, maps } = extractPackageArchive(buf, path, skipped);
  const { sourceFiles, sidecars, layout, sourceMaps } = classifyArchiveEntries(entries, skipped, maps);

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
  surface.packageLayout = layout;
  if (sourceMaps.length) surface.sourceMaps = sourceMaps;
  return surface;
}
