/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Acquire a server's implementation source from a local package directory, so
 * the scan can analyze what the code *does* — not only what its tools *claim*.
 * Bounded (file count, per-file and total size) so a huge repo can't OOM the
 * scan, and never executes any of the code it reads. Offline.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname, sep } from 'node:path';
import type { PackageLayout, ServerSurface, SkippedFile, SourceFile } from '../types.js';
import { LICENSE_FILE, licenseFromNpmManifest, licenseFromPyproject, licenseFromSetupCfg } from '../util/license.js';
import { SOURCE_EXTENSIONS } from '../data/sourcePatterns.js';
import { surfaceFromManifest } from './manifest.js';
import { MAX_SOURCE_MAP_BYTES, sourceMapPathsFor } from '../util/sourceMap.js';

export const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '__pycache__', 'venv', '.venv', 'vendor']);
export const SOURCE_LIMITS = {
  maxFiles: 400,
  // Modern MCP servers ship a single bundled esbuild/tsup `dist` file. A 512 KB
  // cap silently DROPPED those (coverage=metadata, every source detector on zero
  // bytes); 4 MB still dropped the 6–8 MB bundles that inline a whole SDK — and
  // the report then advised "add --online" for a package it HAD downloaded. 16 MB
  // per file, under the unchanged 24 MB total, reads them; the per-file analyses
  // are linear (one lexer pass, one string-state pass), measured at ~1 s for a
  // 6 MB bundle. Anything still over the cap is recorded and named in the report.
  maxFileBytes: 16 * 1024 * 1024, // 16 MB per file
  maxTotalBytes: 24 * 1024 * 1024, // 24 MB total
} as const;
/**
 * Source maps are read under their OWN budget, never the source budget above: a
 * 20 MB map must not evict the bundle it describes. Only maps that sit next to a
 * read source file (`<file>.map`, or the file its `sourceMappingURL` names) are
 * kept, and they are never scanned as code.
 */
export const SOURCE_MAP_LIMITS = {
  maxFiles: 64,
  maxFileBytes: MAX_SOURCE_MAP_BYTES,
  maxTotalBytes: 48 * 1024 * 1024, // 48 MB total
} as const;
const MAX_FILES = SOURCE_LIMITS.maxFiles;
const MAX_FILE_BYTES = SOURCE_LIMITS.maxFileBytes;
const MAX_TOTAL_BYTES = SOURCE_LIMITS.maxTotalBytes;

/** Root-level metadata the analyses read: entry points (reachability) and license. */
export const LAYOUT_FILES = ['package.json', 'pyproject.toml', 'setup.cfg', 'server.json'] as const;

/** Recursively collect scannable source files from a directory (bounded). */
export function readSourceFiles(dir: string, skipped?: SkippedFile[]): SourceFile[] {
  const out: SourceFile[] = [];
  let total = 0;
  const walk = (d: string): void => {
    if (out.length >= MAX_FILES || total >= MAX_TOTAL_BYTES) return;
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const name of entries) {
      if (out.length >= MAX_FILES || total >= MAX_TOTAL_BYTES) return;
      const full = join(d, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name) && !name.startsWith('.')) walk(full);
        continue;
      }
      if (!SOURCE_EXTENSIONS.has(extname(name).toLowerCase())) continue;
      // POSIX separators on every OS, as in a packed artifact: every path rule
      // downstream (test / example / fixture skipping, entry points, layout)
      // reads `/`, so on Windows `tests\test_server.py` slipped past them.
      const path = (relative(dir, full) || name).split(sep).join('/');
      if (st.size > MAX_FILE_BYTES) {
        skipped?.push({ path, bytes: st.size, reason: 'over-per-file-limit' });
        continue;
      }
      try {
        out.push({ path, content: readFileSync(full, 'utf8') });
        total += st.size;
      } catch {
        /* unreadable file — skip */
      }
    }
  };
  walk(dir);
  // `readdirSync` returns filesystem-defined order (APFS vs ext4 differ), and the
  // source detector caps findings per rule — so WITHOUT a stable sort the same
  // package could yield different findings on two machines. Code-unit sort keeps
  // the scan byte-reproducible everywhere (matches util/hash.ts's ordering rule).
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/**
 * The source maps of the generated files in `files`, read from `dir` under
 * {@link SOURCE_MAP_LIMITS}. A map path that would leave `dir` is never read.
 */
export function readSourceMaps(dir: string, files: readonly SourceFile[]): SourceFile[] {
  const out: SourceFile[] = [];
  const seen = new Set<string>();
  let total = 0;
  for (const f of files) {
    for (const rel of sourceMapPathsFor(f.path.replace(/\\/g, '/'), f.content.slice(-2048))) {
      if (seen.has(rel)) continue;
      seen.add(rel);
      if (out.length >= SOURCE_MAP_LIMITS.maxFiles) return out;
      const full = join(dir, rel);
      const back = relative(dir, full);
      if (!back || back.startsWith('..')) continue;
      try {
        const st = statSync(full);
        if (!st.isFile() || st.size > SOURCE_MAP_LIMITS.maxFileBytes || total + st.size > SOURCE_MAP_LIMITS.maxTotalBytes) continue;
        out.push({ path: rel, content: readFileSync(full, 'utf8') });
        total += st.size;
        break; // one map per generated file
      } catch {
        /* no such map — try the next candidate */
      }
    }
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Parse a package.json's text into the surface's package metadata. */
export function packageMetaFromJson(text: string): ServerSurface['packageMeta'] {
  try {
    const pkg = JSON.parse(text) as Record<string, unknown>;
    if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) return undefined;
    return {
      registry: 'npm',
      name: typeof pkg.name === 'string' ? pkg.name : undefined,
      version: typeof pkg.version === 'string' ? pkg.version : undefined,
      scripts: (pkg.scripts as Record<string, string>) ?? undefined,
      dependencies: pkg.dependencies ? Object.keys(pkg.dependencies as object) : undefined,
      license: licenseFromNpmManifest(pkg),
      repositoryUrl:
        typeof pkg.repository === 'string'
          ? pkg.repository
          : ((pkg.repository as { url?: string } | undefined)?.url ?? null),
    };
  } catch {
    return undefined;
  }
}

/** Read a package.json (if present) into the surface's package metadata. */
function readPackageMeta(dir: string): ServerSurface['packageMeta'] {
  const pkgPath = join(dir, 'package.json');
  if (!existsSync(pkgPath)) return undefined;
  try {
    return packageMetaFromJson(readFileSync(pkgPath, 'utf8'));
  } catch {
    return undefined;
  }
}

/**
 * Build a scan surface from a local package directory: its implementation source
 * (for MTC-SRC-* analysis), its package metadata (for supply-chain checks), and
 * a tools manifest if the directory ships one (tools.json / mcp-tools.json).
 */
/** Sidecar manifest file names a package may ship, in priority order. */
export const SIDECAR_MANIFESTS = ['tools.json', 'mcp-tools.json', 'mcp.json'] as const;

export function surfaceFromPackageDir(dir: string): ServerSurface {
  let manifest: unknown = {};
  for (const name of SIDECAR_MANIFESTS) {
    const p = join(dir, name);
    if (existsSync(p)) {
      try {
        manifest = JSON.parse(readFileSync(p, 'utf8'));
      } catch {
        /* ignore an unparseable sidecar manifest */
      }
      break;
    }
  }
  const surface = surfaceFromManifest(manifest, dir, dir);
  surface.source = { kind: 'package', origin: dir };
  surface.packageMeta = { ...readPackageMeta(dir), ...(surface.packageMeta ?? {}) };
  const skipped: SkippedFile[] = [];
  surface.sourceFiles = readSourceFiles(dir, skipped);
  const maps = readSourceMaps(dir, surface.sourceFiles);
  if (maps.length) surface.sourceMaps = maps;
  const layout = readLayout(dir, skipped);
  surface.packageLayout = layout;
  // A Python project (or a JS one that declares nothing in package.json) may
  // declare its license in pyproject.toml / setup.cfg instead.
  if (!surface.packageMeta.license) {
    const declared = licenseFromPyproject(layout.files['pyproject.toml']) ?? licenseFromSetupCfg(layout.files['setup.cfg']);
    if (declared) surface.packageMeta.license = declared;
    else if (surface.packageMeta.license === undefined && (layout.files['pyproject.toml'] || layout.files['setup.cfg'])) surface.packageMeta.license = null;
  }
  return surface;
}

/** Root-level metadata files and license files of a local package directory. */
function readLayout(dir: string, skipped: SkippedFile[]): PackageLayout {
  const files: Record<string, string> = {};
  for (const n of LAYOUT_FILES) {
    const p = join(dir, n);
    if (!existsSync(p)) continue;
    try {
      if (statSync(p).size <= 1024 * 1024) files[n] = readFileSync(p, 'utf8');
    } catch {
      /* unreadable — skip */
    }
  }
  let licenseFiles: string[] = [];
  try {
    licenseFiles = readdirSync(dir).filter((n) => LICENSE_FILE.test(n)).sort();
  } catch {
    /* unreadable directory */
  }
  return { files, licenseFiles, skipped: skipped.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) };
}
