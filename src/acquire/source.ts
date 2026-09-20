/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Acquire a server's implementation source from a local package directory, so
 * the scan can analyze what the code *does* — not only what its tools *claim*.
 * Bounded (file count, per-file and total size) so a huge repo can't OOM the
 * scan, and never executes any of the code it reads. Offline.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { ServerSurface, SourceFile } from '../types.js';
import { SOURCE_EXTENSIONS } from '../data/sourcePatterns.js';
import { surfaceFromManifest } from './manifest.js';

export const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '__pycache__', 'venv', '.venv', 'vendor']);
export const SOURCE_LIMITS = {
  maxFiles: 400,
  // Modern MCP servers ship a single bundled esbuild/tsup `dist` file that is
  // routinely 0.5–4 MB. A 512 KB cap silently DROPPED those, so the package was
  // graded coverage=metadata (−8) AND every source detector ran on zero bytes —
  // an unfair penalty and a security false-negative (a bundled malicious server
  // scored like an empty stub). 4 MB recovers the vast majority of bundled builds.
  maxFileBytes: 4 * 1024 * 1024, // 4 MB per file
  maxTotalBytes: 24 * 1024 * 1024, // 24 MB total
} as const;
const MAX_FILES = SOURCE_LIMITS.maxFiles;
const MAX_FILE_BYTES = SOURCE_LIMITS.maxFileBytes;
const MAX_TOTAL_BYTES = SOURCE_LIMITS.maxTotalBytes;

/** Recursively collect scannable source files from a directory (bounded). */
export function readSourceFiles(dir: string): SourceFile[] {
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
      if (st.size > MAX_FILE_BYTES) continue;
      try {
        out.push({ path: relative(dir, full) || name, content: readFileSync(full, 'utf8') });
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
      license: typeof pkg.license === 'string' ? pkg.license : null,
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
  surface.sourceFiles = readSourceFiles(dir);
  return surface;
}
