/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Repository acquisition: scan an MCP server straight from its GitHub source.
 *
 * Plenty of servers are never published to a registry — they are a repo you are
 * told to clone, or a pre-release you want to read before it ships. Those had no
 * scannable target: a bare `owner/repo` looked like a missing file, and a
 * github.com URL was treated as a live endpoint and failed on content-type.
 *
 * Nothing is cloned, written to disk or executed. The repository's own archive
 * is fetched over https from GitHub's pinned artifact hosts, unpacked **in
 * memory** through the same bounded reader used for npm/PyPI artifacts, and read
 * as source. Every limit that protects a package scan protects this one:
 * size-capped download, redirect re-validation, zip-slip-safe entry paths and a
 * hard unpacked-bytes ceiling.
 *
 * A repository is NOT a released artifact, which the scan states honestly: the
 * default branch moves, and what is on it may not be what a registry ships. The
 * surface is marked `repo` so coverage and provenance never read as a verified
 * package.
 */

import { createHash } from 'node:crypto';
import type { ServerSurface } from '../types.js';
import { extractArchive } from './archive.js';
import { SOURCE_LIMITS, SIDECAR_MANIFESTS, packageMetaFromJson } from './source.js';
import { surfaceFromManifest } from './manifest.js';
import { assertTrustedTarballUrl, downloadCapped, classifyArchiveEntries, wantedSourceEntry } from './packageSource.js';

/** A resolved repository target. `ref` is a branch, tag or commit-ish. */
export interface RepoRef {
  owner: string;
  repo: string;
  ref?: string;
}

// GitHub's own rules: owner is 1–39 of [A-Za-z0-9-] with no leading/trailing
// hyphen; a repo name adds dot and underscore. Anything else never reaches a URL.
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

/**
 * Recognise a repository target: a bare `owner/repo`, an `owner/repo@ref`, or
 * any github.com URL (https, ssh, with or without `.git`, and tolerating a
 * `/tree/<ref>` suffix). Returns undefined when the string is not one — the
 * caller then falls through to its other target shapes, so a package named
 * `@scope/name` is never mistaken for a repository.
 */
export function parseRepoTarget(target: string): RepoRef | undefined {
  const raw = String(target ?? '').trim();
  if (!raw) return undefined;

  let path = raw;
  let ref: string | undefined;

  const url = raw.match(/^(?:https?:\/\/|git@|ssh:\/\/git@)(?:www\.)?github\.com[/:]([^\s?#]+)/i);
  if (url) {
    path = url[1]!;
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.includes('://')) {
    return undefined; // some other scheme — not ours
  } else if (raw.startsWith('.') || raw.startsWith('/') || raw.startsWith('@')) {
    return undefined; // a path, or a scoped package name
  }

  path = path.replace(/\.git$/i, '').replace(/^\/+|\/+$/g, '');

  // github.com/owner/repo/tree/<ref> — keep the ref, drop the rest.
  const tree = path.match(/^([^/]+)\/([^/]+)\/(?:tree|commit)\/([^/]+)/i);
  if (tree) {
    path = `${tree[1]}/${tree[2]}`;
    ref = tree[3];
  }

  const parts = path.split('/');
  if (parts.length !== 2) return undefined;

  let [owner, repo] = parts as [string, string];
  // owner/repo@branch
  const at = repo.lastIndexOf('@');
  if (!url && at > 0) {
    ref = repo.slice(at + 1);
    repo = repo.slice(0, at);
  }
  if (!OWNER.test(owner) || !REPO.test(repo)) return undefined;
  if (ref && !/^[A-Za-z0-9._/-]{1,120}$/.test(ref)) return undefined;
  return { owner, repo, ...(ref ? { ref } : {}) };
}

/** Canonical `owner/repo[@ref]` label for reports and lockfiles. */
export const repoLabel = (r: RepoRef): string => `${r.owner}/${r.repo}${r.ref ? `@${r.ref}` : ''}`;

/** Human URL of the repository (not the artifact URL). */
export const repoHomeUrl = (r: RepoRef): string => `https://github.com/${r.owner}/${r.repo}`;

/**
 * Fetch and scan a repository's source. `ref` defaults to the repository's
 * default branch, chosen by GitHub — which is exactly why the result records
 * the archive's own SHA-256: a "default branch" scan is only reproducible
 * against the bytes it actually read.
 */
export async function surfaceFromGithubRepo(
  ref: RepoRef,
  opts: { token?: string; fetchImpl?: typeof fetch } = {},
): Promise<ServerSurface> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const label = repoLabel(ref);
  const target = `https://api.github.com/repos/${ref.owner}/${ref.repo}/tarball${ref.ref ? `/${ref.ref}` : ''}`;
  const url = assertTrustedTarballUrl(target, 'github');

  const buf = await downloadCapped(url, 'github', authedFetch(fetchImpl, opts.token));
  const entries = extractArchive(buf, 'repo.tar.gz', wantedSourceEntry, SOURCE_LIMITS);
  const { sourceFiles, sidecars } = classifyArchiveEntries(entries);

  let manifest: unknown = {};
  for (const name of SIDECAR_MANIFESTS) {
    if (sidecars[name]) {
      try {
        manifest = JSON.parse(sidecars[name]!);
      } catch {
        /* an unparseable sidecar is not fatal — the source still scans */
      }
      break;
    }
  }

  const surface = surfaceFromManifest(manifest, label, label);
  surface.source = { kind: 'repo', origin: repoHomeUrl(ref) };
  const fromPkg = sidecars['package.json'] ? packageMetaFromJson(sidecars['package.json']) : undefined;
  surface.packageMeta = {
    ...(fromPkg ?? { registry: 'unknown' as const }),
    ...(surface.packageMeta ?? {}),
    // A repository carries no publish provenance: the source is public and
    // readable, which is the `repo` tier — never `source` or `vendor`.
    verification: 'repo',
    publisher: ref.owner,
    repositoryUrl: repoHomeUrl(ref),
    tarballSha256: createHash('sha256').update(buf).digest('hex'),
  };
  surface.sourceFiles = sourceFiles;
  return surface;
}

/**
 * GitHub allows anonymous archive downloads but rate-limits them hard per IP.
 * A token (GITHUB_TOKEN, as CI already sets) lifts that ceiling; it is sent to
 * the pinned GitHub hosts only, and dropped on any redirect elsewhere — the
 * redirect target is re-validated by `downloadCapped` regardless.
 */
function authedFetch(base: typeof fetch, token?: string): typeof fetch {
  const t = (token ?? process.env.GITHUB_TOKEN ?? '').trim();
  if (!t) return base;
  return ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    let sameHost = false;
    try {
      sameHost = new URL(href).hostname === 'api.github.com';
    } catch {
      /* leave credentials off when the URL cannot be parsed */
    }
    const headers = new Headers(init?.headers);
    if (sameHost) headers.set('Authorization', `Bearer ${t}`);
    return base(input, { ...init, headers });
  }) as typeof fetch;
}
