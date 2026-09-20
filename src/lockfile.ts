/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Rug-pull / Trust-On-First-Use (TOFU) integrity lockfile.
 *
 * On first scan we pin the canonical fingerprint of each server's tool surface.
 * On every rescan we diff against the pin: any silent change to a tool's
 * description or schema (the MCPoison rug-pull) shows up as drift and must be
 * re-approved. Users are encouraged to commit `mcptrustchecker.lock` to git.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { IntegrityResult, ServerSurface, SurfaceChange } from './types.js';
import { canonicalTool, surfaceDigest, toolDigest } from './util/hash.js';
import { METHODOLOGY_VERSION } from './version.js';

export interface LockEntry {
  digest: string;
  tools: Record<string, string>;
  instructionsDigest: string;
  /** Package version whose published artifact was verified at pin time. */
  packageVersion?: string;
  /**
   * Identity of the pinned artifact (its registry URL). A registry can publish
   * several artifacts per version (a PyPI sdist AND wheels); the byte pin is
   * only comparable to the SAME artifact, so a later-added sibling artifact
   * isn't mistaken for a same-version republish.
   */
  tarballUrl?: string;
  /** SHA-256 of that verified artifact — pins the actual published bytes. */
  tarballSha256?: string;
  pinnedAt?: string;
}

export interface Lockfile {
  lockfileVersion: 1;
  methodologyVersion: string;
  servers: Record<string, LockEntry>;
}

function hashString(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

/** The artifact's file name (last path segment, query/fragment stripped). */
function artifactBasename(url: string): string {
  try {
    return new URL(url).pathname.split('/').pop() ?? url;
  } catch {
    return url.split(/[?#]/)[0]!.split('/').pop() ?? url;
  }
}

export function emptyLockfile(): Lockfile {
  return { lockfileVersion: 1, methodologyVersion: METHODOLOGY_VERSION, servers: {} };
}

export function readLockfile(path: string): Lockfile | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Lockfile;
  } catch (err) {
    throw new Error(`Failed to parse lockfile ${path}: ${(err as Error).message}`);
  }
}

export function writeLockfile(path: string, lock: Lockfile): void {
  writeFileSync(path, JSON.stringify(lock, null, 2) + '\n', 'utf8');
}

/** Build a lock entry from the current surface. */
export function entryFor(surface: ServerSurface, pinnedAt?: string): LockEntry {
  const tools: Record<string, string> = {};
  for (const t of surface.tools) tools[t.name] = toolDigest(t);
  const meta = surface.packageMeta;
  return {
    digest: surfaceDigest(surface),
    tools,
    instructionsDigest: hashString(surface.server.instructions ?? ''),
    ...(typeof meta?.version === 'string' && meta.tarballSha256
      ? { packageVersion: meta.version, tarballUrl: meta.tarballUrl ?? undefined, tarballSha256: meta.tarballSha256 }
      : {}),
    ...(pinnedAt ? { pinnedAt } : {}),
  };
}

/** Add/update this surface's pin in the lockfile (returns a new object). */
export function pinSurface(lock: Lockfile, surface: ServerSurface, pinnedAt?: string): Lockfile {
  const entry = entryFor(surface, pinnedAt);
  // Never DROP an existing byte-level pin unless this scan positively verified a
  // DIFFERENT version. An offline / metadata-only / failed-download re-pin has no
  // fresh hash (and often no observed version at all) — carrying the previous pin
  // forward keeps rug-pull protection alive rather than silently un-pinning it on
  // a networkless CI re-pin or a transient outage.
  const prev = lock.servers[surface.id];
  const observedVersion = surface.packageMeta?.version;
  const versionChanged = Boolean(observedVersion && prev?.packageVersion && observedVersion !== prev.packageVersion);
  if (!entry.tarballSha256 && prev?.tarballSha256 && !versionChanged) {
    entry.packageVersion = prev.packageVersion;
    entry.tarballUrl = prev.tarballUrl;
    entry.tarballSha256 = prev.tarballSha256;
  }
  return {
    ...lock,
    methodologyVersion: METHODOLOGY_VERSION,
    servers: { ...lock.servers, [surface.id]: entry },
  };
}

/** Compare the current surface against its pinned entry. */
export function checkIntegrity(surface: ServerSurface, lock: Lockfile | null): IntegrityResult {
  const currentDigest = surfaceDigest(surface);
  const entry = lock?.servers[surface.id];
  if (!entry) return { status: 'first-seen', currentDigest };

  // Byte-level rug pull: the SAME pinned version was republished with different
  // content. The tool surface (and therefore the digest) may be identical —
  // that is exactly what makes this attack invisible to a metadata-only check.
  //
  // Artifact identity is registry-aware, because the tarball URL comes from the
  // (attacker-controllable) registry response and MUST NOT be trusted to gate
  // the comparison:
  //   • npm — a version maps to exactly ONE canonical tarball, so we compare by
  //     VERSION only and ignore the URL entirely. That defeats a forged registry
  //     that appends `?rev=2` (or any different path) to dodge the check.
  //   • PyPI — a version legitimately has several immutable, differently-named
  //     files (sdist + wheels), so we compare by the artifact FILE NAME (query
  //     stripped) to avoid a false republish when a sibling file is added, while
  //     still catching a same-file byte change (PyPI enforces file immutability,
  //     so a same-name/different-bytes swap is itself the anomaly).
  const meta = surface.packageMeta;
  // Require a STRING version on both sides: a non-primitive `meta.version`
  // (a hostile registry can make it an array/object) would never compare equal
  // after the lockfile's JSON round-trip, silently suppressing the byte check.
  const sameVersion = Boolean(typeof meta?.version === 'string' && meta.version === entry.packageVersion);
  const sameArtifact =
    sameVersion &&
    (meta?.registry !== 'pypi' ||
      !entry.tarballUrl ||
      !meta?.tarballUrl ||
      artifactBasename(entry.tarballUrl) === artifactBasename(meta.tarballUrl));
  const tarballChange: SurfaceChange | undefined =
    entry.tarballSha256 && entry.packageVersion && meta?.tarballSha256 && sameArtifact && meta.tarballSha256 !== entry.tarballSha256
      ? {
          kind: 'package-changed',
          name: meta.name,
          detail:
            `Version ${meta.version} was republished with different content: the verified artifact hash changed ` +
            `from ${entry.tarballSha256.slice(0, 12)}… to ${meta.tarballSha256.slice(0, 12)}… since the pin (same version, different bytes).`,
        }
      : undefined;

  if (entry.digest === currentDigest && !tarballChange)
    return { status: 'unchanged', currentDigest, previousDigest: entry.digest };

  // A pin made under a DIFFERENT methodology version was computed from a
  // different canonical projection, so its digest is not comparable — a
  // projection change (adding `title`, say) makes every unchanged server look
  // like it drifted. Accusing every user of a rug pull the first time they
  // upgrade is the worst possible false positive, so the schema comparison is
  // declared un-evaluable instead of being guessed at.
  //
  // The artifact byte pin does NOT depend on the projection, so it is still
  // reported: a same-version republish is caught across an upgrade.
  if (lock && lock.methodologyVersion !== METHODOLOGY_VERSION) {
    return {
      status: 'stale-pin',
      currentDigest,
      previousDigest: entry.digest,
      pinnedMethodologyVersion: lock.methodologyVersion,
      ...(tarballChange ? { changes: [tarballChange] } : {}),
    };
  }

  const changes: SurfaceChange[] = [];
  const currentTools: Record<string, string> = {};
  for (const t of surface.tools) currentTools[t.name] = toolDigest(t);

  for (const name of Object.keys(currentTools)) {
    if (!(name in entry.tools)) {
      changes.push({ kind: 'tool-added', name, detail: `Tool "${name}" is new since the pin.` });
    } else if (entry.tools[name] !== currentTools[name]) {
      const tool = surface.tools.find((t) => t.name === name);
      changes.push({
        kind: 'tool-changed',
        name,
        detail: `Tool "${name}" changed after approval (description/schema drift): ${JSON.stringify(canonicalTool(tool!)).slice(0, 200)}…`,
      });
    }
  }
  for (const name of Object.keys(entry.tools)) {
    if (!(name in currentTools)) {
      changes.push({ kind: 'tool-removed', name, detail: `Tool "${name}" was removed since the pin.` });
    }
  }
  if (entry.instructionsDigest !== hashString(surface.server.instructions ?? '')) {
    changes.push({ kind: 'instructions-changed', detail: 'Server instructions changed since the pin.' });
  }
  if (tarballChange) changes.push(tarballChange);

  return { status: 'drift', currentDigest, previousDigest: entry.digest, changes };
}
