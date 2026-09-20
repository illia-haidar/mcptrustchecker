/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Target resolution — turn a CLI target (path / URL / package / config) plus
 * options into one or more normalized surfaces, choosing the safest acquisition
 * path. Live process spawning from a client config is opt-in (`--run`).
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import type { PackageMeta, ServerSurface } from '../types.js';
import { surfaceFromManifest } from './manifest.js';
import { parseRepoTarget, repoLabel, surfaceFromGithubRepo } from './repo.js';
import { surfaceFromPackageDir } from './source.js';
import { acquireHttp, acquireStdio, ALLOWED_COMMANDS, type LiveOptions } from './live.js';
import {
  expandVars,
  isClientConfig,
  packageSpecFromStdio,
  parseClientConfig,
  redactSensitiveArgs,
  type ConfigServerSpec,
} from './clientConfig.js';
import { fetchNpmMeta, fetchPypiMeta } from './npm.js';
import { fetchPackageSource, surfaceFromArchiveFile, PackageSourceError } from './packageSource.js';
import { extractToolsFromSource } from './toolExtract.js';

export interface ResolveOptions extends LiveOptions {
  command?: string;
  args?: string[];
  url?: string;
  online?: boolean;
  run?: boolean;
  registry?: 'npm' | 'pypi';
  /** Environment variables to pass to a `--command` stdio server. */
  envVars?: Record<string, string>;
  /** With `--online`: skip downloading the published artifact (metadata checks only). */
  metadataOnly?: boolean;
  /** Lifts GitHub's anonymous archive rate limit; falls back to GITHUB_TOKEN. */
  githubToken?: string;
}

export interface ResolvedTarget {
  label: string;
  surface: ServerSurface;
}

const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const HTTP_RE = /^https?:\/\//i;

/** Split a `name` / `name@version` / `@scope/name@version` target. */
function parsePackageTarget(target: string): { name: string; version?: string } | undefined {
  const scoped = target.startsWith('@');
  const at = target.indexOf('@', scoped ? 1 : 0);
  if (at <= 0) return { name: target };
  return { name: target.slice(0, at), version: target.slice(at + 1) || undefined };
}

function commandBase(command: string): string {
  const cleaned = command.replace(/\\/g, '/');
  return cleaned.slice(cleaned.lastIndexOf('/') + 1);
}

/** Map a stdio runner command to the registry that runner installs from. */
function registryForRunner(command?: string): 'npm' | 'pypi' | undefined {
  if (!command) return undefined;
  const base = command.replace(/\\/g, '/');
  const runner = base.slice(base.lastIndexOf('/') + 1).replace(/\.(cmd|exe)$/, '');
  if (runner === 'uvx' || runner === 'pipx' || runner === 'pip' || runner === 'pip3' || runner.startsWith('python')) return 'pypi';
  if (runner === 'npx' || runner === 'bunx' || runner === 'pnpm' || runner === 'yarn' || runner === 'node') return 'npm';
  return undefined;
}

async function metaFor(
  name: string,
  opts: ResolveOptions,
  registry: 'npm' | 'pypi',
  version?: string,
): Promise<PackageMeta> {
  if (!opts.online) return { registry, name };
  return registry === 'pypi' ? fetchPypiMeta(name, version) : fetchNpmMeta(name, version);
}

function packageSurface(name: string, meta: PackageMeta, origin: string): ServerSurface {
  return {
    id: name,
    source: { kind: 'package', origin },
    server: { name },
    tools: [],
    prompts: [],
    resources: [],
    packageMeta: meta,
  };
}

/**
 * Fetch + verify the package's published artifact and attach its real source to
 * the surface (the deep half of an `--online` package scan).
 *
 * Failure handling is fail-CLOSED for tampering and fail-OPEN for outages, but
 * NEVER silent: a hash mismatch or an off-allowlist redirect (hard tamper
 * evidence) is recorded on the surface so a detector raises a finding — it must
 * not degrade to a clean grade. A transient network failure is recorded too, so
 * a machine consumer can see the byte-level check did not run rather than
 * mistaking an unverified scan for a verified one.
 */
async function attachPublishedSource(surface: ServerSurface, opts: ResolveOptions): Promise<void> {
  const meta = surface.packageMeta;
  if (!opts.online || opts.metadataOnly || !meta?.tarballUrl) return;
  try {
    const src = await fetchPackageSource(meta);
    if (!src) return;
    meta.tarballSha256 = src.tarballSha256;
    surface.sourceFiles = src.sourceFiles;
    // With the real source in hand but no running server to enumerate tools,
    // reconstruct the tool surface statically so the MCP-specific detectors
    // (tool-poisoning, unicode smuggling, toxic flows, name collisions, per-tool
    // capability) have a surface to inspect. Marked `static` so the engine caps
    // tool-derived finding confidence — an inferred tool never forces the F-gate.
    // Fail-open: if nothing is recovered, the scan is left exactly as it was.
    if ((!surface.tools || surface.tools.length === 0) && surface.sourceFiles.length) {
      const extracted = extractToolsFromSource(surface.sourceFiles);
      if (extracted.extracted) {
        surface.tools = extracted.tools;
        surface.toolProvenance = 'static';
      }
    }
  } catch (err) {
    const kind = err instanceof PackageSourceError ? err.kind : 'other';
    const detail = (err as Error).message;
    meta.artifactError = { kind, detail };
    const label =
      kind === 'integrity' || kind === 'untrusted-redirect'
        ? 'artifact FAILED verification'
        : 'artifact byte-check skipped';
    process.stderr.write(`! ${surface.id}: ${label} (${detail}).\n`);
  }
}

/** Strip the query string from a stored URL so config-embedded tokens don't leak. */
function redactUrl(url?: string): string | undefined {
  if (!url) return url;
  try {
    const u = new URL(url);
    if (u.search) u.search = ''; // query-string tokens
    u.username = ''; // userinfo credentials (user:pass@host)
    u.password = '';
    return u.href;
  } catch {
    return url;
  }
}

/** Build the static (no-spawn) surface for one client-config server entry. */
function staticConfigSurface(spec: ConfigServerSpec, origin: string): ServerSurface {
  const transport: ServerSurface['transport'] =
    spec.transport === 'http'
      ? { kind: 'http', url: redactUrl(spec.url) }
      : {
          kind: 'stdio',
          command: spec.command,
          args: redactSensitiveArgs(spec.args ?? []),
          // A path-qualified command OR one outside the allowlist is untrusted.
          userControlledCommand: spec.command
            ? /[\\/]/.test(spec.command) || !ALLOWED_COMMANDS.has(commandBase(spec.command))
            : false,
        };
  return {
    id: spec.id,
    source: { kind: 'client-config', origin },
    server: { name: spec.id },
    tools: [],
    prompts: [],
    resources: [],
    transport,
  };
}

/** Resolve a target into scannable surfaces. */
export async function resolveTargets(target: string | undefined, opts: ResolveOptions = {}): Promise<ResolvedTarget[]> {
  // 1) Explicit live specs win.
  if (opts.command) {
    const surface = await acquireStdio({ command: opts.command, args: opts.args, env: opts.envVars }, opts);
    return [{ label: surface.id, surface }];
  }
  // A repository target is checked before the URL branch: a github.com link is
  // source to read, not an MCP endpoint to connect to (it used to fail on
  // content-type). Bare `owner/repo` is checked here too, where it used to look
  // like a missing file.
  if (target && !opts.url) {
    const repoRef = parseRepoTarget(target);
    if (repoRef) {
      const surface = await surfaceFromGithubRepo(repoRef, { token: opts.githubToken });
      if ((!surface.tools || surface.tools.length === 0) && surface.sourceFiles?.length) {
        const extracted = extractToolsFromSource(surface.sourceFiles);
        if (extracted.extracted) {
          surface.tools = extracted.tools;
          surface.toolProvenance = 'static';
        }
      }
      return [{ label: repoLabel(repoRef), surface }];
    }
  }

  if (opts.url || (target && HTTP_RE.test(target))) {
    const url = opts.url ?? target!;
    const surface = await acquireHttp(url, opts);
    return [{ label: url, surface }];
  }

  if (!target) throw new Error('No scan target provided.');

  // A scoped npm/PyPI package (@scope/name, optionally @version) contains '/'
  // but is NOT a path — e.g. `@modelcontextprotocol/server-filesystem@1.0.0`.
  // A scoped-SHAPED string ending in an archive/.json extension is a FILE path
  // (e.g. `@myorg/server-1.0.0.tgz`), so it must not shadow the not-found guard.
  const isArchiveFile = /\.(tgz|tar\.gz|tar|zip|whl)$/i.test(target);
  const hasFileExt = isArchiveFile || target.toLowerCase().endsWith('.json');
  const isScopedPkg =
    !hasFileExt && /^@[a-z0-9-~][a-z0-9-._~]*\/[a-z0-9-~][a-z0-9-._~]*(@[^/\\]+)?$/i.test(target);
  const looksLikePath =
    !isScopedPkg && (target.includes('/') || target.includes('\\') || target.toLowerCase().endsWith('.json') || isArchiveFile);

  // A path/manifest target that doesn't exist: say so plainly.
  if (looksLikePath && !existsSync(target)) {
    throw new Error(`No such file: ${target}`);
  }

  // A local package DIRECTORY → analyze its implementation source + metadata.
  if (existsSync(target) && statSync(target).isDirectory()) {
    return [{ label: target, surface: surfaceFromPackageDir(target) }];
  }

  // A packed release artifact (.tgz/.tar.gz/.tar/.zip/.whl) → read the real
  // shipped source in memory, offline, without installing or executing it.
  if (isArchiveFile && existsSync(target) && statSync(target).isFile()) {
    return [{ label: target, surface: surfaceFromArchiveFile(target) }];
  }

  // 2) A file on disk: manifest or client config.
  if (existsSync(target) && target.toLowerCase().endsWith('.json')) {
    let json: unknown;
    try {
      json = JSON.parse(readFileSync(target, 'utf8'));
    } catch (err) {
      throw new Error(`Invalid JSON in ${target}: ${(err as Error).message}`);
    }
    if (isClientConfig(json)) {
      const specs = parseClientConfig(json);
      const results: ResolvedTarget[] = [];
      for (const spec of specs) {
        if (opts.run) {
          // URLs/commands come from an UNTRUSTED config. Expand ${VAR} ONLY from
          // the entry's own env block — NEVER from the scanner's process.env,
          // which would leak operator secrets into an outbound request.
          const varEnv = { ...(spec.env ?? {}) };
          try {
            const surface =
              spec.transport === 'http'
                ? await acquireHttp(expandVars(spec.url!, varEnv), { ...opts, blockPrivateHosts: opts.blockPrivateHosts ?? true })
                : await acquireStdio(
                    {
                      command: expandVars(spec.command!, varEnv),
                      args: (spec.args ?? []).map((a) => expandVars(a, varEnv)),
                      env: spec.env,
                    },
                    opts,
                  );
            // Use the config's server key as the stable id (not the raw command,
            // which may embed a token), and scrub any secrets from stored args.
            surface.id = spec.id;
            surface.source = { kind: 'client-config', origin: target };
            if (surface.transport?.args) surface.transport.args = redactSensitiveArgs(surface.transport.args);
            // The expanded URL can carry a ${TOKEN} in its query/userinfo — redact
            // it before it is stored in the report (matches the static path).
            if (surface.transport?.url) surface.transport.url = redactUrl(surface.transport.url) ?? surface.transport.url;
            results.push({ label: spec.id, surface });
          } catch {
            // One dead/unreachable server must not abort the whole config scan.
            results.push({ label: spec.id, surface: staticConfigSurface(spec, target) });
          }
          continue;
        }
        // Static: posture + supply-chain only, no process spawned.
        const surface = staticConfigSurface(spec, target);
        if (spec.transport === 'stdio' && spec.command) {
          const pkgSpec = packageSpecFromStdio(spec.command, spec.args ?? []);
          // Only fetch metadata for a well-formed package name (config values are untrusted).
          if (pkgSpec && NPM_NAME.test(pkgSpec.name)) {
            // Pick the registry from the RUNNER (uvx/pipx → PyPI, npx → npm), not
            // the global --registry default, so a Python server isn't looked up
            // (and its same-named npm squat isn't downloaded) as an npm package.
            const registry = registryForRunner(spec.command) ?? opts.registry ?? 'npm';
            const meta = await metaFor(pkgSpec.name, opts, registry, pkgSpec.version);
            meta.requestedSpec = pkgSpec.version;
            meta.pinned = Boolean(pkgSpec.version && pkgSpec.version !== 'latest' && /^[0-9]/.test(pkgSpec.version));
            surface.packageMeta = meta;
            // The config names the package the runner would install — read its
            // actual published source (the pinned version), not just its metadata.
            await attachPublishedSource(surface, opts);
          }
        }
        results.push({ label: spec.id, surface });
      }
      if (results.length === 0) throw new Error(`No MCP servers found in config: ${target}`);
      return results;
    }
    // Plain tools manifest — must be a JSON object, not an array/null/scalar.
    if (!json || typeof json !== 'object' || Array.isArray(json)) {
      throw new Error(
        `${target} is not a recognizable MCP manifest (expected a JSON object with a "tools" array or an "mcpServers" map).`,
      );
    }
    const surface = surfaceFromManifest(json, target);
    return [{ label: surface.id, surface }];
  }

  // 3) A bare package name (optionally `name@version`) → supply-chain /
  // provenance scan; with `--online` the published artifact of the requested
  // version is fetched, verified and read as real source.
  const bare = parsePackageTarget(target);
  if (bare && NPM_NAME.test(bare.name)) {
    const registry = opts.registry ?? 'npm';
    const meta = await metaFor(bare.name, opts, registry, bare.version);
    meta.requestedSpec = bare.version;
    meta.pinned = Boolean(bare.version && /^\d/.test(bare.version));
    const surface = packageSurface(bare.name, meta, target);
    await attachPublishedSource(surface, opts);
    return [{ label: target, surface }];
  }

  throw new Error(
    `Could not resolve target "${target}". Provide a tools.json manifest, an http(s) URL, ` +
      `a client config, a package name, or use --command for stdio.`,
  );
}
