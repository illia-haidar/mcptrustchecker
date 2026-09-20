/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Live acquisition over the wire using the official MCP SDK.
 *
 * SECURITY: scanning is itself an attack surface. stdio acquisition spawns a
 * child process, so we:
 *   - allowlist the executable by BARE NAME only (a path like `/tmp/node`
 *     is rejected — a basename must not authorize an attacker-chosen path);
 *   - pass a scrubbed environment: the parent env is not inherited by us, and
 *     any caller/config-supplied env has execution-hijacking variables
 *     (NODE_OPTIONS, LD_PRELOAD, DYLD_*, PYTHON*, …) stripped, so an allowlisted
 *     runtime can't be redirected;  (the SDK still injects a small sudo-style
 *     safe subset — HOME/PATH/SHELL/TERM/USER — via getDefaultEnvironment());
 *   - capture stderr and enforce aggressive timeouts.
 * HTTP acquisition validates the URL scheme, and — for config-derived URLs —
 * blocks private/loopback/link-local hosts to prevent SSRF.
 *
 * The SDK is imported dynamically so the pure engine and its tests never need
 * it loaded; live scanning requires `@modelcontextprotocol/sdk` at runtime.
 */

import type { PromptDef, ResourceDef, ServerSurface, ToolDef } from '../types.js';
import { surfaceFromManifest } from './manifest.js';
import { TOOL_VERSION } from '../version.js';
import { applyCredentialGate } from '../util/headers.js';

/** Executables permitted for stdio acquisition (the canonical safe set). */
export const ALLOWED_COMMANDS = new Set(['npx', 'uvx', 'python', 'python3', 'node', 'docker', 'deno']);

/**
 * Environment variables that can hijack an otherwise-trusted runtime. Stripped
 * from any caller/config-supplied env before spawning, so an allowlisted
 * `node`/`python` can't be told to load attacker code at startup.
 */
const DANGEROUS_ENV_EXACT = new Set([
  'PATH', // a config-supplied PATH would redirect an allowlisted `node`/`python` to an attacker binary
  'NODE_PATH', // hijacks bare-import resolution for `node`
  'NODE_OPTIONS',
  'NODE_REPL_EXTERNAL_MODULE',
  'PYTHONSTARTUP',
  'PYTHONPATH',
  'PYTHONHOME',
  'PERL5OPT',
  'RUBYOPT',
  'BASH_ENV',
  'ENV',
  'GIT_SSH_COMMAND',
  'GIT_EXTERNAL_DIFF',
  // Package-index redirects — a config env could point `npx`/`uvx`/`pip` at an
  // attacker-controlled registry (supply-chain redirect). Defense-in-depth.
  'NPM_CONFIG_REGISTRY',
  'PIP_INDEX_URL',
  'PIP_EXTRA_INDEX_URL',
  'UV_INDEX_URL',
  'UV_DEFAULT_INDEX',
]);
const DANGEROUS_ENV_PREFIX = ['LD_', 'DYLD_', 'NPM_CONFIG_'];

/** Drop execution-hijacking vars and bash function definitions from an env map. */
export function sanitizeEnv(env: Record<string, string>): { clean: Record<string, string>; dropped: string[] } {
  const clean: Record<string, string> = {};
  const dropped: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    const key = k.toUpperCase();
    const bad =
      DANGEROUS_ENV_EXACT.has(key) ||
      DANGEROUS_ENV_PREFIX.some((p) => key.startsWith(p)) ||
      (typeof v === 'string' && v.startsWith('()'));
    if (bad) dropped.push(k);
    else clean[k] = v;
  }
  return { clean, dropped };
}

/** True for a private/loopback/link-local/otherwise non-routable IPv4 dotted-quad. */
function isPrivateIpv4(h: string): boolean {
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return (
    a === 127 || a === 10 || a === 0 ||
    (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 169 && b === 254) || // link-local incl. cloud metadata 169.254.169.254
    (a === 100 && b >= 64 && b <= 127) || // CGNAT (RFC 6598) — carrier-internal
    a >= 224 // multicast (224/4) and reserved (240/4), incl. 255.255.255.255
  );
}

/**
 * Block loopback / private / link-local hosts (SSRF guard for config-derived
 * URLs). IPv6 checks apply only to actual IPv6 literals (so DNS names like
 * "fc-api.com" aren't blocked), and IPv4-mapped IPv6 (::ffff:127.0.0.1) is
 * unwrapped. This is the STRING-level half of the guard: a public DNS name that
 * *resolves* to a private IP is not visible here — `isBlockedHostResolved` adds
 * that half, and callers that accept untrusted targets should use it.
 */
/**
 * Extract the embedded IPv4 of an IPv4-mapped IPv6 literal. Node's URL parser
 * normalizes `::ffff:169.254.169.254` to the HEX form `::ffff:a9fe:a9fe`, so we
 * must accept BOTH the dotted and the hextet forms — the previous dotted-only
 * regex was dead code against a real `URL.hostname`, leaving cloud-metadata
 * (169.254.169.254) reachable through the SSRF guard.
 */
function mappedIpv4(h: string): string | undefined {
  const dotted = h.match(/:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) return dotted[1];
  const hex = h.match(/::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
  }
  return undefined;
}

export function isBlockedHost(hostname: string): boolean {
  // Strip brackets and a trailing FQDN dot (`localhost.` resolves like `localhost`).
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (isPrivateIpv4(h)) return true;
  // IPv6 literal (contains a colon)
  if (h.includes(':')) {
    if (h === '::1' || h === '::') return true;
    if (h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) return true; // link-local / ULA
    const embedded = mappedIpv4(h);
    if (embedded && isPrivateIpv4(embedded)) return true; // IPv4-mapped IPv6 (dotted OR hextet form)
  }
  return false;
}

/** True when `h` is already an IP literal, so there is nothing to resolve. */
function isIpLiteral(h: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
}

/**
 * The DNS-rebinding half of the SSRF guard: resolve the name and block it when
 * ANY returned address is non-routable. `isBlockedHost` alone cannot see this —
 * `evil.example.com` is a perfectly public *string* that can point at 127.0.0.1
 * or the cloud-metadata address. Every A/AAAA record is checked, because a
 * multi-record name is only as safe as its worst answer.
 *
 * Two honest limits: a resolution FAILURE is not treated as blocked (the
 * connection would fail on its own, and failing closed would break split-horizon
 * DNS), and this is a pre-connect check — a sub-TTL rebind between this lookup
 * and the socket connect remains theoretically possible. Pinning the resolved
 * address into the connection is the only complete fix and needs a custom
 * dispatcher; this check plus the per-hop re-validation is the practical guard.
 */
export type HostResolver = (host: string) => Promise<Array<{ address: string }>>;

export async function isBlockedHostResolved(hostname: string, resolver?: HostResolver): Promise<boolean> {
  if (isBlockedHost(hostname)) return true;
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (isIpLiteral(h)) return false;
  try {
    // The resolver is injectable so this can be tested without reaching the
    // network: asserting on a live third-party domain would make the unit suite
    // fail offline and on any resolver with DNS-rebinding protection.
    const lookup: HostResolver = resolver
      ?? (async (name) => (await import('node:dns/promises')).lookup(name, { all: true }));
    // dns.lookup accepts no timeout and no AbortSignal, and this call sits
    // outside the connect timeout — a hostile authoritative nameserver that
    // black-holes queries would otherwise stall the scan for the OS resolver's
    // whole budget (tens of seconds).
    const addrs = await Promise.race([
      lookup(h),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('dns timeout')), DNS_GUARD_TIMEOUT_MS).unref?.()),
    ]);
    return addrs.some((a) => isBlockedHost(a.address));
  } catch {
    return false;
  }
}

const REQUEST_OPTS = { timeout: 15_000, maxTotalTimeout: 30_000, resetTimeoutOnProgress: false };
const CONNECT_TIMEOUT_MS = 20_000;
/** Budget for the SSRF guard's own DNS lookup (see isBlockedHostResolved). */
const DNS_GUARD_TIMEOUT_MS = 3_000;
const MAX_ITEMS = 1000;
const MAX_PAGES = 50;

export interface StdioSpec {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface LiveOptions {
  /** Allow spawning a command outside the allowlist (opt-in, dangerous). */
  allowAnyCommand?: boolean;
  /** Restrict HTTP acquisition to these hostnames. */
  allowedHosts?: string[];
  /** Block private/loopback/link-local hosts (set for untrusted, config-derived URLs). */
  blockPrivateHosts?: boolean;
  /**
   * Extra request headers (e.g. `Authorization: Bearer …`) for HTTP acquisition
   * of protected endpoints. Sent ONLY to the target host — never forwarded to a
   * redirect on a different host, so the credential can't leak.
   */
  headers?: Record<string, string>;
  /**
   * Perform an interactive OAuth 2.0 browser sign-in for endpoints that require
   * it (the MCP authorization flow). Opens the user's browser; tokens live in
   * memory for the scan only.
   */
  login?: boolean;
  /** Optional OAuth scope to request during `login` (e.g. `mcp:tools`). */
  scope?: string;
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/* eslint-disable @typescript-eslint/no-explicit-any */
async function loadSdk(): Promise<any> {
  try {
    const [{ Client }, stdio, http, sse, auth] = await Promise.all([
      import('@modelcontextprotocol/sdk/client/index.js'),
      import('@modelcontextprotocol/sdk/client/stdio.js'),
      import('@modelcontextprotocol/sdk/client/streamableHttp.js'),
      import('@modelcontextprotocol/sdk/client/sse.js'),
      import('@modelcontextprotocol/sdk/client/auth.js'),
    ]);
    return {
      Client,
      StdioClientTransport: (stdio as any).StdioClientTransport,
      StreamableHTTPClientTransport: (http as any).StreamableHTTPClientTransport,
      SSEClientTransport: (sse as any).SSEClientTransport,
      UnauthorizedError: (auth as any).UnauthorizedError,
    };
  } catch (err) {
    throw new Error(
      'Live scanning requires the "@modelcontextprotocol/sdk" package. ' +
        `Install it (npm i @modelcontextprotocol/sdk). Underlying error: ${(err as Error).message}`,
    );
  }
}

// Permissive result schemas so a single non-spec-compliant tool/prompt/resource
// object does not make the SDK reject the WHOLE list (real servers are often
// slightly non-compliant — scanning them is exactly the point). Built once from
// the zod that ships with the SDK; falls back to the strict high-level calls.
let looseSchemas: Record<string, unknown> | null | undefined;
async function getLooseSchemas(): Promise<Record<string, unknown> | null> {
  if (looseSchemas !== undefined) return looseSchemas ?? null;
  try {
    const zod: any = await import('zod');
    const z = zod.z ?? zod.default ?? zod;
    const mk = (key: string) =>
      z.object({ [key]: z.array(z.any()).optional(), nextCursor: z.string().optional() }).passthrough();
    looseSchemas = { tools: mk('tools'), prompts: mk('prompts'), resources: mk('resources') };
  } catch {
    looseSchemas = null;
  }
  return looseSchemas;
}

async function listLoose(
  client: any,
  method: string,
  key: 'tools' | 'prompts' | 'resources',
  cursor?: string,
): Promise<{ items: unknown[]; nextCursor?: string }> {
  const schemas = await getLooseSchemas();
  const params = cursor ? { cursor } : {};
  if (schemas && typeof client.request === 'function') {
    const r = await client.request({ method, params }, schemas[key], REQUEST_OPTS);
    return { items: Array.isArray(r?.[key]) ? r[key] : [], nextCursor: r?.nextCursor };
  }
  const fn = key === 'tools' ? 'listTools' : key === 'prompts' ? 'listPrompts' : 'listResources';
  const r = await client[fn](params, REQUEST_OPTS);
  return { items: Array.isArray(r?.[key]) ? r[key] : [], nextCursor: r?.nextCursor };
}

async function enumerate(client: any): Promise<{
  tools: ToolDef[];
  prompts: PromptDef[];
  resources: ResourceDef[];
  server: ServerSurface['server'];
}> {
  const caps = client.getServerCapabilities?.() ?? {};
  const info = client.getServerVersion?.() ?? {};
  const instructions = client.getInstructions?.();

  const tools: ToolDef[] = [];
  let cursor: string | undefined;
  let pages = 0;
  do {
    const r = await listLoose(client, 'tools/list', 'tools', cursor);
    for (const t of r.items) tools.push(t as ToolDef);
    cursor = r.nextCursor;
    // Bound BOTH item count and page count: a malicious server can return
    // empty pages with a persistent cursor forever.
    if (tools.length >= MAX_ITEMS || ++pages >= MAX_PAGES) break;
  } while (cursor);

  const prompts: PromptDef[] = [];
  if (caps.prompts) {
    try {
      const r = await listLoose(client, 'prompts/list', 'prompts');
      for (const p of r.items) prompts.push(p as PromptDef);
    } catch {
      /* optional capability */
    }
  }

  const resources: ResourceDef[] = [];
  if (caps.resources) {
    try {
      const r = await listLoose(client, 'resources/list', 'resources');
      for (const res of r.items) resources.push(res as ResourceDef);
    } catch {
      /* optional capability */
    }
  }

  return {
    tools,
    prompts,
    resources,
    server: {
      name: info.name,
      version: info.version,
      title: info.title,
      instructions,
      capabilities: caps,
    },
  };
}

function commandBase(command: string): string {
  const cleaned = command.replace(/\\/g, '/');
  return cleaned.slice(cleaned.lastIndexOf('/') + 1);
}

/** Acquire a surface by spawning a local stdio MCP server. */
export async function acquireStdio(spec: StdioSpec, opts: LiveOptions = {}): Promise<ServerSurface> {
  const base = commandBase(spec.command);
  // A path separator means the caller specified an explicit path; a basename
  // match must NOT authorize an attacker-chosen path (e.g. /tmp/evil/node).
  const hasPathSeparator = /[\\/]/.test(spec.command);
  const allowed = ALLOWED_COMMANDS.has(base) && !hasPathSeparator;
  if (!allowed && !opts.allowAnyCommand) {
    const reason = hasPathSeparator
      ? `path-qualified commands are not allowlisted (only bare names ${[...ALLOWED_COMMANDS].join(', ')})`
      : `not in the executable allowlist (${[...ALLOWED_COMMANDS].join(', ')})`;
    throw new Error(
      `Refusing to spawn "${spec.command}": ${reason}. Re-run with --allow-any-command only if you trust it.`,
    );
  }

  const { clean: safeEnv, dropped } = sanitizeEnv(spec.env ?? {});

  const sdk = await loadSdk();
  const transport = new sdk.StdioClientTransport({
    command: spec.command,
    args: spec.args ?? [],
    // PATH last so a (scrubbed, but defense-in-depth) config env can never win.
    env: { ...safeEnv, PATH: process.env.PATH ?? '' },
    cwd: spec.cwd ?? process.cwd(),
    stderr: 'pipe',
  });
  const client = new sdk.Client({ name: 'mcptrustchecker', version: TOOL_VERSION }, { capabilities: {} });

  try {
    await withTimeout(client.connect(transport), CONNECT_TIMEOUT_MS, 'stdio connect');
    const enumd = await enumerate(client);
    const id = `${spec.command} ${(spec.args ?? []).join(' ')}`.trim();
    const surface = surfaceFromManifest({ ...enumd }, id, id);
    surface.source = { kind: 'stdio', origin: id };
    surface.transport = {
      kind: 'stdio',
      command: spec.command,
      args: spec.args ?? [],
      userControlledCommand: !allowed,
      ...(dropped.length ? { droppedEnv: dropped } : {}),
    };
    return surface;
  } finally {
    await client.close?.().catch(() => {});
  }
}

/** Acquire a surface from a Streamable-HTTP / SSE endpoint. */
export async function acquireHttp(url: string, opts: LiveOptions = {}): Promise<ServerSurface> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported URL scheme "${parsed.protocol}" (only http/https).`);
  }
  if (opts.allowedHosts && !opts.allowedHosts.includes(parsed.hostname)) {
    throw new Error(`Host ${parsed.hostname} is not in the allowed-hosts list.`);
  }
  // An explicit --allowed-hosts entry is the operator naming this host on
  // purpose, so it overrides the private-host guard. Without this the guard
  // rejects the very host you just permitted — and tells you to permit it.
  const explicitlyAllowed = Boolean(opts.allowedHosts?.includes(parsed.hostname));
  if (opts.blockPrivateHosts && !explicitlyAllowed && (await isBlockedHostResolved(parsed.hostname))) {
    throw new Error(
      `Refusing to connect to private/loopback host "${parsed.hostname}" from an untrusted config (SSRF guard). ` +
        `Pass --allowed-hosts ${parsed.hostname} to scan it deliberately.`,
    );
  }

  const sdk = await loadSdk();
  const client = new sdk.Client({ name: 'mcptrustchecker', version: TOOL_VERSION }, { capabilities: {} });

  // Re-validate every redirect hop: the initial-URL SSRF check is useless if the
  // server 302s to http://[::ffff:169.254.169.254]/. We follow redirects
  // manually (capped) and run each hop's host back through the same guard.
  // Re-validate every hop AND contain credentials. The SDK routes ALL its
  // requests — including OAuth discovery / registration / token endpoints, whose
  // hosts come from the *server's* metadata — through this fetch, so every hop
  // (not just 3xx targets) must pass the SSRF guard, and credentials must never
  // cross to a different origin.
  const guardedFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    let current = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    for (let hop = 0; hop < 6; hop++) {
      let cur: URL;
      try {
        cur = new URL(current);
      } catch {
        throw new Error(`Invalid request URL "${current}".`);
      }
      // SSRF guard on THIS hop's host — covers the initial request too, not just
      // redirect targets (an OAuth authorization-server host is server-chosen).
      if (cur.protocol !== 'http:' && cur.protocol !== 'https:')
        throw new Error(`Blocked request to non-http scheme "${cur.protocol}".`);
      if (opts.allowedHosts && !opts.allowedHosts.includes(cur.hostname))
        throw new Error(`Blocked request to disallowed host "${cur.hostname}".`);
      // Resolved, not just string-matched: an OAuth authorization-server host is
      // chosen by the *target server's* metadata, so it is exactly the place a
      // rebinding name would be planted.
      if (opts.blockPrivateHosts && !opts.allowedHosts?.includes(cur.hostname)
          && (await isBlockedHostResolved(cur.hostname)))
        throw new Error(`SSRF: blocked request to private/loopback host "${cur.hostname}".`);

      // Credentials (the SDK-injected OAuth bearer in init.headers, and any
      // static --header) go ONLY to the exact target ORIGIN; stripped on any
      // cross-origin hop (redirect, downgrade, different port).
      const headers = applyCredentialGate(
        init?.headers as ConstructorParameters<typeof Headers>[0],
        cur.origin === parsed.origin,
        opts.headers,
      );

      const res = await fetch(current, { ...init, headers, redirect: 'manual' });
      const loc = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
      if (!loc) return res;
      current = new URL(loc, current).href;
    }
    throw new Error('Too many redirects.');
  };

  const connect = async (): Promise<void> => {
    try {
      const t = new sdk.StreamableHTTPClientTransport(parsed, { fetch: guardedFetch });
      await withTimeout(client.connect(t), CONNECT_TIMEOUT_MS, 'http connect');
    } catch {
      const sseT = new sdk.SSEClientTransport(parsed, { fetch: guardedFetch });
      await withTimeout(client.connect(sseT), CONNECT_TIMEOUT_MS, 'sse connect');
    }
  };

  // Interactive OAuth: register a client, open the browser, catch the redirect,
  // exchange the code for a token, then reconnect authenticated.
  const connectWithOAuth = async (): Promise<void> => {
    const { CliOAuthProvider, startCallbackServer, openBrowser } = await import('./oauth.js');
    const cb = await startCallbackServer();
    // Flips true the instant the browser sign-in is triggered. After that, a
    // failure (denied consent, callback timeout, token-exchange error) is NOT a
    // transport mismatch — we must not restart the flow on SSE (a second browser
    // window + reuse of the already-settled single-shot callback promise).
    let authStarted = false;
    const provider = new CliOAuthProvider(
      cb.redirectUrl,
      opts.scope,
      (authUrl: URL) => {
        authStarted = true;
        process.stderr.write(
          `\n${'→'} This MCP server requires sign-in. Opening your browser…\n` +
            `  If it doesn't open, paste this URL:\n  ${authUrl.href}\n\n`,
        );
        openBrowser(authUrl.href);
      },
      cb.state,
    );

    const attempt = async (TransportCtor: any): Promise<void> => {
      let transport = new TransportCtor(parsed, { authProvider: provider, fetch: guardedFetch });
      try {
        await withTimeout(client.connect(transport), CONNECT_TIMEOUT_MS, 'oauth connect');
      } catch (err) {
        if (sdk.UnauthorizedError && err instanceof sdk.UnauthorizedError) {
          const code = await cb.waitForCode();
          await transport.finishAuth(code);
          transport = new TransportCtor(parsed, { authProvider: provider, fetch: guardedFetch });
          await withTimeout(client.connect(transport), CONNECT_TIMEOUT_MS, 'oauth reconnect');
        } else {
          throw err;
        }
      }
    };

    try {
      try {
        await attempt(sdk.StreamableHTTPClientTransport);
      } catch (primary) {
        // Fall back to SSE ONLY for a pre-auth transport/protocol mismatch; once
        // the browser has opened, surface the real error instead of re-running
        // the whole sign-in on a second transport.
        if (authStarted || (sdk.UnauthorizedError && primary instanceof sdk.UnauthorizedError)) throw primary;
        await attempt(sdk.SSEClientTransport);
      }
    } finally {
      cb.close();
    }
  };

  try {
    await (opts.login ? connectWithOAuth() : connect());
    const enumd = await enumerate(client);
    const surface = surfaceFromManifest({ ...enumd }, url, url);
    surface.source = { kind: 'http', origin: url };
    surface.transport = { kind: 'http', url };
    return surface;
  } finally {
    await client.close?.().catch(() => {});
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */
