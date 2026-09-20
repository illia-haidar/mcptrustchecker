/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Parse an MCP client config (`claude_desktop_config.json`, Cursor, Windsurf,
 * VS Code, Continue, …) into a list of server specs. All these clients share
 * the `mcpServers` map shape.
 */

export interface ConfigServerSpec {
  id: string;
  transport: 'stdio' | 'http';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

type AnyObj = Record<string, unknown>;

/** Detect whether a parsed JSON object is a client config (vs a manifest). */
export function isClientConfig(json: unknown): boolean {
  return Boolean(json && typeof json === 'object' && ('mcpServers' in (json as AnyObj) || 'servers' in (json as AnyObj)));
}

/** Extract server specs from a client config object. */
export function parseClientConfig(json: unknown): ConfigServerSpec[] {
  const root = (json ?? {}) as AnyObj;
  const servers = (root.mcpServers ?? root.servers ?? {}) as AnyObj;
  const specs: ConfigServerSpec[] = [];
  for (const [id, raw] of Object.entries(servers)) {
    if (!raw || typeof raw !== 'object') continue;
    const s = raw as AnyObj;
    const url = typeof s.url === 'string' ? s.url : undefined;
    if (url) {
      specs.push({ id, transport: 'http', url });
    } else if (typeof s.command === 'string') {
      specs.push({
        id,
        transport: 'stdio',
        command: s.command,
        args: Array.isArray(s.args) ? (s.args as string[]) : [],
        env: (s.env as Record<string, string>) ?? undefined,
      });
    }
  }
  return specs;
}

/**
 * Expand `${VAR}` / `$VAR` references using the given env (typically the
 * server entry's own `env` block merged over process.env) — exactly what MCP
 * clients do before spawning, so an auth header like `Authorization:${AUTH}`
 * resolves. Unknown variables are left untouched rather than silently blanked.
 */
export function expandVars(input: string, env: Record<string, string | undefined>): string {
  return input.replace(/\$\{(\w+)\}|\$(\w+)/g, (match, braced, bare) => {
    const name = braced ?? bare;
    const val = env[name];
    return val === undefined ? match : val;
  });
}

/** Strip a trailing `@version` from a package spec, preserving the scope. */
export function stripVersion(spec: string): string {
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 0) return spec;
    const rest = spec.slice(slash + 1);
    const at = rest.indexOf('@');
    return at >= 0 ? spec.slice(0, slash + 1 + at) : spec;
  }
  const at = spec.indexOf('@');
  return at >= 0 ? spec.slice(0, at) : spec;
}

/** Split a package spec into its name and version token (if any). */
export function versionOf(spec: string): string | undefined {
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 0) return undefined;
    const at = spec.slice(slash + 1).indexOf('@');
    return at >= 0 ? spec.slice(slash + 1 + at + 1) : undefined;
  }
  const at = spec.indexOf('@');
  return at >= 0 ? spec.slice(at + 1) : undefined;
}

/**
 * Best-effort: pull the npm/PyPI package name (and version token) out of an
 * `npx`/`uvx`-style stdio spec so the supply-chain stage has something to check
 * without running the server.
 */
export function packageSpecFromStdio(command: string, args: string[] = []): { name: string; version?: string } | undefined {
  const base = command.replace(/\\/g, '/');
  const runner = base.slice(base.lastIndexOf('/') + 1).replace(/\.(cmd|exe)$/, '');
  const skip = new Set(['-y', '--yes', 'dlx', 'exec', '-q', '--quiet', 'run']);
  if (['npx', 'bunx', 'pnpm', 'yarn', 'uvx', 'pipx'].includes(runner)) {
    for (const a of args) {
      if (a.startsWith('-') || skip.has(a)) continue;
      return { name: stripVersion(a), version: versionOf(a) };
    }
  }
  return undefined;
}

/** Package name only (back-compat convenience). */
export function packageFromStdio(command: string, args: string[] = []): string | undefined {
  return packageSpecFromStdio(command, args)?.name;
}

function redactValue(a: string): string {
  return a
    .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1<redacted>')
    // Redact the WHOLE Authorization value (Basic <base64>, Digest …), not just
    // the first token — the credential lives after the scheme word.
    .replace(/(authorization\s*[:=]\s*)(?!bearer\b).+$/gi, '$1<redacted>')
    .replace(/(cookie\s*[:=]\s*).+$/gi, '$1<redacted>')
    .replace(/((?:api[_-]?key|token|secret|password|access[_-]?token)\s*[:=]\s*)\S+/gi, '$1<redacted>');
}

// Flags whose FOLLOWING arg is the secret itself → always redact (any length).
const VALUE_IS_SECRET = /^(--token|--api-?key|--auth|--authorization|--secret|--password|--pass|--bearer|--key|--pat)$/i;
// Header flags whose following arg is "Name: value" → redact only a secret value.
const HEADER_FLAG = /^(--header|-h|--headers)$/i;

/**
 * Redact secrets from a spawn arg vector before storing/printing them — a
 * security scanner must not leak the user's own tokens in its report. Handles
 * inline `Authorization:Bearer …` values, header flags (secret value only), and
 * bare values following a dedicated secret flag (redacted regardless of length).
 */
export function redactSensitiveArgs(args: string[]): string[] {
  return args.map((a, i) => {
    const prev = args[i - 1] ?? '';
    if (VALUE_IS_SECRET.test(prev)) return '<redacted>';
    if (HEADER_FLAG.test(prev)) return redactValue(a); // header value only if it looks secret
    return redactValue(a); // inline secret patterns anywhere
  });
}
