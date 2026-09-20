/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Parse repeated `--header "Name: Value"` CLI arguments into a header map.
 * Used to authenticate against protected remote MCP endpoints (e.g. a Bearer
 * token). Kept pure and separate from the CLI entrypoint so it stays testable.
 */
export function parseHeaderArgs(items?: string[]): Record<string, string> | undefined {
  if (!items || items.length === 0) return undefined;
  const out: Record<string, string> = {};
  for (const raw of items) {
    const item = raw.trim();
    const idx = item.indexOf(':');
    if (idx <= 0) throw new Error(`Invalid --header "${raw}" — expected "Name: Value".`);
    const name = item.slice(0, idx).trim();
    const value = item.slice(idx + 1).trim();
    if (!name) throw new Error(`Invalid --header "${raw}" — empty header name.`);
    out[name] = value;
  }
  return out;
}

/** Credential headers that must never cross an origin boundary on a redirect. */
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'proxy-authorization', 'mcp-session-id'];

/**
 * Contain credentials to the target origin. On the target origin, keep the
 * request's own headers and add any static `--header`s. On any OTHER origin
 * (cross-host redirect, https→http downgrade, different port), strip the
 * credential headers the caller/SDK attached (incl. the OAuth bearer) and drop
 * the static headers — mirroring how a browser drops `Authorization` across
 * origins, so a redirect can't exfiltrate a token.
 */
export function applyCredentialGate(
  rawHeaders: ConstructorParameters<typeof Headers>[0],
  sameOrigin: boolean,
  staticHeaders?: Record<string, string>,
): Headers {
  const headers = new Headers(rawHeaders);
  if (sameOrigin) {
    if (staticHeaders) for (const [k, v] of Object.entries(staticHeaders)) headers.set(k, v);
  } else {
    for (const h of CREDENTIAL_HEADERS) headers.delete(h);
    if (staticHeaders) for (const k of Object.keys(staticHeaders)) headers.delete(k);
  }
  return headers;
}
