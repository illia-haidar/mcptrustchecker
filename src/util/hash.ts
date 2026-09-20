/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Canonicalization & hashing for the rug-pull (TOFU) integrity fingerprint.
 *
 * Trust binds to *content*, not to a name (the MCPoison lesson). We therefore
 * hash the full canonicalized tool surface — name + description + full schema +
 * annotations + the spawn command — so any silent redefinition changes the
 * digest and is caught on rescan.
 */

import { createHash } from 'node:crypto';
import type { ServerSurface, ToolDef } from '../types.js';

/** Deterministic JSON: object keys sorted recursively. */
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortDeep(value, 0, new WeakSet()));
}

// Bound the recursion so a hostile, deeply-nested schema can't overflow the
// stack during hashing. 200 is far beyond any legitimate JSON-Schema depth.
const MAX_HASH_DEPTH = 200;

function sortDeep(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (depth > MAX_HASH_DEPTH) return '__mcptrustchecker_truncated__';
  if (value && typeof value === 'object') {
    // A shared subtree (DAG) would otherwise expand exponentially even under the
    // depth cap — visit each node once.
    if (seen.has(value)) return '__mcptrustchecker_cycle__';
    seen.add(value as object);
  }
  if (Array.isArray(value)) return value.map((v) => sortDeep(v, depth + 1, seen));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortDeep((value as Record<string, unknown>)[key], depth + 1, seen);
    }
    return out;
  }
  return value;
}

/** Canonical per-tool projection used for both the digest and drift diffs. */
export function canonicalTool(tool: ToolDef): Record<string, unknown> {
  return {
    name: typeof tool.name === 'string' ? tool.name : String(tool.name ?? ''),
    // `title` is the display name a client puts on the consent prompt. Leaving
    // it out of the pin let a server swap what the user reads at approval time
    // without tripping the drift check.
    title: typeof tool.title === 'string' ? tool.title : '',
    description: typeof tool.description === 'string' ? tool.description : '',
    inputSchema: tool.inputSchema ?? null,
    outputSchema: tool.outputSchema ?? null,
    annotations: tool.annotations ?? null,
  };
}

/** The canonical, security-relevant projection of a whole surface. */
export function canonicalSurface(surface: ServerSurface): Record<string, unknown> {
  const tools = (Array.isArray(surface.tools) ? [...surface.tools] : [])
    .filter((t): t is ToolDef => Boolean(t) && typeof t === 'object')
    // Code-unit sort, NOT localeCompare — ICU collation is locale-dependent, so
    // the same tool set could canonicalize differently on two machines and raise
    // a false rug-pull DRIFT. This must be byte-reproducible everywhere.
    .sort((a, b) => {
      const x = String(a.name ?? '');
      const y = String(b.name ?? '');
      return x < y ? -1 : x > y ? 1 : 0;
    })
    .map(canonicalTool);
  return {
    server: {
      name: surface.server.name ?? '',
      instructions: surface.server.instructions ?? '',
    },
    tools,
    transport: surface.transport
      ? { kind: surface.transport.kind, command: surface.transport.command ?? '', args: surface.transport.args ?? [] }
      : null,
  };
}

/** SHA-256 over the canonical surface — the rug-pull fingerprint. */
export function surfaceDigest(surface: ServerSurface): string {
  return createHash('sha256').update(stableStringify(canonicalSurface(surface))).digest('hex');
}

/** SHA-256 over a single canonical tool (used to diff which tools changed). */
export function toolDigest(tool: ToolDef): string {
  return createHash('sha256').update(stableStringify(canonicalTool(tool))).digest('hex');
}
