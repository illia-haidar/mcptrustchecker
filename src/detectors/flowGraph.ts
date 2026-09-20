/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Dataflow graph for the toxic-flow analysis.
 *
 * MCP tools are not statically wired to each other — the *agent* orchestrates
 * them. So the conservative model is: any tool's output can reach any other
 * tool's input via the model ("agent-mediated" edge). On top of that we detect
 * the higher-plausibility case where a consumer exposes an unconstrained
 * free-text / URL parameter that a producer's output can be dropped straight
 * into ("schema-wired" edge).
 *
 * From that graph we recover a concrete UNTRUSTED → SENSITIVE → SINK **path**
 * (the actual attack chain, e.g. `fetch_url → read_file → http_request`) and
 * grade confidence by how directly the legs are wired — turning a co-presence
 * heuristic into an explainable, path-level result.
 */

import type { CapabilityTag, ToolCapability, ToolDef } from '../types.js';

export type FlowEdgeKind = 'schema-wired' | 'agent-mediated';

export interface FlowEdge {
  from: string;
  to: string;
  kind: FlowEdgeKind;
}

export interface FlowPath {
  /** Ordered tools forming the attack chain (2 or 3 hops). */
  path: string[];
  edges: FlowEdge[];
  /** True when at least one leg is a direct schema wire (higher plausibility). */
  wired: boolean;
}

/** Parameter names that accept free-form content a producer's output slots into. */
const FREE_TEXT_PARAMS = new Set([
  'content', 'body', 'text', 'data', 'input', 'message', 'prompt', 'query', 'q',
  'url', 'uri', 'html', 'markdown', 'payload', 'value', 'string', 'document',
]);

/** Does this tool expose an unconstrained string param a producer can feed? */
export function consumesFreeText(tool: ToolDef | undefined): boolean {
  const props = tool?.inputSchema?.properties;
  if (!props || typeof props !== 'object') return false;
  for (const [name, schema] of Object.entries(props)) {
    if (!FREE_TEXT_PARAMS.has(name.toLowerCase())) continue;
    const t = (schema as { type?: unknown; enum?: unknown })?.type;
    const stringy = t === undefined || t === 'string' || (Array.isArray(t) && t.includes('string'));
    const constrained = Boolean((schema as { enum?: unknown; pattern?: unknown })?.enum) ||
      Boolean((schema as { pattern?: unknown })?.pattern);
    if (stringy && !constrained) return true;
  }
  return false;
}

function edge(from: string, to: string, toolByName: Map<string, ToolDef>): FlowEdge {
  // A leg is a "schema wire" when the consumer takes free text (the producer's
  // output can be dropped straight in); otherwise the agent has to mediate it.
  const kind: FlowEdgeKind = consumesFreeText(toolByName.get(to)) ? 'schema-wired' : 'agent-mediated';
  return { from, to, kind };
}

const has = (c: ToolCapability, tag: CapabilityTag): boolean => c.tags.includes(tag);
const isSink = (c: ToolCapability): boolean => has(c, 'external-sink') || has(c, 'code-exec');

/**
 * Recover a representative untrusted → sensitive → sink attack path. Legs are
 * chosen deterministically (lexicographic) and preferentially across *distinct*
 * tools so the chain reads as a real composition. Returns null if the trifecta
 * is not completable.
 */
export function representativeTrifectaPath(
  caps: ToolCapability[],
  tools: ToolDef[],
): FlowPath | null {
  const toolByName = new Map(tools.filter((t) => t && typeof t.name === 'string').map((t) => [t.name, t]));
  const sorted = [...caps].sort((a, b) => (a.tool < b.tool ? -1 : a.tool > b.tool ? 1 : 0));
  const untrusted = sorted.filter((c) => has(c, 'untrusted-input')).map((c) => c.tool);
  const sources = sorted.filter((c) => has(c, 'sensitive-source')).map((c) => c.tool);
  const sinks = sorted.filter(isSink).map((c) => c.tool);
  if (!untrusted.length || !sources.length || !sinks.length) return null;

  // Prefer legs on distinct tools; fall back to reuse when the surface is small.
  const pick = (pool: string[], avoid: Set<string>): string =>
    pool.find((t) => !avoid.has(t)) ?? pool[0]!;
  const used = new Set<string>();
  const u = pick(untrusted, used); used.add(u);
  const s = pick(sources, used); used.add(s);
  const k = pick(sinks, used);

  // Collapse consecutive duplicates (a tool holding two roles) into one node.
  const nodes: string[] = [];
  for (const n of [u, s, k]) if (nodes[nodes.length - 1] !== n) nodes.push(n);

  const edges: FlowEdge[] = [];
  for (let i = 0; i < nodes.length - 1; i++) edges.push(edge(nodes[i]!, nodes[i + 1]!, toolByName));
  return { path: nodes, edges, wired: edges.some((e) => e.kind === 'schema-wired') };
}

/** A representative sensitive-source → external-sink path (no untrusted leg). */
export function representativeExfilPath(caps: ToolCapability[], tools: ToolDef[]): FlowPath | null {
  const toolByName = new Map(tools.filter((t) => t && typeof t.name === 'string').map((t) => [t.name, t]));
  const sorted = [...caps].sort((a, b) => (a.tool < b.tool ? -1 : a.tool > b.tool ? 1 : 0));
  const sources = sorted.filter((c) => has(c, 'sensitive-source')).map((c) => c.tool);
  const sinks = sorted.filter(isSink).map((c) => c.tool);
  const s = sources[0];
  const k = sinks.find((x) => x !== s) ?? sinks[0];
  if (!s || !k) return null;
  const nodes = s === k ? [s] : [s, k];
  const edges = nodes.length === 2 ? [edge(nodes[0]!, nodes[1]!, toolByName)] : [];
  return { path: nodes, edges, wired: edges.some((e) => e.kind === 'schema-wired') };
}

/** Render a path as an arrow chain for a human-readable finding. */
export function renderPath(p: FlowPath): string {
  if (p.path.length === 1) return p.path[0]!;
  return p.path
    .map((n, i) => (i === 0 ? n : `${p.edges[i - 1]!.kind === 'schema-wired' ? '⇒' : '→'} ${n}`))
    .join(' ');
}
