/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability extraction: derive each tool's roles (untrusted-input,
 * sensitive-source, external-sink, code-exec, file-write) from its name,
 * description verbs, and parameter shape. This is the substrate the toxic-flow
 * graph runs over. It is deliberately derived from behavior, never from the
 * server's self-declared `annotations` (which are untrusted).
 */

import type { CapabilityTag, ResolvedConfig, ServerSurface, ToolCapability, ToolDef } from '../types.js';
import { CAPABILITY_SIGNALS, PARAM_NAME_SIGNALS } from '../data/capabilityLexicon.js';
import { normalizeForMatch } from './text.js';

function tokenize(text: string): Set<string> {
  return new Set(normalizeForMatch(text).split(' ').filter(Boolean));
}

function keywordMatches(haystack: string, tokens: Set<string>, keyword: string): boolean {
  const k = normalizeForMatch(keyword);
  if (k.includes(' ')) return haystack.includes(k);
  return tokens.has(k);
}

function paramNames(tool: ToolDef): string[] {
  const props = tool.inputSchema?.properties;
  if (!props) return [];
  return Object.keys(props);
}

/** Extract capability tags + evidence for a single tool. */
export function extractToolCapability(tool: ToolDef): ToolCapability {
  const name = typeof tool?.name === 'string' ? tool.name : '';
  const desc = typeof tool?.description === 'string' ? tool.description : '';
  const haystack = normalizeForMatch(`${name} ${desc}`);
  const tokens = tokenize(`${name} ${desc}`);
  // Operative surface = the tool NAME only (what the tool DOES), used for the
  // high-impact capability tags below.
  const nameHay = normalizeForMatch(name);
  const nameTokens = tokenize(name);
  const reasons: Partial<Record<CapabilityTag, string[]>> = {};
  const tags = new Set<CapabilityTag>();

  const addReason = (tag: CapabilityTag, why: string): void => {
    tags.add(tag);
    (reasons[tag] ??= []).push(why);
  };

  // `code-exec` and `file-write` are the tags that drive the biggest blast-radius
  // penalty (-6/-10). Require OPERATIVE evidence — the keyword in the tool NAME, not
  // in prose — for them: a read-only analyzer DESCRIBED as "detects shell/eval usage"
  // must not itself be tagged command-execution. Param-name signals (below) still add
  // operative evidence. Other tags keep name+description matching.
  const OPERATIVE_ONLY = new Set<CapabilityTag>(['code-exec', 'file-write']);
  for (const sig of CAPABILITY_SIGNALS) {
    const operative = OPERATIVE_ONLY.has(sig.tag);
    const hay = operative ? nameHay : haystack;
    const toks = operative ? nameTokens : tokens;
    for (const kw of sig.keywords) {
      if (keywordMatches(hay, toks, kw)) {
        addReason(sig.tag, `keyword "${kw}"${operative ? ' in tool name' : ''}`);
        break; // one reason per signal is enough
      }
    }
  }

  const pnames = paramNames(tool).map((n) => n.toLowerCase());
  const pTokens = new Set(pnames.flatMap((n) => n.split(/[^a-z0-9]+/i).filter(Boolean)));
  for (const sig of PARAM_NAME_SIGNALS) {
    for (const pn of sig.names) {
      if (pTokens.has(pn)) {
        addReason(sig.tag, `parameter "${pn}"`);
        break;
      }
    }
  }

  // Read-only getter exclusion: a tool whose NAME is a pure getter reads or
  // enumerates — it neither sends data out nor mutates files. A getter that only
  // MATCHED a sink/write keyword ('list_webhooks' hitting "webhook", 'get_config'
  // picking up external-sink) is a spurious toxic-flow leg, so strip those two
  // roles. Its read roles (sensitive-source / untrusted-input) are kept, and any
  // getter that ALSO does a write/send verb is left untouched.
  const isGetter =
    /^(get|list|read|fetch|search|find|query|show|view|describe|count|check|has|is|lookup)[_-]/i.test(name) ||
    /(_results?|_list|_status|_info|_config|_details?|_metadata)$/i.test(name);
  const alsoMutates = /write|create|update|delete|set[_-]|put[_-]|send|post|upload|edit|modif|append|remove|publish|forward/i.test(name);
  if (isGetter && !alsoMutates) {
    tags.delete('external-sink');
    tags.delete('file-write');
    delete reasons['external-sink'];
    delete reasons['file-write'];
  }

  return { tool: name, tags: [...tags], reasons };
}

/** Extract capabilities for every tool in a surface (non-object tools skipped). */
export function extractCapabilities(surface: ServerSurface, _config: ResolvedConfig): ToolCapability[] {
  const tools = Array.isArray(surface.tools) ? surface.tools : [];
  return tools.filter((t): t is ToolDef => Boolean(t) && typeof t === 'object').map(extractToolCapability);
}

/** Tags that can act as an exfiltration/impact sink. */
export const SINK_TAGS: CapabilityTag[] = ['external-sink', 'code-exec'];

/** True if a capability set can serve as an external sink. */
export function isSink(tags: CapabilityTag[]): boolean {
  return tags.some((t) => SINK_TAGS.includes(t));
}
