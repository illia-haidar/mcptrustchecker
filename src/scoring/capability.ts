/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability (blast-radius) rating — the second axis, independent of the trust
 * grade. It answers "how much could this server do if the model driving it were
 * prompt-injected?" A legitimate, well-behaved server can still be high- or
 * critical-capability; that is not a mark against its trustworthiness, it is
 * information for deciding how much access to grant.
 */

import type {
  CapabilityLevel,
  CapabilityProfile,
  CapabilityTag,
  Finding,
  JsonSchema,
  ServerSurface,
  ToolCapability,
  ToolDef,
  ToxicFlow,
} from '../types.js';
import { SSRF_PARAM_NAMES } from '../data/capabilityLexicon.js';
import { boundsWholeValue, staticParamFacts } from '../util/capabilities.js';

const ORDER: CapabilityLevel[] = ['minimal', 'moderate', 'high', 'critical'];

function atLeast(current: CapabilityLevel, candidate: CapabilityLevel): CapabilityLevel {
  return ORDER.indexOf(candidate) > ORDER.indexOf(current) ? candidate : current;
}

export const OPEN_DESTINATION_REASON = 'ingests untrusted content from a destination the model chooses (SSRF / egress through the URL)';
export const UNTRUSTED_INPUT_OBSERVATION = 'ingests untrusted external content (a prompt-injection entry point; not priced on its own)';

/** A schema the model can fill with any destination: a string (or list of them) no enum, const or bounding pattern holds. */
function freeDestination(prop: unknown, depth = 0): boolean {
  if (!prop || typeof prop !== 'object' || Array.isArray(prop)) return prop === undefined || prop === true;
  const s = prop as JsonSchema;
  if (Array.isArray(s.enum) && s.enum.length > 0) return false;
  if (Object.hasOwn(s, 'const')) return false;
  if (typeof s.pattern === 'string' && boundsWholeValue(s.pattern)) return false;
  // `Optional[str]` / a union: open when any branch is.
  for (const k of ['anyOf', 'oneOf'] as const) {
    const branches = s[k];
    if (Array.isArray(branches) && branches.length > 0 && depth < 2) return branches.some((b) => freeDestination(b, depth + 1));
  }
  const types = Array.isArray(s.type) ? s.type : s.type === undefined ? [] : [s.type];
  if (types.length === 0 || types.includes('string')) return true;
  if (types.includes('array') && depth < 2) {
    const items = s.items ?? {};
    return Array.isArray(items) ? items.some((i) => freeDestination(i, depth + 1)) : freeDestination(items, depth + 1);
  }
  return false;
}

/** A URL / host parameter by one of its words, camelCase split too: `url`, `targetUrl`, `base_url`, a list of `urls`. */
const namesDestination = (name: string): boolean =>
  name
    .slice(0, 200)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .some((w) => SSRF_PARAM_NAMES.includes(w) || (w.endsWith('s') && SSRF_PARAM_NAMES.includes(w.slice(0, -1))));

/**
 * Does the model choose where this tool's request goes? It ingests or sends
 * (`untrusted-input` / `external-sink`) and either takes a URL / host parameter
 * nothing pins down, or its own evidence says the URL comes from its input (the
 * `param` and `handler` sources of `untrusted-input`). Read from the tool itself,
 * never from MTC-CAP-007: disabling that rule or the capability detector must not
 * move the score.
 */
function opensDestination(cap: ToolCapability, defs: ToolDef[], surface: ServerSurface | undefined): boolean {
  if (!cap.tags.includes('untrusted-input') && !cap.tags.includes('external-sink')) return false;
  const from = cap.sources?.['untrusted-input'] ?? [];
  if (from.includes('param') || from.includes('handler')) return true;
  for (const def of defs) {
    const props = def.inputSchema?.properties;
    if (!props || typeof props !== 'object') continue;
    for (const [pname, pschema] of Object.entries(props)) {
      if (!namesDestination(pname) || !freeDestination(pschema)) continue;
      // A statically recovered tool keeps only parameter NAMES; its registration
      // source says whether the value is an enum, a literal or a pattern — and a
      // pattern pins the destination only when it bounds the whole value, as above.
      const empty = !pschema || (typeof pschema === 'object' && Object.keys(pschema).length === 0);
      const facts = empty && surface ? staticParamFacts(surface, def.name, pname) : undefined;
      if (facts?.constrained && (facts.pattern === undefined || boundsWholeValue(facts.pattern))) continue;
      return true;
    }
  }
  return false;
}

export function computeCapabilityProfile(
  capabilities: ToolCapability[],
  flows: ToxicFlow[],
  findings: Finding[] = [],
  surface?: ServerSurface,
): CapabilityProfile {
  const tagSet = new Set<CapabilityTag>(capabilities.flatMap((c) => c.tags));
  // The source scan sees what the implementation DOES even when the tool
  // metadata under-declares it: code that spawns processes is code-exec
  // capability, a hardcoded endpoint is an external sink, a credential-path
  // read is a sensitive source. Feeding these into the same tag set keeps one
  // capability model for both axes of evidence.
  const ruleTag: Record<string, CapabilityTag> = {
    'MTC-SRC-001': 'code-exec',
    'MTC-SRC-002': 'code-exec',
    // SRC-010 (dynamic eval of a non-literal) is code-exec capability, same as
    // SRC-001 — moved off the threat axis (see CAPABILITY_RULES); it must still
    // raise the blast radius here or the eval sink would vanish from both axes.
    'MTC-SRC-010': 'code-exec',
    'MTC-SRC-003': 'external-sink',
    'MTC-SRC-006': 'sensitive-source',
  };
  for (const f of findings) {
    // A source finding downgraded to packaging/dev tooling (non-runtime), or in a
    // file the MCP server does not import, ships — but it is not the server's
    // request-handling surface, so it must NOT inflate the client's blast radius.
    // Without this the downgrade is cosmetic: the finding still buys the -6/-10.
    if (f.data?.nonRuntime) continue;
    // A finding can carry its own tag: MTC-SRC-002 tags a runtime-chosen command
    // `code-exec`, a fixed program `process-spawn`, and a fixed program with fixed
    // arguments nothing at all (`null`). Absent, the rule's default applies.
    const explicit = f.data && 'capabilityTag' in f.data ? (f.data.capabilityTag as CapabilityTag | null) : undefined;
    const tag = explicit !== undefined ? explicit : ruleTag[f.ruleId];
    if (tag) tagSet.add(tag);
  }
  const has = (t: CapabilityTag): boolean => tagSet.has(t);
  const reasons: string[] = [];
  const observations: string[] = [];
  let level: CapabilityLevel = 'minimal';

  const bump = (candidate: CapabilityLevel, reason: string): void => {
    level = atLeast(level, candidate);
    reasons.push(reason);
  };

  // Reading outside content is an entry point, not damage: a tool that only
  // brings text in can do nothing by itself, and the combinations that turn it
  // into harm (the trifecta, a link to code execution) are priced below. It is
  // blast radius only when the model chooses WHERE the request goes — SSRF into
  // the internal network or cloud metadata, data out through the URL itself.
  // Otherwise the fact stays on the profile as an observation, without points.
  if (has('untrusted-input')) {
    const defsByName = new Map<string, ToolDef[]>();
    for (const t of Array.isArray(surface?.tools) ? surface.tools : []) {
      if (!t || typeof t !== 'object' || typeof t.name !== 'string') continue;
      const list = defsByName.get(t.name);
      if (list) list.push(t);
      else defsByName.set(t.name, [t]);
    }
    if (capabilities.some((c) => opensDestination(c, defsByName.get(c.tool) ?? [], surface))) bump('moderate', OPEN_DESTINATION_REASON);
    else observations.push(UNTRUSTED_INPUT_OBSERVATION);
  }
  if (has('external-sink')) bump('moderate', 'can send data / act on an external service');
  if (has('file-write')) bump('moderate', 'can create, modify or delete files');
  if (has('sensitive-source')) bump('moderate', 'reads sensitive or local data');
  // A fixed program (`execFile("git", […])`) is a real capability but not code
  // execution: the model cannot choose what runs. Never more than moderate.
  if (has('process-spawn')) bump('moderate', 'can start a fixed program (a process-spawning capability, not arbitrary code execution)');
  if (has('state-write')) bump('moderate', 'a tool declares that it changes state it has access to');

  if (has('sensitive-source') && (has('external-sink') || has('code-exec'))) {
    bump('high', 'has a read → egress path (a data-exfiltration surface)');
  }
  if (has('code-exec')) bump('high', 'can execute shell commands or code');

  const roleComplete = (f: ToxicFlow): boolean =>
    f.untrustedInput.length > 0 && f.sensitiveSource.length > 0 && f.externalSink.length > 0;
  const selfContained = flows.some((f) => f.selfContained && roleComplete(f));
  const crossTrifecta = flows.some((f) => !f.selfContained && roleComplete(f));

  if (crossTrifecta) bump('high', 'untrusted-input, sensitive-source and egress co-exist across tools (toxic-flow surface)');
  if (selfContained) bump('critical', 'a single tool completes the exfiltration trifecta by itself');
  // CRITICAL from code-exec + untrusted-input requires an actual LINKAGE, not mere
  // co-occurrence: a real toxic flow connecting the two, or a runtime assembled-
  // command finding (MTC-SRC-009). Co-presence alone stays at `high` (-6) — else
  // ~700 packages eat an extra -4 for two unrelated tools existing in one server.
  const assembledCommand = findings.some((f) => f.ruleId === 'MTC-SRC-009' && !f.data?.nonRuntime);
  if (has('code-exec') && has('untrusted-input') && (selfContained || crossTrifecta || assembledCommand)) {
    bump('critical', 'untrusted input can reach code execution');
  }

  // De-duplicate reasons while preserving order.
  const seen = new Set<string>();
  const uniqueReasons = reasons.filter((r) => (seen.has(r) ? false : (seen.add(r), true)));

  return { level, reasons: uniqueReasons, tags: [...tagSet], observations };
}
