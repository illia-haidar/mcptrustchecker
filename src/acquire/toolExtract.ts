/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Static tool extraction — recover a server's tool surface from its PUBLISHED
 * SOURCE when no running server enumerated it.
 *
 * WHY: a package scan reads the real source (an `--online` fetch) but never spawns
 * the server, so `surface.tools` is empty and the MCP-specific detectors that key
 * off the tool surface — tool-poisoning (injection), hidden-Unicode smuggling,
 * cross-tool toxic flows, tool-name collisions, per-tool capability — have nothing
 * to inspect. The tool definitions, however, are right there in the source: every
 * SDK registers them with a literal name and description. This module parses those
 * registrations into a synthetic {@link ToolDef} surface so those detectors run on
 * a package scan, turning "no tools were enumerated" into real MCP-threat analysis.
 *
 * PHILOSOPHY — bias to MISS, never to MIS-ATTRIBUTE. A missed tool leaves the scan
 * exactly where it is today (no worse); a mis-attributed tool could raise a false
 * finding against a legitimate package, which is worse than the known gap. So the
 * matchers are deliberately narrow (literal names, recognised SDK call shapes),
 * test/example/fixture files are skipped, and anything ambiguous is dropped. The
 * result is marked `toolProvenance: 'static'` on the surface so the engine caps the
 * confidence of tool-derived findings — a statically-inferred tool can never force
 * the confirmed-critical F-gate; a live scan (`--command`) is what confirms it.
 *
 * This is intentionally NOT a full parser/AST: published MCP servers ship readable
 * JS/TS/Python, and a lexical pass over recognised call shapes is both robust to
 * dialect (ESM/CJS/TS, FastMCP/low-level) and immune to the "evaluate arbitrary
 * code" foot-guns of a real evaluator.
 */

import type { SourceFile, StaticToolOrigin, ToolDef, JsonSchema } from '../types.js';
import { MAX_MERGED_DESC, mergeDescriptions, mergeHints, readRegistrationsWithStats } from '../analysis/toolRegistry.js';

export interface ToolExtractionResult {
  tools: ToolDef[];
  /** True when at least one tool was recovered (⟺ the surface may be marked static). */
  extracted: boolean;
  /** Files that contributed ≥1 tool — for the coverage caveat / debugging. */
  fromFiles: string[];
  /** How each tool was recovered (registration shape, hints, condition, handler evidence). */
  origins: Record<string, StaticToolOrigin>;
  /** Files where a reading cap was hit — some of their tools may be missing. */
  truncated: string[];
}

// A source file is worth scanning only if it can contain a tool registration.
const CODE_EXT = /\.(mjs|cjs|js|jsx|ts|tsx|mts|cts|py)$/i;
// Declaration files carry no runtime registrations; sourcemaps are noise.
const SKIP_EXT = /\.(d\.ts|map)$/i;
// Test / example / fixture code frequently defines throwaway "tools" that are NOT
// the package's real surface — extracting them is a pure false-positive source.
const SKIP_PATH = /(^|\/)(test|tests|__tests__|__mocks__|examples?|fixtures?|spec|specs|docs?|samples?)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/i;
// A byte ceiling per file — a legit server module is small; an enormous bundle is
// both a DoS risk for the regexes and unlikely to be hand-written source.
const MAX_FILE_BYTES = 512 * 1024;
// Never advertise more tools than a real server plausibly has — a match explosion
// means the matcher latched onto something that is not a tool registration.
const MAX_TOOLS = 200;
const MAX_NAME_LEN = 128;
const MAX_DESC_LEN = 8192;

/** A plausible MCP tool name: the SDK requires a non-empty, reasonably short id. */
function looksLikeToolName(name: string): boolean {
  if (!name || name.length > MAX_NAME_LEN) return false;
  // Tool names are identifiers/slugs, not sentences or paths.
  return /^[A-Za-z0-9._:\- ]{1,128}$/.test(name) && /[A-Za-z0-9]/.test(name);
}

/** Decode the common escapes in a captured string literal, bounded in length. */
function cleanString(raw: string | undefined, max = MAX_DESC_LEN): string | undefined {
  if (typeof raw !== 'string') return undefined;
  let s = raw
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\r/g, '')
    .replace(/\\(['"`\\])/g, '$1');
  if (s.length > max) s = s.slice(0, max);
  return s;
}

/**
 * Pull the value of a `key: "..."` / `key = "..."` / `key="..."` string field out
 * of a bounded window of source. Handles ', " and ` quoting. Returns the FIRST
 * match only — windows are small and scoped to a single registration.
 */
function fieldString(window: string, key: string): string | undefined {
  const re = new RegExp(`\\b${key}\\s*[:=]\\s*(?:(?:String\\.raw)?\`([^\`]*)\`|'((?:[^'\\\\]|\\\\.)*)'|"((?:[^"\\\\]|\\\\.)*)")`, 'm');
  const m = re.exec(window);
  if (!m) return undefined;
  return cleanString(m[1] ?? m[2] ?? m[3]);
}

/**
 * Extract top-level property names from an `inputSchema` / `parameters` object in
 * a bounded window. Covers both a JSON-Schema-ish `{ properties: { p: {...} } }`
 * and the SDK's Zod raw-shape `{ p: z.string(), q: z.number() }`. Only the NAMES
 * are recovered (that is all the param-name detectors need); values are ignored to
 * stay dialect-agnostic and side-effect-free.
 */
function schemaParamNames(window: string, key: string): string[] | undefined {
  const at = window.search(new RegExp(`\\b${key}\\s*[:=]\\s*(?:z\\.object\\(\\s*)?\\{`));
  if (at < 0) return undefined;
  // Take a balanced-ish brace slice starting at the first '{' after the key.
  const braceStart = window.indexOf('{', at);
  if (braceStart < 0) return undefined;
  let depth = 0;
  let end = braceStart;
  for (let i = braceStart; i < window.length && i < braceStart + 4000; i++) {
    const c = window[i];
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  let body = window.slice(braceStart + 1, end);
  // Descend into a nested `properties: { ... }` when present (JSON-Schema shape).
  const propsAt = body.search(/\bproperties\s*:\s*\{/);
  if (propsAt >= 0) {
    const ps = body.indexOf('{', propsAt);
    let d = 0, e = ps;
    for (let i = ps; i < body.length; i++) {
      const c = body[i];
      if (c === '{') d++;
      else if (c === '}') { d--; if (d === 0) { e = i; break; } }
    }
    body = body.slice(ps + 1, e);
  }
  const names = new Set<string>();
  // Top-level keys only: `name:` / `"name":` / `'name':` at brace depth 0 of body.
  let d = 0;
  const keyRe = /(?:^|[,{])\s*(?:(["'])([A-Za-z_$][\w$-]{0,63})\1|([A-Za-z_$][\w$]{0,63}))\s*:/g;
  // Track depth so we only take depth-0 keys.
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '{' || c === '(' || c === '[') d++;
    else if (c === '}' || c === ')' || c === ']') d--;
  }
  // Depth tracking above is a guard; for the common flat shape we match keys that
  // are immediately preceded by the object open or a comma at the outer level.
  let m: RegExpExecArray | null;
  while ((m = keyRe.exec(body)) && names.size < 64) {
    const nm = m[2] ?? m[3];
    if (nm && nm !== 'type' && nm !== 'properties' && nm !== 'required' && nm !== 'description') names.add(nm);
  }
  return names.size ? [...names] : undefined;
}

function schemaFromParamNames(names: string[] | undefined): JsonSchema | undefined {
  if (!names || !names.length) return undefined;
  const properties: Record<string, JsonSchema> = {};
  for (const n of names) properties[n] = {};
  return { type: 'object', properties };
}

/** A window of source starting at `from`, ending at the next registration or a cap. */
function windowFrom(src: string, from: number, nextIdx: number): string {
  const hardEnd = Math.min(src.length, from + 3000);
  const end = nextIdx > from ? Math.min(nextIdx, hardEnd) : hardEnd;
  return src.slice(from, end);
}

// --- JS/TS matchers --------------------------------------------------------

// `.registerTool("name", {...})` and `server.tool("name", ...)` — the two shapes
// the TS SDK exposes. Capture the name; the window after it yields desc + schema.
const RE_REGISTER_TOOL = /\.(registerTool|tool)\s*\(\s*(['"`])([^'"`]{1,128})\2/g;
// `name: "x"` paired with a nearby `description:` inside a ListTools handler array.
const RE_TOOL_OBJECT = /\bname\s*:\s*(['"`])([^'"`]{1,128})\1/g;

// `registerTool(nameIdent, configIdent, …)` — the well-factored TS shape where a
// module hoists `const name = "x"` and `const config = { description, inputSchema }`
// then registers them (e.g. @modelcontextprotocol/server-everything). Both consts
// are resolved IN THE SAME FILE. Bias to miss: emit only when the name const
// resolves to a plain string literal AND the config const resolves to something
// tool-config-shaped — an unrelated `.tool(a, b)` is not invented into a tool.
const RE_REGISTER_IDENT = /\.(?:registerTool|tool)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)/g;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const constStringMemo = new WeakMap<object, Map<string, string | undefined>>();
const constBodyMemo = new WeakMap<object, Map<string, string | undefined>>();
let memoKey: object = {};

function memo<T>(store: WeakMap<object, Map<string, T>>, ident: string, compute: () => T): T {
  let m = store.get(memoKey);
  if (!m) store.set(memoKey, (m = new Map()));
  if (m.has(ident)) return m.get(ident)!;
  const v = compute();
  m.set(ident, v);
  return v;
}

/** Resolve `const <ident> = "literal"` (', " or `) in the source, else undefined. Memoised per file. */
function resolveConstString(src: string, ident: string): string | undefined {
  return memo(constStringMemo, ident, () => resolveConstStringUncached(src, ident));
}

function resolveConstStringUncached(src: string, ident: string): string | undefined {
  const re = new RegExp(
    `\\b(?:const|let|var)\\s+${escapeRegExp(ident)}\\s*=\\s*(?:\`([^\`]*)\`|'((?:[^'\\\\]|\\\\.)*)'|"((?:[^"\\\\]|\\\\.)*)")`,
  );
  const m = re.exec(src);
  return m ? cleanString(m[1] ?? m[2] ?? m[3]) : undefined;
}

/** Resolve `const <ident> = { … }` and return its brace-balanced object body. Memoised per file. */
function resolveConstObjectBody(src: string, ident: string): string | undefined {
  return memo(constBodyMemo, ident, () => resolveConstObjectBodyUncached(src, ident));
}

function resolveConstObjectBodyUncached(src: string, ident: string): string | undefined {
  const decl = new RegExp(`\\b(?:const|let|var)\\s+${escapeRegExp(ident)}\\s*=\\s*\\{`).exec(src);
  if (!decl) return undefined;
  const braceStart = src.indexOf('{', decl.index);
  if (braceStart < 0) return undefined;
  let depth = 0;
  for (let i = braceStart; i < src.length && i < braceStart + 8000; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return src.slice(braceStart + 1, i);
    }
  }
  return undefined;
}

function extractJsTools(src: string): ToolDef[] {
  memoKey = {};
  const out: ToolDef[] = [];
  const seen = new Set<string>();

  // Collect registration offsets first so each window ends at the next one.
  const regs: { idx: number; end: number; name: string; kind: string }[] = [];
  let m: RegExpExecArray | null;
  RE_REGISTER_TOOL.lastIndex = 0;
  while ((m = RE_REGISTER_TOOL.exec(src))) {
    if (!m[1] || !m[3]) continue;
    regs.push({ idx: m.index, end: RE_REGISTER_TOOL.lastIndex, name: m[3], kind: m[1] });
  }

  const hasListToolsHandler = /ListToolsRequestSchema|setRequestHandler\s*\(\s*['"`]?tools\/list/.test(src);

  for (let i = 0; i < regs.length; i++) {
    const reg = regs[i]!;
    if (!looksLikeToolName(reg.name) || seen.has(reg.name)) continue;
    const next = regs[i + 1]?.idx ?? -1;
    const win = windowFrom(src, reg.end, next);
    // For `.tool(name, "description", ...)` the description may be the 2nd
    // positional arg; for `.registerTool(name, { description })` it is a field.
    const positional = /^\s*,\s*(?:(['"`])((?:[^'"`\\]|\\.)*)\1)/.exec(win);
    const description = fieldString(win, 'description') ?? cleanString(positional?.[2]);
    const params = schemaParamNames(win, 'inputSchema') ?? schemaParamNames(win, 'parameters');
    const tool: ToolDef = { name: reg.name };
    if (description) tool.description = description;
    const schema = schemaFromParamNames(params);
    if (schema) tool.inputSchema = schema;
    seen.add(reg.name);
    out.push(tool);
    if (out.length >= MAX_TOOLS) return out;
  }

  // Const-resolved registrations: registerTool(nameIdent, configIdent, …).
  RE_REGISTER_IDENT.lastIndex = 0;
  while ((m = RE_REGISTER_IDENT.exec(src))) {
    if (out.length >= MAX_TOOLS) return out;
    const nameId = m[1];
    const configId = m[2];
    if (!nameId || !configId) continue;
    const name = resolveConstString(src, nameId);
    if (!name || !looksLikeToolName(name) || seen.has(name)) continue;
    const body = resolveConstObjectBody(src, configId);
    // Require a tool-config shape before trusting this as a real registration —
    // guards against an unrelated `.tool(a, b)` whose args happen to resolve.
    if (!body || !/\b(?:description|inputSchema|title|annotations)\s*:/.test(body)) continue;
    const description = fieldString(body, 'description') ?? fieldString(body, 'title');
    const params = schemaParamNames(body, 'inputSchema') ?? schemaParamNames(body, 'parameters');
    const tool: ToolDef = { name };
    if (description) tool.description = description;
    const schema = schemaFromParamNames(params);
    if (schema) tool.inputSchema = schema;
    seen.add(name);
    out.push(tool);
  }

  // ListTools handler style: objects with `name:` + `description:` in a returned
  // array. Only mine this when the file actually wires a tools/list handler, so we
  // do not scrape unrelated `{ name: ... }` object literals.
  if (hasListToolsHandler) {
    RE_TOOL_OBJECT.lastIndex = 0;
    const objs: { idx: number; end: number; name: string }[] = [];
    while ((m = RE_TOOL_OBJECT.exec(src))) { if (m[2]) objs.push({ idx: m.index, end: RE_TOOL_OBJECT.lastIndex, name: m[2] }); }
    for (let i = 0; i < objs.length; i++) {
      const o = objs[i]!;
      if (!looksLikeToolName(o.name) || seen.has(o.name)) continue;
      const next = objs[i + 1]?.idx ?? -1;
      const win = windowFrom(src, o.end, next);
      const description = fieldString(win, 'description');
      // Require a description here: a bare `name:` object in a list handler with no
      // description is too weak a signal to attribute as a real tool.
      if (!description) continue;
      // An MCP tool object carries an inputSchema (the protocol requires one). A
      // prompt, a resource, a prompt's argument or a CLI option does not — in a
      // file that also lists prompts, they filled the tool cap and pushed the
      // real tools out. Only the text up to the next `name:` is read, so a `uri`
      // property inside a tool's own schema no longer disqualifies it.
      const upToNext = src.slice(o.end, next > o.end ? Math.min(next, o.end + 12_000) : o.end + 12_000);
      if (!/\b(?:inputSchema|input_schema)\s*:/.test(upToNext)) continue;
      if (/\barguments\s*:\s*\[[^\]]*$/.test(src.slice(Math.max(0, o.idx - 400), o.idx))) continue;
      const params = schemaParamNames(win, 'inputSchema');
      const tool: ToolDef = { name: o.name, description };
      const schema = schemaFromParamNames(params);
      if (schema) tool.inputSchema = schema;
      seen.add(o.name);
      out.push(tool);
      if (out.length >= MAX_TOOLS) return out;
    }
  }

  return out;
}

// --- Python matchers -------------------------------------------------------

// FastMCP: `@mcp.tool()` / `@app.tool(name="x", description="y")` on a `def`.
const RE_PY_DECORATOR = /@(\w+)\.tool\s*(\([^)]*\))?\s*\r?\n\s*(?:async\s+)?def\s+(\w+)\s*\(/g;
// Low-level list_tools: `types.Tool(name="x", description="y", inputSchema={...})`.
const RE_PY_TOOL_CTOR = /\bTool\s*\(\s*name\s*=\s*(['"])([^'"]{1,128})\1/g;

function pyDocstring(src: string, defParenIdx: number): string | undefined {
  // Find the ':' that ends the def signature, then the first triple-quoted string.
  const colon = src.indexOf(':', defParenIdx);
  if (colon < 0) return undefined;
  const after = src.slice(colon, colon + 2000);
  const m = /^[\s\S]{0,80}?("""|''')([\s\S]*?)\1/.exec(after);
  return m ? cleanString((m[2] ?? '').trim()) : undefined;
}

function extractPyTools(src: string): ToolDef[] {
  const out: ToolDef[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;

  RE_PY_DECORATOR.lastIndex = 0;
  while ((m = RE_PY_DECORATOR.exec(src)) && out.length < MAX_TOOLS) {
    const decoratorArgs = m[2] ?? '';
    const fnName = m[3];
    if (!fnName) continue;
    const explicitName = fieldString(decoratorArgs, 'name');
    const name = explicitName ?? fnName;
    if (!looksLikeToolName(name) || seen.has(name)) continue;
    const description = fieldString(decoratorArgs, 'description') ?? pyDocstring(src, RE_PY_DECORATOR.lastIndex);
    const tool: ToolDef = { name };
    if (description) tool.description = description;
    seen.add(name);
    out.push(tool);
  }

  RE_PY_TOOL_CTOR.lastIndex = 0;
  while ((m = RE_PY_TOOL_CTOR.exec(src)) && out.length < MAX_TOOLS) {
    const name = m[2];
    if (!name || !looksLikeToolName(name) || seen.has(name)) continue;
    const win = windowFrom(src, RE_PY_TOOL_CTOR.lastIndex, -1);
    const description = fieldString(win, 'description');
    const params = schemaParamNames(win, 'inputSchema');
    const tool: ToolDef = { name };
    if (description) tool.description = description;
    const schema = schemaFromParamNames(params);
    if (schema) tool.inputSchema = schema;
    seen.add(name);
    out.push(tool);
  }

  return out;
}

/**
 * Extract a best-effort tool surface from a package's source files.
 *
 * Deterministic and side-effect-free. Returns `extracted:false` (an empty surface)
 * whenever nothing could be recovered with confidence — the caller then leaves the
 * scan exactly as it was, so this can only ADD coverage, never remove it.
 */
export function extractToolsFromSource(files: SourceFile[] | undefined): ToolExtractionResult {
  // A null-prototype record: a tool named `__proto__` is an own key like any other.
  const empty: ToolExtractionResult = { tools: [], extracted: false, fromFiles: [], origins: Object.create(null), truncated: [] };
  if (!Array.isArray(files) || !files.length) return empty;

  const byName = new Map<string, ToolDef>();
  const origins: Record<string, StaticToolOrigin> = Object.create(null);
  const fromFiles: string[] = [];
  const truncated: string[] = [];

  for (const f of files) {
    if (!f || typeof f.path !== 'string' || typeof f.content !== 'string') continue;
    if (SKIP_EXT.test(f.path) || !CODE_EXT.test(f.path) || SKIP_PATH.test(f.path)) continue;
    if (f.content.length > MAX_FILE_BYTES) continue;

    const isPy = /\.py$/i.test(f.path);
    const found = isPy ? extractPyTools(f.content) : extractJsTools(f.content);
    const local = new Map<string, { tool: ToolDef; origin: StaticToolOrigin }>();
    for (const t of found) local.set(t.name, { tool: t, origin: { file: f.path, line: lineOf(f.content, t.name), via: 'direct', hintSource: 'none' } });
    // Registrations read the way the language runs them: helpers, loops, nested
    // decorators — and, for every tool including the literal ones above, its
    // annotations, the condition it sits behind and what its handler does. The
    // name/description/schema the line matcher found are kept as they were.
    // A reader failure on one file must never cost the scan its tools: that file
    // keeps what the line matcher found, as in 1.15.
    let read: ReturnType<typeof readRegistrationsWithStats>['regs'] = [];
    try {
      const got = readRegistrationsWithStats(f);
      read = got.regs;
      if (got.truncated) truncated.push(f.path);
    } catch {
      read = [];
    }
    for (const reg of read) {
      if (!looksLikeToolName(reg.name)) continue;
      // `@mcp.tool("delete_records") def _impl(…)` is the tool delete_records: the
      // line matcher's tool named after the def is not a second tool.
      if (reg.defName && reg.defName !== reg.name && local.get(reg.defName)?.origin.hintSource === 'none' && !read.some((x) => x.name === reg.defName)) {
        local.delete(reg.defName);
      }
      const hit = local.get(reg.name);
      const tool: ToolDef = hit ? hit.tool : { name: reg.name };
      // The evaluated description is the one the server sends; the line matcher
      // stops at the first literal (`'Sync notes. ' + NOTE` read as 'Sync notes. ').
      // When the two differ — a second registration of the name — both are kept,
      // so the injection detectors read every text the tool may present.
      if (hit && reg.description !== undefined) {
        const d = cleanString(reg.description, MAX_MERGED_DESC);
        const merged = mergeDescriptions(tool.description, d);
        if (merged) tool.description = merged;
      }
      if (!hit) {
        const description =
          reg.description !== undefined ? cleanString(reg.description, MAX_MERGED_DESC) : reg.defAt !== undefined ? pyDocstring(f.content, reg.defAt) : undefined;
        if (description) tool.description = description;
        if (reg.title) tool.title = reg.title;
        const schema = schemaFromParamNames(reg.params);
        if (schema) tool.inputSchema = schema;
      }
      if (reg.hints) tool.annotations = { ...(tool.annotations ?? {}), ...(mergeHints(hintsOf(tool), reg.hints) ?? {}) };
      local.set(reg.name, {
        tool,
        origin: {
          file: f.path,
          line: reg.line,
          via: reg.via,
          ...(reg.helpers ? { helpers: reg.helpers } : {}),
          hintSource: reg.hintSource,
          ...(reg.condition ? { condition: reg.condition } : {}),
          ...(reg.behavior ? { behavior: reg.behavior } : {}),
        },
      });
    }
    if (!local.size) continue;

    let contributed = false;
    for (const { tool: t, origin } of local.values()) {
      if (byName.has(t.name)) {
        // The same name in two files (a legacy copy, a variant): keep the richer
        // description and schema, but merge hints toward a write and unite the
        // handler evidence — a read-only decoy must not hide the real writer.
        const prev = byName.get(t.name)!;
        const prevOrigin = origins[t.name];
        const score = (x: ToolDef): number => (x.description ? 1 : 0) + (x.inputSchema ? 1 : 0);
        const keep = score(t) > score(prev) ? { ...t } : { ...prev };
        const description = mergeDescriptions(prev.description, t.description);
        if (description) keep.description = description;
        const hints = mergeHints(hintsOf(prev), hintsOf(t));
        if (hints) keep.annotations = { ...(keep.annotations ?? {}), ...hints };
        const behavior = [...(prevOrigin?.behavior ?? []), ...(origin.behavior ?? [])].filter((b, i, all) => all.findIndex((x) => x.why === b.why) === i);
        const base = score(t) > score(prev) ? origin : (prevOrigin ?? origin);
        const merged: StaticToolOrigin = { ...base, ...(behavior.length ? { behavior: behavior.slice(0, 3) } : {}) };
        // Registered unconditionally in either file: not conditional.
        if (!(prevOrigin?.condition && origin.condition)) delete merged.condition;
        byName.set(t.name, keep);
        origins[t.name] = merged;
        continue;
      }
      if (byName.size >= MAX_TOOLS) {
        // A package with more tools than the scanner keeps says so in the report.
        if (!truncated.includes(f.path)) truncated.push(f.path);
        break;
      }
      byName.set(t.name, t);
      origins[t.name] = origin;
      contributed = true;
    }
    if (contributed) fromFiles.push(f.path);
  }

  const tools = [...byName.values()];
  if (!tools.length) return { ...empty, truncated };
  return { tools, extracted: true, fromFiles, origins, truncated };
}

/** The boolean hints a tool definition carries. */
function hintsOf(t: ToolDef): Parameters<typeof mergeHints>[0] {
  const a = t.annotations;
  if (!a) return undefined;
  const out: NonNullable<Parameters<typeof mergeHints>[0]> = {};
  for (const k of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const) if (typeof a[k] === 'boolean') out[k] = a[k] as boolean;
  return Object.keys(out).length ? out : undefined;
}

/** 1-based line of the first quoted occurrence of a tool name, for the origin record. */
function lineOf(src: string, name: string): number {
  let i = -1;
  for (const q of ['"', "'", '`']) {
    const j = src.indexOf(q + name + q);
    if (j >= 0 && (i < 0 || j < i)) i = j;
  }
  if (i < 0) return 0;
  let n = 1;
  for (let k = 0; k < i; k++) if (src.charCodeAt(k) === 10) n++;
  return n;
}
