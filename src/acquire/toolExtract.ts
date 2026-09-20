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

import type { SourceFile, ToolDef, JsonSchema } from '../types.js';

export interface ToolExtractionResult {
  tools: ToolDef[];
  /** True when at least one tool was recovered (⟺ the surface may be marked static). */
  extracted: boolean;
  /** Files that contributed ≥1 tool — for the coverage caveat / debugging. */
  fromFiles: string[];
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
function cleanString(raw: string | undefined): string | undefined {
  if (typeof raw !== 'string') return undefined;
  let s = raw
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\r/g, '')
    .replace(/\\(['"`\\])/g, '$1');
  if (s.length > MAX_DESC_LEN) s = s.slice(0, MAX_DESC_LEN);
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

/** Resolve `const <ident> = "literal"` (', " or `) in the source, else undefined. */
function resolveConstString(src: string, ident: string): string | undefined {
  const re = new RegExp(
    `\\b(?:const|let|var)\\s+${escapeRegExp(ident)}\\s*=\\s*(?:\`([^\`]*)\`|'((?:[^'\\\\]|\\\\.)*)'|"((?:[^"\\\\]|\\\\.)*)")`,
  );
  const m = re.exec(src);
  return m ? cleanString(m[1] ?? m[2] ?? m[3]) : undefined;
}

/** Resolve `const <ident> = { … }` and return its brace-balanced object body. */
function resolveConstObjectBody(src: string, ident: string): string | undefined {
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
  const empty: ToolExtractionResult = { tools: [], extracted: false, fromFiles: [] };
  if (!Array.isArray(files) || !files.length) return empty;

  const byName = new Map<string, ToolDef>();
  const fromFiles: string[] = [];

  for (const f of files) {
    if (!f || typeof f.path !== 'string' || typeof f.content !== 'string') continue;
    if (SKIP_EXT.test(f.path) || !CODE_EXT.test(f.path) || SKIP_PATH.test(f.path)) continue;
    if (f.content.length > MAX_FILE_BYTES) continue;

    const isPy = /\.py$/i.test(f.path);
    const found = isPy ? extractPyTools(f.content) : extractJsTools(f.content);
    if (!found.length) continue;

    let contributed = false;
    for (const t of found) {
      if (byName.has(t.name)) {
        // Prefer the richer definition (one with a description / schema).
        const prev = byName.get(t.name)!;
        const prevScore = (prev.description ? 1 : 0) + (prev.inputSchema ? 1 : 0);
        const curScore = (t.description ? 1 : 0) + (t.inputSchema ? 1 : 0);
        if (curScore > prevScore) byName.set(t.name, t);
        continue;
      }
      if (byName.size >= MAX_TOOLS) break;
      byName.set(t.name, t);
      contributed = true;
    }
    if (contributed) fromFiles.push(f.path);
  }

  const tools = [...byName.values()];
  if (!tools.length) return empty;
  return { tools, extracted: true, fromFiles };
}
