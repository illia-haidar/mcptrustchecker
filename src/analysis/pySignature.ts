/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * What FastMCP makes of a Python function it registers as a tool, read from the
 * source instead of the running object:
 *
 *   - the docstring, cleaned the way `inspect.cleandoc` cleans it — the tool's
 *     description when the registration gives none;
 *   - the input schema FastMCP builds from the signature: one property per
 *     parameter, JSON types from the annotations (`str`, `int`, `list[str]`,
 *     `Optional[…]` / `X | None`, `Literal[…]` as an enum, `Annotated[T, Field(…)]`
 *     and `= Field(…)` with their description and bounds), defaults, and the
 *     parameters that have none as `required`. `self`, `cls`, `*args`,
 *     `**kwargs` and the `Context` parameter FastMCP injects are not inputs.
 *
 * Only what the text says with certainty: a model class, an enum or any other
 * type the scanner cannot see is an empty schema (`{}`), never a guess; a value
 * the caller cannot fold leaves its keyword out. Bounded for hostile files: a
 * fixed number of parameters, nesting depth and type nodes per signature.
 */

import type { JsonSchema } from '../types.js';
import { COMMENT, STRING } from '../util/jsLex.js';
import { type FileCtx, type FnInfo } from '../util/fileCtx.js';
import { decodeEscapes } from '../util/constFold.js';

/** A docstring is read up to this many characters (the line matcher's description cap). */
export const MAX_DOC = 8192;
const MAX_PARAMS = 64;
const MAX_TYPE_DEPTH = 8;
const MAX_TYPE_NODES = 400;

/**
 * The constant value of an expression range in the function's file, or
 * undefined when it cannot be folded. `text` admits a string with unreadable
 * pieces left out (a description), never a value that names or constrains.
 */
export type PyValue = (from: number, to: number, text?: boolean) => string | number | boolean | null | undefined;

/** `inspect.cleandoc`: tabs expanded, the common indentation of the lines after the first removed, blank edges dropped. */
export function cleandoc(doc: string): string {
  const lines = doc.split('\n').map((l) => {
    if (!l.includes('\t')) return l;
    let out = '';
    for (const ch of l) out += ch === '\t' ? ' '.repeat(8 - (out.length % 8)) : ch;
    return out;
  });
  let margin = Infinity;
  for (const l of lines.slice(1)) {
    const content = l.trimStart().length;
    if (content) margin = Math.min(margin, l.length - content);
  }
  lines[0] = lines[0]!.trimStart();
  if (margin < Infinity) for (let i = 1; i < lines.length; i++) lines[i] = lines[i]!.slice(margin);
  while (lines.length && !lines[lines.length - 1]) lines.pop();
  while (lines.length && !lines[0]) lines.shift();
  return lines.join('\n');
}

/** The `(` of a `def`'s parameter list, its partner, and the `:` that ends the header. */
function header(ctx: FileCtx, fn: FnInfo): { open: number; close: number; colon: number } | undefined {
  const { src } = ctx;
  const open = src.indexOf('(', fn.headerStart);
  if (open < 0 || open - fn.headerStart > 200 || !ctx.isCode(open)) return undefined;
  const close = ctx.closeOf(open);
  if (close < 0) return undefined;
  // `-> Annotated[CallToolResult, Out]:` — brackets in the return annotation are jumped over.
  for (let i = close + 1, n = 0; i < src.length && n < 4000; i++, n++) {
    if (!ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = ctx.closeOf(i);
      if (e < 0) return undefined;
      n += e - i;
      i = e;
      continue;
    }
    if (c === ':') return { open, close, colon: i };
  }
  return undefined;
}

/** The function whose `def` header holds offset `at` (its name or its `(`). */
export function pyDefAt(ctx: FileCtx, at: number): FnInfo | undefined {
  return ctx.functions().find((f) => f.headerStart <= at && at - f.headerStart < 200 && f.bodyStart > at);
}

/** One string token starting at `at` (prefix and quotes included): its decoded text, or undefined. */
function stringToken(ctx: FileCtx, at: number): { text: string; end: number; prefix: string } | undefined {
  const { src, mask } = ctx;
  if (mask[at] !== STRING) return undefined;
  let end = at;
  while (end < src.length && mask[end] === STRING) end++;
  const tok = src.slice(at, end);
  const m = /^([rRbBuUfF]{0,2})("""|'''|"|')/.exec(tok);
  if (!m) return undefined;
  const q = m[2]!;
  if (tok.length < m[0].length + q.length || !tok.endsWith(q)) return undefined;
  const body = tok.slice(m[0].length, tok.length - q.length);
  return { text: /[rR]/.test(m[1]!) ? body : decodeEscapes(body, true), end, prefix: m[1]!.toLowerCase() };
}

/** Skip whitespace, line continuations and comments from `i`. */
function skipBlank(ctx: FileCtx, i: number, newlines: boolean): number {
  const { src, mask } = ctx;
  while (i < src.length) {
    const c = src[i]!;
    if (c === ' ' || c === '\t' || c === '\r' || (newlines && c === '\n')) i++;
    else if (c === '\\' && src[i + 1] === '\n') i += 2;
    else if (mask[i] === COMMENT) i++;
    else break;
  }
  return i;
}

/**
 * The function's docstring — the string literal that is its first statement —
 * cleaned like `inspect.cleandoc`. An f-string or a bytes literal is not a
 * docstring (Python leaves `__doc__` empty), nor is a string that is only the
 * start of an expression (`"""…""".strip()`).
 */
export function pyDocstring(ctx: FileCtx, fn: FnInfo): string | undefined {
  if (docMemo.has(fn)) return docMemo.get(fn) ?? undefined;
  const doc = docstringOf(ctx, fn);
  docMemo.set(fn, doc ?? null);
  return doc;
}

const docMemo = new WeakMap<FnInfo, string | null>();

function docstringOf(ctx: FileCtx, fn: FnInfo): string | undefined {
  const h = header(ctx, fn);
  if (!h) return undefined;
  const at = skipBlank(ctx, h.colon + 1, true);
  const tok = stringToken(ctx, at);
  if (!tok || /[fb]/.test(tok.prefix)) return undefined;
  const after = skipBlank(ctx, tok.end, false);
  if (after < ctx.src.length && ctx.src[after] !== '\n' && ctx.src[after] !== ';') return undefined;
  // A docstring far longer than the description cap is cleaned on its head only.
  const doc = cleandoc(tok.text.slice(0, 4 * MAX_DOC));
  return doc ? doc.slice(0, MAX_DOC) : undefined;
}

// --- the signature -----------------------------------------------------------------

/** Trim whitespace and comments off both ends of a range. */
function trimRange(ctx: FileCtx, a: number, b: number): [number, number] {
  const { src, mask } = ctx;
  while (a < b && (/\s/.test(src[a]!) || mask[a] === COMMENT || (src[a] === '\\' && src[a + 1] === '\n'))) a++;
  while (b > a && (/\s/.test(src[b - 1]!) || mask[b - 1] === COMMENT || src[b - 1] === '\\')) b--;
  return [a, b];
}

/** Split a range at top-level `sep` characters (code only, bracket groups jumped over). */
function splitTop(ctx: FileCtx, a: number, b: number, sep: string): [number, number][] | undefined {
  const { src } = ctx;
  const out: [number, number][] = [];
  let start = a;
  for (let i = a; i < b; i++) {
    if (!ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = ctx.closeOf(i);
      if (e < 0 || e >= b) return undefined;
      i = e;
      continue;
    }
    if (c === sep) {
      out.push(trimRange(ctx, start, i));
      start = i + 1;
    }
  }
  out.push(trimRange(ctx, start, b));
  return out.filter(([x, y]) => y > x);
}

/** The top-level `=` of a range that starts a default (`x: int = 3`), not `==`, `<=`, `!=`, `:=`. */
function defaultEq(ctx: FileCtx, a: number, b: number): number {
  const { src } = ctx;
  for (let i = a; i < b; i++) {
    if (!ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = ctx.closeOf(i);
      if (e < 0 || e >= b) return -1;
      i = e;
      continue;
    }
    if (c === '=' && src[i + 1] !== '=' && !/[=!<>:]/.test(src[i - 1] ?? '')) return i;
  }
  return -1;
}

interface PyParam {
  name: string;
  ann?: [number, number];
  dflt?: [number, number];
  star: 0 | 1 | 2;
}

/** The parameters of a `def`, with the ranges of their annotations and defaults. */
function pyParams(ctx: FileCtx, fn: FnInfo): PyParam[] | undefined {
  const h = header(ctx, fn);
  if (!h) return undefined;
  const parts = splitTop(ctx, h.open + 1, h.close, ',');
  if (!parts) return undefined;
  const out: PyParam[] = [];
  for (const [a, b] of parts) {
    const t = ctx.src.slice(a, Math.min(b, a + 200));
    const m = /^(\*{0,2})\s*([A-Za-z_]\w*)/.exec(t);
    if (!m) continue; // `/` and a bare `*` are markers, not parameters
    const star = m[1]!.length as 0 | 1 | 2;
    const after = a + m[0].length;
    const eq = defaultEq(ctx, after, b);
    const annEnd = eq >= 0 ? eq : b;
    const colon = skipBlank(ctx, after, true);
    const p: PyParam = { name: m[2]!, star };
    if (ctx.src[colon] === ':' && colon < annEnd) p.ann = trimRange(ctx, colon + 1, annEnd);
    if (eq >= 0) p.dflt = trimRange(ctx, eq + 1, b);
    out.push(p);
    if (out.length > MAX_PARAMS) return undefined;
  }
  return out;
}

const SIMPLE: Record<string, JsonSchema> = {
  str: { type: 'string' },
  int: { type: 'integer' },
  float: { type: 'number' },
  bool: { type: 'boolean' },
  bytes: { type: 'string', format: 'binary' },
  None: { type: 'null' },
  NoneType: { type: 'null' },
  Any: {},
  object: {},
  datetime: { type: 'string', format: 'date-time' },
  date: { type: 'string', format: 'date' },
  time: { type: 'string', format: 'time' },
  UUID: { type: 'string', format: 'uuid' },
};
const ARRAYS = new Set(['list', 'List', 'Sequence', 'MutableSequence', 'Iterable', 'Collection', 'tuple', 'Tuple', 'set', 'Set', 'frozenset', 'FrozenSet', 'AbstractSet']);
const OBJECTS = new Set(['dict', 'Dict', 'Mapping', 'MutableMapping']);

/** Field(...) keywords FastMCP (through pydantic) turns into schema keywords. */
const FIELD_BOUNDS: Record<string, string> = { ge: 'minimum', gt: 'exclusiveMinimum', le: 'maximum', lt: 'exclusiveMaximum', multiple_of: 'multipleOf', pattern: 'pattern' };

class SchemaReader {
  private nodes = 0;
  constructor(
    private readonly ctx: FileCtx,
    private readonly value: PyValue,
  ) {}

  private text(a: number, b: number): string {
    return this.ctx.src.slice(a, b);
  }

  /** The schema of a type expression; `{}` for anything that is not certain. */
  type(a0: number, b0: number, depth: number): JsonSchema {
    if (depth > MAX_TYPE_DEPTH || ++this.nodes > MAX_TYPE_NODES) return {};
    const [a, b] = trimRange(this.ctx, a0, b0);
    if (a >= b) return {};
    const { src, mask } = this.ctx;
    const union = splitTop(this.ctx, a, b, '|');
    if (!union) return {};
    if (union.length > 1) return anyOf(union.map(([x, y]) => this.type(x, y, depth + 1)));
    // A forward reference: `"str"`, `'Item'` — read only when it is a plain name.
    if (mask[a] === STRING) {
      const v = this.value(a, b);
      return typeof v === 'string' && /^[A-Za-z_][\w.]*$/.test(v.trim()) ? this.named(v.trim(), depth) : {};
    }
    if (src[a] === '(' && this.ctx.closeOf(a) === b - 1) return this.type(a + 1, b - 1, depth + 1);
    const head = /^[A-Za-z_][\w.]*/.exec(this.text(a, Math.min(b, a + 200)));
    if (!head) return {};
    let i = a + head[0].length;
    while (i < b && /\s/.test(src[i]!)) i++;
    if (i === b) return this.named(head[0], depth);
    if (src[i] !== '[' || this.ctx.closeOf(i) !== b - 1) return {};
    const args = splitTop(this.ctx, i + 1, b - 1, ',');
    if (!args) return {};
    return this.generic(head[0].split('.').pop()!, args, depth);
  }

  /** A bare name: a builtin type, or a type alias the module defines (`Sort = Annotated[…]`). */
  private named(name: string, depth: number): JsonSchema {
    const last = name.split('.').pop()!;
    if (Object.hasOwn(SIMPLE, last)) return { ...SIMPLE[last]! };
    if (ARRAYS.has(last)) return last === 'set' || last === 'Set' || last === 'frozenset' || last === 'FrozenSet' ? { type: 'array', uniqueItems: true } : { type: 'array' };
    if (OBJECTS.has(last)) return { type: 'object' };
    if (name.includes('.')) return {};
    // A module-level alias, declared once. (`constInitAt` would refuse it: every
    // `x: Alias = default` in a signature reads to it like another binding.)
    const decls = this.ctx.declsOf(name).filter((d) => !d.scope);
    const decl = decls.length === 1 ? decls[0]! : undefined;
    if (!decl || !/^(?:typing\.|t\.)?(?:Annotated|Literal|Optional|Union|List|Dict|list|dict|tuple|Tuple|set|Set|Sequence)\b|^\w+\s*\|/.test(decl.init)) return {};
    const start = this.ctx.src.indexOf(decl.init, decl.at);
    if (start < 0) return {};
    let end = start + decl.init.length;
    const br = this.ctx.src.indexOf('[', start);
    if (br >= 0 && br < end) {
      const c = this.ctx.closeOf(br);
      if (c > 0) end = Math.max(end, c + 1);
    }
    return this.type(start, end, depth + 1);
  }

  private generic(base: string, args: [number, number][], depth: number): JsonSchema {
    const d = depth + 1;
    if (base === 'Optional' && args.length === 1) return anyOf([this.type(args[0]![0], args[0]![1], d), { type: 'null' }]);
    if (base === 'Union') return anyOf(args.map(([x, y]) => this.type(x, y, d)));
    if (base === 'Literal') {
      const vals = args.map(([x, y]) => this.value(x, y));
      if (!vals.length || vals.some((v) => v === undefined)) return {};
      const kinds = new Set(vals.map((v) => (v === null ? 'null' : typeof v === 'number' ? (Number.isInteger(v) ? 'integer' : 'number') : typeof v)));
      const out: JsonSchema = vals.length === 1 ? { const: vals[0] } : { enum: vals };
      if (kinds.size === 1) out.type = [...kinds][0]!;
      return out;
    }
    if (base === 'Annotated' && args.length >= 1) {
      let s = this.type(args[0]![0], args[0]![1], d);
      for (const [x, y] of args.slice(1)) s = this.field(x, y, s).schema;
      return s;
    }
    if (ARRAYS.has(base)) {
      const out: JsonSchema = { type: 'array' };
      if (base === 'set' || base === 'Set' || base === 'frozenset' || base === 'FrozenSet' || base === 'AbstractSet') out.uniqueItems = true;
      // `tuple[str, ...]` is a list of str; a fixed tuple's per-position types are left out.
      const tupleOfOne = (base === 'tuple' || base === 'Tuple') && args.length === 2 && this.text(args[1]![0], args[1]![1]) === '...';
      if (args.length === 1 && base !== 'tuple' && base !== 'Tuple') out.items = this.type(args[0]![0], args[0]![1], d);
      else if (tupleOfOne) out.items = this.type(args[0]![0], args[0]![1], d);
      return out;
    }
    if (OBJECTS.has(base)) {
      const out: JsonSchema = { type: 'object' };
      if (args.length === 2) out.additionalProperties = this.type(args[1]![0], args[1]![1], d);
      return out;
    }
    return {};
  }

  /**
   * Apply a `Field(…)` (an `Annotated` argument, or a parameter's default) to a
   * schema: description, title, bounds, and its default. Anything else in the
   * metadata is left alone.
   */
  field(a0: number, b0: number, schema: JsonSchema): { schema: JsonSchema; isField: boolean; hasDefault: boolean; dflt?: unknown } {
    const [a, b] = trimRange(this.ctx, a0, b0);
    const m = /^(?:[A-Za-z_]\w*\.)?Field\s*\(/.exec(this.text(a, Math.min(b, a + 80)));
    if (!m || this.ctx.closeOf(a + m[0].length - 1) !== b - 1) return { schema, isField: false, hasDefault: false };
    const args = splitTop(this.ctx, a + m[0].length, b - 1, ',') ?? [];
    const out: JsonSchema = { ...schema };
    let hasDefault = false;
    let dflt: unknown;
    let pos = 0;
    // A bound on an `Optional[T]` applies to T, as pydantic writes it.
    const inner = (): JsonSchema => {
      const branches = out.anyOf as JsonSchema[] | undefined;
      return Array.isArray(branches) ? (branches.find((x) => x.type !== 'null') ?? out) : out;
    };
    for (const [x, y] of args) {
      const kw = /^([A-Za-z_]\w*)\s*=(?!=)\s*/.exec(this.text(x, Math.min(y, x + 80)));
      if (!kw) {
        // `Field(..., description=…)` is required; `Field("x", …)` has a default.
        if (pos++ === 0 && this.text(x, y) !== '...') {
          hasDefault = true;
          dflt = this.value(x, y);
        }
        continue;
      }
      const key = kw[1]!;
      const v = this.value(x + kw[0].length, y, key === 'description' || key === 'title');
      if (key === 'default') {
        if (this.text(x + kw[0].length, y).trim() !== '...') {
          hasDefault = true;
          dflt = v;
        }
      } else if (key === 'default_factory') hasDefault = true;
      else if ((key === 'description' || key === 'title') && typeof v === 'string') out[key] = v;
      else if (Object.hasOwn(FIELD_BOUNDS, key) && v !== undefined && v !== null) inner()[FIELD_BOUNDS[key]!] = v;
      else if ((key === 'min_length' || key === 'max_length') && typeof v === 'number') {
        const t = inner();
        const which = key === 'min_length' ? 'min' : 'max';
        t[t.type === 'array' ? `${which}Items` : t.type === 'object' ? `${which}Properties` : `${which}Length`] = v;
      }
    }
    if (hasDefault && dflt !== undefined) out.default = dflt;
    return { schema: out, isField: true, hasDefault, ...(dflt !== undefined ? { dflt } : {}) };
  }
}

function anyOf(list: JsonSchema[]): JsonSchema {
  const flat: JsonSchema[] = [];
  for (const s of list) {
    if (Array.isArray(s.anyOf) && Object.keys(s).length === 1) flat.push(...(s.anyOf as JsonSchema[]));
    else flat.push(s);
  }
  if (flat.length === 1) return flat[0]!;
  // `Any | None` and the like say nothing certain about the value.
  if (flat.some((s) => Object.keys(s).length === 0)) return {};
  return { anyOf: flat };
}

/** Is this annotation FastMCP's injected request context (`Context`, `Context[S, L]`, `fastmcp.Context`)? */
function isContext(ctx: FileCtx, ann: [number, number] | undefined): boolean {
  if (!ann) return false;
  const t = ctx.src.slice(ann[0], Math.min(ann[1], ann[0] + 200)).replace(/^['"]|['"]$/g, '');
  return /^(?:[A-Za-z_]\w*\.)*Context\s*(?:\[|$)/.test(t.trim());
}

/**
 * The input schema FastMCP generates for this function, or undefined when its
 * header cannot be read. `exclude` names parameters the registration hides
 * (`exclude_args=[…]`).
 */
export function pySignatureSchema(ctx: FileCtx, fn: FnInfo, value: PyValue, exclude?: ReadonlySet<string>): JsonSchema | undefined {
  const params = pyParams(ctx, fn);
  if (!params) return undefined;
  const reader = new SchemaReader(ctx, value);
  const properties: Record<string, JsonSchema> = Object.create(null);
  const required: string[] = [];
  params.forEach((p, i) => {
    if (p.star) return;
    if (i === 0 && (p.name === 'self' || p.name === 'cls')) return;
    if (p.name === 'ctx' || isContext(ctx, p.ann) || exclude?.has(p.name)) return;
    let schema = p.ann ? reader.type(p.ann[0], p.ann[1], 0) : {};
    let hasDefault = false;
    if (p.dflt) {
      const f = reader.field(p.dflt[0], p.dflt[1], schema);
      if (f.isField) {
        schema = f.schema;
        hasDefault = f.hasDefault;
      } else {
        hasDefault = true;
        const v = value(p.dflt[0], p.dflt[1]);
        if (v !== undefined) schema = { ...schema, default: v };
      }
    }
    if (p.name === '__proto__') Object.defineProperty(properties, p.name, { value: schema, enumerable: true, writable: true, configurable: true });
    else properties[p.name] = schema;
    if (!hasDefault) required.push(p.name);
  });
  const out: JsonSchema = { type: 'object', properties: { ...properties } };
  if (required.length) out.required = required;
  return out;
}
