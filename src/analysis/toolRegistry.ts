/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Tool registrations read the way the language runs them — for the shapes the
 * line-oriented extractor in `acquire/toolExtract.ts` cannot see:
 *
 *   - a local HELPER that passes its own parameter as the tool name
 *     (`function register(server, name, def, h) { server.registerTool(name, …) }`),
 *     including a helper that calls another helper;
 *   - a LOOP over a table of definitions
 *     (`for (const [name, def] of Object.entries(TOOLS))`, `TOOLS.forEach(t => …)`);
 *   - the low-level `tools/list` handler's tool objects;
 *   - Python decorators with nested calls (`@mcp.tool(annotations=ToolAnnotations(…))`)
 *     and decorator wrappers (`def write_tool(**kw): return mcp.tool(…, **kw)`).
 *
 * For EVERY registration it finds — literal ones included — it reads the tool's
 * annotations, a condition the registration sits behind, and what the handler
 * visibly does (an HTTP or database write). The annotations are evaluated, not
 * grepped: object literals, spreads in source order, `||` / `??` fallbacks,
 * `Object.freeze` / `Object.assign`, same-file constants, helper parameters bound
 * to the arguments of each call. Anything that cannot be read with certainty —
 * an imported constant, a function call, a spread of an unknown object, a value
 * the helper reassigns — is UNKNOWN, and unknown is never replaced by a helper's
 * default: a default stands in only where the call site has no `annotations`
 * key at all.
 *
 * Bias to miss, never to mis-attribute: a helper is recognised only when its
 * parameter is the name argument, the helper's name is bound once and never
 * shadowed, its call sites pass a literal name, the file shows it is an MCP
 * server, and the file is not a minified bundle.
 */

import type { CapabilityTag, JsonSchema, SourceFile } from '../types.js';
import { type FileCtx, type FnInfo, fileCtxOf } from '../util/fileCtx.js';
import { decodeEscapes, fold } from '../util/constFold.js';
import { CODE, COMMENT, STRING, braceDepths, splitArgs } from '../util/jsLex.js';
import { type PyPackage, inClassBody, pyImports } from './pyModules.js';
import { pyDefAt, pyDocstring, pySignatureSchema } from './pySignature.js';

export interface ToolHints {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/**
 * Where a tool's hints came from: its own declaration, a helper's default, a
 * merge of the two, a declaration that exists but cannot be read, or nothing.
 */
export type HintSource = 'declared' | 'default' | 'merged' | 'unreadable' | 'none';

export interface RegistrationCondition {
  /** `if` — inside `if (expr) {…}`; `else` — in its else branch; `unless` — after `if (expr) return`. */
  kind: 'if' | 'else' | 'unless';
  expr: string;
  line: number;
}

export interface HandlerEvidence {
  tag: CapabilityTag;
  why: string;
  line: number;
}

export interface FoundRegistration {
  name: string;
  file: string;
  line: number;
  via: 'direct' | 'helper' | 'loop' | 'decorator' | 'decorator-helper';
  /** Helper chain, outermost first (`via: 'helper'`). */
  helpers?: string[];
  title?: string;
  description?: string;
  params?: string[];
  hints?: ToolHints;
  hintSource: HintSource;
  condition?: RegistrationCondition;
  behavior?: HandlerEvidence[];
  /** URL / host parameters whose destination the handler pins (see `pinnedParams`). */
  pinned?: string[];
  /** Python: offset of the `(` of the `def` the decorator sits on (for the docstring). */
  defAt?: number;
  /** Python: the decorated function's own name, when the tool is registered under another. */
  defName?: string;
  /** Python: the input schema FastMCP builds from the registered function's signature. */
  inputSchema?: JsonSchema;
}

const MAX_REGS = 200;
const MAX_RAW_CALLS = 20_000;
/** Registration evaluations per file (a loop over a table counts once per element). */
const MAX_EVALS = 20_000;
/** Distinct descriptions of one tool name, joined, are scanned up to this length. */
export const MAX_MERGED_DESC = 32_768;
/** Object fields spreads may copy per file, in all. */
const MAX_SPREAD_COPIES = 2_000_000;
const MAX_DEPTH = 24;
/** A constant read from another file of a Python package is at most this many characters of source. */
const MAX_PY_CONST = 64 * 1024;
/** Characters a scope search for one Python name may look at before the name is taken as rebound. */
const MAX_BIND_WORK = 400_000;
/** `add_tool(…)` calls read per Python file; a file with more says so (`truncated`). */
const MAX_PY_ADD_SITES = 400;
/**
 * Loop elements and wrapper callers read per Python file, in all: each may
 * fold a constant at the cost of a pass over the file, and a hostile file
 * lists tens of thousands of them. A file with more says so (`truncated`).
 */
const MAX_PY_EXPANSIONS = 400;
/** Evaluation steps per registration: spreads of spreads must not grow without bound. */
const MAX_STEPS = 20_000;
const MAX_ITEMS = 200;
/** The hint names the SDKs read — exactly these spellings, nothing normalised. */
const HINT_NAMES = new Set<keyof ToolHints>(['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']);
const hintKey = (k: string): keyof ToolHints | undefined => (HINT_NAMES.has(k as keyof ToolHints) ? (k as keyof ToolHints) : undefined);
/** A name a helper or a loop produces: an identifier-like slug, never prose. */
const SLUG = /^[A-Za-z0-9._:-]{1,128}$/;

// --- values -------------------------------------------------------------------

interface Env {
  vars: Map<string, Thunk>;
  /** The function whose parameters `vars` binds (its body is where they are in scope). */
  fn: FnInfo | null;
  parent: Env | null;
}

/**
 * An expression to evaluate lazily — a source range in an environment, or a
 * value already known. `own` marks a value that came from the call site's own
 * arguments (directly or through a constant they name) rather than from a
 * helper's body: it is what tells a declared hint from a helper default.
 */
type Thunk = { from: number; to: number; env: Env | null; own?: boolean } | { val: Val; own?: boolean };

type Val =
  | { k: 'obj'; fields: Map<string, Thunk>; open: boolean }
  | { k: 'arr'; items: Thunk[]; open: boolean }
  /** `partial`: a string with unreadable pieces left out — good enough to read, never to name. */
  | { k: 'lit'; v: boolean | string | number | null; partial?: boolean }
  | { k: 'fn'; fn: FnInfo; env: Env | null }
  /** Python: a function another file of the package defines, imported by name. */
  | { k: 'ext'; name: string; file: SourceFile; fn: FnInfo }
  | { k: 'unknown' };

const UNKNOWN: Val = { k: 'unknown' };
const NULLISH: Val = { k: 'lit', v: null };

// --- the evaluator --------------------------------------------------------------

class Reader {
  readonly ctx: FileCtx;
  readonly src: string;
  readonly py: boolean;
  private readonly fnByName = new Map<string, FnInfo | null>();
  private readonly enclosingMemo = new Map<number, FnInfo | null>();
  private readonly constMemo = new Map<string, Val>();
  private steps = 0;
  private ownSpans: [number, number][] = [];
  /** Values of ranges evaluated with no environment, per (range, ownership): table elements, configs. */
  private readonly rangeMemo = new Map<string, Val>();
  /** Fields copied by spreads in this file: a huge object spread a thousand times must not cost minutes. */
  copied = 0;

  /** Python: the package's other files, for names this file imports from them. */
  readonly pkg: PyPackage | undefined;

  constructor(ctx: FileCtx, pkg?: PyPackage) {
    this.ctx = ctx;
    this.src = ctx.src;
    this.py = ctx.lang === 'py';
    this.pkg = pkg;
  }

  /** Start reading one registration: a fresh step budget, and the call site's own argument ranges. */
  begin(own: [number, number][]): void {
    this.steps = 0;
    this.ownSpans = own;
  }

  private inOwn(at: number): boolean {
    for (const [a, z] of this.ownSpans) if (at >= a && at < z) return true;
    return false;
  }

  /** The one function of this name the file defines, or null when there are none or several. */
  fnNamed(name: string): FnInfo | null {
    if (this.fnByName.has(name)) return this.fnByName.get(name)!;
    const all = this.ctx.functions().filter((f) => f.name === name);
    const one = all.length === 1 ? all[0]! : null;
    this.fnByName.set(name, one);
    return one;
  }

  /** {@link FileCtx.enclosingFn}, memoised. */
  enclosing(i: number): FnInfo | null {
    if (this.enclosingMemo.has(i)) return this.enclosingMemo.get(i)!;
    const f = this.ctx.enclosingFn(i);
    this.enclosingMemo.set(i, f);
    return f;
  }

  text(from: number, to: number): string {
    return this.src.slice(from, to);
  }

  close(i: number): number {
    return this.ctx.closeOf(i);
  }

  /** Trim whitespace, wrapping parentheses and TypeScript-only suffixes off a range. */
  trim(from: number, to: number): [number, number] {
    const s = this.src;
    for (let k = 0; k < 8; k++) {
      while (from < to && /\s/.test(s[from]!)) from++;
      while (to > from && /\s/.test(s[to - 1]!)) to--;
      const tail = /\s+(?:as\s+const|as\s+[\w$.<>[\]| ]{1,80}|satisfies\s+[\w$.<>[\]| ]{1,80})$|!$/.exec(s.slice(Math.max(from, to - 90), to));
      if (tail && !this.py) {
        to -= tail[0].length;
        continue;
      }
      if (s[from] === '(' && this.close(from) === to - 1) {
        from++;
        to--;
        continue;
      }
      break;
    }
    return [from, to];
  }

  /** Split a range at top-level occurrences of `sep` (code only, outside brackets). */
  split(from: number, to: number, sep: string): [number, number][] {
    const s = this.src;
    const out: [number, number][] = [];
    let start = from;
    const word = /^[a-z]+$/.test(sep);
    for (let i = from; i < to; i++) {
      if (!this.ctx.isCode(i)) continue;
      const c = s[i]!;
      if (c === '(' || c === '[' || c === '{') {
        const e = this.close(i);
        if (e < 0 || e >= to) return [[from, to]];
        i = e;
        continue;
      }
      if (s.startsWith(sep, i)) {
        if (word && (/[\w$]/.test(s[i - 1] ?? '') || /[\w$]/.test(s[i + sep.length] ?? ''))) continue;
        if (s[i + sep.length] === '=') continue; // `??=` / `||=` assign
        if (sep === '+' && (s[i + 1] === '+' || s[i - 1] === '+')) continue;
        out.push([start, i]);
        start = i + sep.length;
        i += sep.length - 1;
      }
    }
    out.push([start, to]);
    return out;
  }

  /** The parts of a `{…}` / `[…]` / `(…)` whose opening bracket is at `open`. */
  parts(open: number): [number, number][] | null {
    const a = splitArgs(this.src, this.ctx.mask, open);
    if (a) return a.args.map((t, i) => [a.starts[i]!, a.starts[i]! + t.length] as [number, number]);
    // The bracket scan gives up after 200 KB. A registration whose handler is
    // longer is still one call: padding a handler with two thousand requests
    // must not make the tool, and the sink after them, disappear. Its partner
    // comes from the file's bracket table, and nested groups are jumped over,
    // so splitting costs the call's top level only.
    const close = this.close(open);
    if (close < 0) return null;
    const out: [number, number][] = [];
    let from = open + 1;
    const push = (to: number): void => {
      const [a0, z0] = this.trimWs(from, to);
      if (z0 > a0) out.push([a0, z0]);
    };
    for (let i = open + 1; i < close; i++) {
      if (!this.ctx.isCode(i)) continue;
      const c = this.src[i]!;
      if (c === '(' || c === '[' || c === '{') {
        const e = this.close(i);
        if (e < 0 || e > close) return null;
        i = e;
      } else if (c === ',') {
        push(i);
        from = i + 1;
      }
    }
    push(close);
    return out;
  }

  private trimWs(from: number, to: number): [number, number] {
    while (from < to && /\s/.test(this.src[from]!)) from++;
    while (to > from && /\s/.test(this.src[to - 1]!)) to--;
    return [from, to];
  }

  /** The environment in which a declaration at `at` evaluates: the innermost bound one whose function contains it. */
  envFor(env: Env | null, at: number): Env | null {
    for (let e = env; e; e = e.parent) {
      if (!e.fn || (at >= e.fn.bodyStart && at < e.fn.bodyEnd)) return e;
    }
    return null;
  }

  lookup(env: Env | null, name: string): Thunk | undefined {
    for (let e = env; e; e = e.parent) {
      const t = e.vars.get(name);
      if (t) return t;
    }
    return undefined;
  }

  ev(t: Thunk | undefined, depth = 0): Val {
    if (!t) return UNKNOWN;
    if ('val' in t) return t.val;
    return this.evRange(t.from, t.to, t.env, depth, t.own ?? false);
  }

  /** JavaScript / Python truthiness of a value, or undefined when unknown. */
  truthy(v: Val): boolean | undefined {
    if (v.k === 'unknown') return undefined;
    if (v.k === 'lit') return v.partial ? true : v.v !== null && v.v !== false && v.v !== 0 && v.v !== '';
    // An empty dict or list is falsy in Python; every object is truthy in JS.
    if (this.py && (v.k === 'obj' || v.k === 'arr')) {
      if (v.open) return undefined;
      return v.k === 'obj' ? v.fields.size > 0 : v.items.length > 0;
    }
    return true;
  }

  evRange(from0: number, to0: number, env: Env | null, depth: number, own = false): Val {
    if (depth > MAX_DEPTH || ++this.steps > MAX_STEPS) return UNKNOWN;
    const [from, to] = this.trim(from0, to0);
    if (from >= to) return UNKNOWN;
    const isOwn = own || this.inOwn(from);
    if (env) return this.evRangeRaw(from, to, env, depth, isOwn);
    const key = `${from}:${to}:${isOwn ? 1 : 0}`;
    const hit = this.rangeMemo.get(key);
    if (hit) return hit;
    const v = this.evRangeRaw(from, to, env, depth, isOwn);
    // Unknown is not cached: it may be a budget artefact of this registration.
    if (v.k !== 'unknown') this.rangeMemo.set(key, v);
    return v;
  }

  private evRangeRaw(from: number, to: number, env: Env | null, depth: number, isOwn: boolean): Val {
    const s = this.src;
    const text = s.slice(from, to);
    const d = depth + 1;

    // Python: a top-level comma makes a tuple (`TOOLS = (a, b)` — its parentheses
    // are trimmed off above), and a lambda's own parameters are not one.
    if (this.py && !/^lambda\b/.test(text)) {
      const items = this.split(from, to, ',').map(([a, b]) => this.trim(a, b)).filter(([a, b]) => b > a);
      if (items.length > 1 || (items.length === 1 && /,\s*$/.test(text))) {
        return { k: 'arr', items: items.slice(0, MAX_ITEMS).map(([a, b]) => ({ from: a, to: b, env, own: isOwn })), open: false };
      }
    }

    // Lowest precedence first: a ternary is a value we cannot choose.
    if (!this.py && this.hasTopLevelTernary(from, to)) return UNKNOWN;
    if (this.py && this.split(from, to, 'if').length > 1) return UNKNOWN;

    for (const op of this.py ? ['or'] : ['||', '??']) {
      const segs = this.split(from, to, op);
      if (segs.length > 1) {
        let cur = this.evRange(segs[0]![0], segs[0]![1], env, d, isOwn);
        for (const seg of segs.slice(1)) {
          const keep = op === '??' ? (cur.k === 'unknown' ? undefined : !(cur.k === 'lit' && cur.v === null)) : this.truthy(cur);
          if (keep === undefined) return UNKNOWN;
          if (keep) return cur;
          cur = this.evRange(seg[0], seg[1], env, d, isOwn);
        }
        return cur;
      }
    }

    // String concatenation (JS `+`), read piece by piece.
    if (!this.py || /['"]/.test(text)) {
      const plus = this.split(from, to, '+');
      if (plus.length > 1) return this.concat(plus.map(([a, b]) => this.evRange(a, b, env, d, isOwn)));
    }

    // Literals.
    if (/^(?:true|True|!0)$/.test(text)) return { k: 'lit', v: true };
    if (/^(?:false|False|!1)$/.test(text)) return { k: 'lit', v: false };
    if (/^(?:null|undefined|None|void\s+0)$/.test(text)) return NULLISH;
    if (/^-?\d+(?:\.\d+)?$/.test(text)) return { k: 'lit', v: Number(text) };
    if (!this.py && text.startsWith('`') && text.endsWith('`') && text.length >= 2 && text.includes('${')) return this.template(from, to, env, d, isOwn);
    // Python joins adjacent string literals (`("Search the web. "\n "Returns results.")`);
    // an f-string piece that cannot be read leaves a partial string.
    if (this.py && this.ctx.mask[from] === STRING) {
      const pieces = this.pyStrings(from, to);
      if (pieces && pieces.length > 1) return this.concat(pieces.map(([a, b]) => this.evRange(a, b, env, d, isOwn)));
      if (/^(?:[fF][rR]?|[rR][fF])['"]/.test(text)) return this.pyFString(from, to, env, d, isOwn);
    }
    if (/^[`'"]|^[rRbBuUfF]{1,2}['"]/.test(text)) {
      const f = fold(this.ctx, text, { at: from });
      return f.kind === 'literal' && f.values.length === 1 ? { k: 'lit', v: f.values[0]! } : UNKNOWN;
    }

    if (s[from] === '{' && this.close(from) === to - 1) return this.evObject(from, env, d, isOwn);
    if (s[from] === '[' && this.close(from) === to - 1) return this.evArray(from, env, d, isOwn);

    // A function literal is a value: the handler.
    const fnLit = this.fnAt(from, to);
    if (fnLit) return { k: 'fn', fn: fnLit, env };

    if (/^[A-Za-z_$][\w$]*$/.test(text)) return this.evIdent(text, from, env, d, isOwn);

    // Member access: `X.y`, `X?.y`, `X["y"]`.
    const mem = this.memberSplit(from, to);
    if (mem) {
      const base = this.evRange(mem.base[0], mem.base[1], env, d, isOwn);
      // `fn.__name__` — what FastMCP names a tool registered without a name.
      if (this.py && mem.prop === '__name__' && (base.k === 'fn' || base.k === 'ext')) {
        const ctx = base.k === 'ext' ? fileCtxOf(base.file) : this.ctx;
        return base.fn.name && !renamedPyFn(ctx, base.fn) ? { k: 'lit', v: base.fn.name } : UNKNOWN;
      }
      if (base.k === 'obj') {
        const f = base.fields.get(mem.prop);
        if (f) return this.ev(f, d);
        return base.open ? UNKNOWN : NULLISH;
      }
      if (base.k === 'lit' && base.v === null && mem.optional) return NULLISH;
      return UNKNOWN;
    }

    // Calls whose argument list closes the expression.
    const call = /^(?:new\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/.exec(text);
    if (call && this.close(from + call[0].length - 1) === to - 1) {
      const callee = call[1]!.replace(/\s+/g, '');
      const open = from + call[0].length - 1;
      const parts = this.parts(open) ?? [];
      if (callee === 'Object.freeze' && parts.length === 1) return this.evRange(parts[0]![0], parts[0]![1], env, d, isOwn);
      if (callee === 'Object.assign' && parts.length >= 1) return this.merge(parts.map(([a, b]) => ({ from: a, to: b, env, own: isOwn })), d);
      if (callee === 'Object.entries' || callee === 'Object.values' || callee === 'Object.keys') {
        if (parts.length !== 1) return UNKNOWN;
        const o = this.evRange(parts[0]![0], parts[0]![1], env, d, isOwn);
        if (o.k !== 'obj' || o.open) return UNKNOWN;
        const items: Thunk[] = [];
        for (const [key, v] of o.fields) {
          const keyVal: Val = { k: 'lit', v: key };
          if (callee === 'Object.keys') items.push({ val: keyVal, own: isOwn });
          else if (callee === 'Object.values') items.push(v);
          else items.push({ val: { k: 'arr', items: [{ val: keyVal, own: isOwn }, v], open: false }, own: isOwn });
        }
        return { k: 'arr', items: items.slice(0, MAX_ITEMS), open: false };
      }
      // Python `D.items()` / `.keys()` / `.values()` of a dict, and `list(X)` / `tuple(X)` of a sequence.
      if (this.py && parts.length === 0 && /\.(?:items|keys|values)$/.test(callee)) {
        const dot = text.lastIndexOf('.', call[0].length - 1);
        const o = this.evRange(from, from + dot, env, d, isOwn);
        if (o.k !== 'obj' || o.open) return UNKNOWN;
        const items: Thunk[] = [];
        for (const [key, v] of o.fields) {
          const keyVal: Val = { k: 'lit', v: key };
          if (callee.endsWith('.keys')) items.push({ val: keyVal, own: isOwn });
          else if (callee.endsWith('.values')) items.push(v);
          else items.push({ val: { k: 'arr', items: [{ val: keyVal, own: isOwn }, v], open: false }, own: isOwn });
        }
        return { k: 'arr', items: items.slice(0, MAX_ITEMS), open: false };
      }
      if (this.py && parts.length === 1 && (callee === 'list' || callee === 'tuple')) {
        const v = this.evRange(parts[0]![0], parts[0]![1], env, d, isOwn);
        return v.k === 'arr' ? v : UNKNOWN;
      }
      // Python `dict(X, k=v, **Y)` and an annotations constructor with keyword
      // arguments — `ToolAnnotations(readOnlyHint=True)`. A JS annotations class
      // taking one object (`new ToolAnnotations({…})`) reads the same.
      const last = callee.split('.').pop() ?? '';
      if ((this.py && last === 'dict') || /^(?:Tool)?Annotations?$/.test(last)) {
        if (!this.py && parts.length === 1) return this.evRange(parts[0]![0], parts[0]![1], env, d, isOwn);
        if (this.py) return this.evKwargs(parts, env, d, isOwn);
      }
      return UNKNOWN;
    }
    return UNKNOWN;
  }

  private hasTopLevelTernary(from: number, to: number): boolean {
    const s = this.src;
    for (let i = from; i < to; i++) {
      if (!this.ctx.isCode(i)) continue;
      const c = s[i]!;
      if (c === '(' || c === '[' || c === '{') {
        const e = this.close(i);
        if (e < 0 || e >= to) return false;
        i = e;
      } else if (c === '?' && s[i + 1] !== '.' && s[i + 1] !== '?' && s[i - 1] !== '?') return true;
    }
    return false;
  }

  /** Pieces of a concatenation: all known → a string; a known string with unknown pieces → partial. */
  private concat(vals: Val[]): Val {
    if (!vals.some((v) => v.k === 'lit' && typeof v.v === 'string')) return UNKNOWN;
    let out = '';
    let partial = false;
    for (const v of vals) {
      if (v.k === 'lit' && v.v !== null) {
        out += String(v.v);
        if (v.partial) partial = true;
      } else partial = true;
    }
    return { k: 'lit', v: out, ...(partial ? { partial } : {}) };
  }

  /** A template literal with `${…}` pieces evaluated in the environment. */
  private template(from: number, to: number, env: Env | null, d: number, own: boolean): Val {
    const body = this.src.slice(from + 1, to - 1);
    const vals: Val[] = [];
    let last = 0;
    const re = /\$\{([^{}`]{1,300})\}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body))) {
      vals.push({ k: 'lit', v: unescapeTemplate(body.slice(last, m.index)) });
      const a = from + 1 + m.index + 2;
      vals.push(this.evRange(a, a + m[1]!.length, env, d, own));
      last = m.index + m[0].length;
    }
    const rest = body.slice(last);
    if (rest.includes('${')) return UNKNOWN;
    vals.push({ k: 'lit', v: unescapeTemplate(rest) });
    return this.concat(vals);
  }

  /**
   * A Python f-string: its literal text, with each `{name}` piece read the way
   * Python formats it; any other piece (a call, a format spec) is left out and
   * the string is partial — good enough to read, never to name.
   */
  private pyFString(from: number, to: number, env: Env | null, d: number, own: boolean): Val {
    const text = this.src.slice(from, to);
    const m = /^([fF][rR]?|[rR][fF])("""|'''|"|')/.exec(text);
    if (!m) return UNKNOWN;
    const q = m[2]!;
    if (text.length < m[0].length + q.length || !text.endsWith(q)) return UNKNOWN;
    const raw = /[rR]/.test(m[1]!);
    const body = text.slice(m[0].length, text.length - q.length);
    const piece = (t: string): Val => ({ k: 'lit', v: raw ? t : decodeEscapes(t, true) });
    const vals: Val[] = [];
    let lit = '';
    for (let i = 0; i < body.length; i++) {
      const c = body[i]!;
      if ((c === '{' || c === '}') && body[i + 1] === c) {
        lit += c;
        i++;
        continue;
      }
      if (c !== '{') {
        lit += c;
        continue;
      }
      const close = body.indexOf('}', i);
      if (close < 0) return UNKNOWN;
      vals.push(piece(lit));
      lit = '';
      const inner = body.slice(i + 1, close);
      const id = /^\s*([A-Za-z_]\w*)\s*$/.exec(inner);
      let v: Val = UNKNOWN;
      if (id && vals.length < MAX_ITEMS) {
        v = this.evIdent(id[1]!, from + m[0].length + i + 1 + inner.indexOf(id[1]!), env, d, own);
        if (v.k === 'lit' && typeof v.v === 'boolean') v = { k: 'lit', v: v.v ? 'True' : 'False' };
        else if (v.k === 'lit' && v.v === null) v = { k: 'lit', v: 'None' };
        else if (v.k !== 'lit') v = UNKNOWN;
      }
      vals.push(v);
      i = close;
    }
    vals.push(piece(lit));
    return this.concat(vals);
  }

  /** `base.prop` / `base?.prop` / `base["prop"]` at the top level of a range. */
  private memberSplit(from: number, to: number): { base: [number, number]; prop: string; optional: boolean } | null {
    const s = this.src;
    if (s[to - 1] === ']') {
      for (let i = to - 2; i > from; i--) {
        if (!this.ctx.isCode(i) || s[i] !== '[') continue;
        if (this.close(i) !== to - 1) continue;
        const key = /^\[\s*(['"])([\w$-]{1,64})\1\s*\]$/.exec(s.slice(i, to));
        if (!key) return null;
        const optional = s.slice(i - 2, i) === '?.';
        return { base: [from, optional ? i - 2 : i], prop: key[2]!, optional };
      }
      return null;
    }
    let i = to;
    while (i > from && /[\w$]/.test(s[i - 1]!)) i--;
    if (i === to || i <= from) return null;
    const prop = s.slice(i, to);
    let j = i;
    while (j > from && /\s/.test(s[j - 1]!)) j--;
    if (s[j - 1] !== '.' || !this.ctx.isCode(j - 1)) return null;
    const optional = s[j - 2] === '?';
    const baseEnd = optional ? j - 2 : j - 1;
    if (baseEnd <= from) return null;
    return { base: [from, baseEnd], prop, optional };
  }

  private byHeader?: Map<number, FnInfo>;

  /** A function literal spanning exactly this range. */
  fnAt(from: number, to: number): FnInfo | null {
    const head = this.src.slice(from, from + 12);
    if (!/^(?:async\b|function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(head)) return null;
    if (/^\(/.test(head) && !/=>/.test(this.src.slice(from, Math.min(to, from + 400)))) return null;
    if (!this.byHeader) {
      this.byHeader = new Map();
      for (const f of this.ctx.functions()) if (!this.byHeader.has(f.headerStart)) this.byHeader.set(f.headerStart, f);
    }
    for (let h = from; h <= from + 8; h++) {
      const f = this.byHeader.get(h);
      if (f && f.bodyEnd <= to + 1) return f;
    }
    return null;
  }

  private readonly paramsMemo = new Map<FnInfo, Param[]>();
  readonly reassignedMemo = new Map<string, boolean>();
  readonly shadowMemo = new Map<string, boolean>();

  /** {@link paramsOf}, memoised per function. */
  params(fn: FnInfo): Param[] {
    let p = this.paramsMemo.get(fn);
    if (!p) this.paramsMemo.set(fn, (p = paramsOf(this, fn)));
    return p;
  }

  private evIdent(name: string, at: number, env: Env | null, d: number, own: boolean): Val {
    const bound = this.lookup(env, name);
    if (bound) return this.ev(bound, d);
    if (name === 'undefined') return NULLISH;
    // A name this file imports is defined somewhere we did not read — unless it
    // is a Python name from one of the package's own files.
    if (this.imported(name)) return this.py ? this.importedValue(name) : UNKNOWN;
    const decl = this.ctx.constInitAt(name, at);
    if (decl && decl.init && decl.init !== name) {
      // The whole initializer, not readInit's 4,000-character prefix: a table of
      // fourteen tool definitions is longer than that.
      const start = this.src.indexOf(decl.init, decl.at);
      if (start < 0) return UNKNOWN;
      let end = start + decl.init.length;
      if (this.py) {
        // A Python statement ends at its logical line: a tuple's commas, a long
        // triple-quoted string and a parenthesized concatenation are all of it.
        end = this.pyStatementEnd(start);
        if (end < 0) return UNKNOWN;
      } else if (this.src[start] === '{' || this.src[start] === '[') {
        const c = this.close(start);
        if (c > 0) end = c + 1;
      } else if (/^Object\s*\.\s*freeze\s*\(/.test(decl.init)) {
        const open = this.src.indexOf('(', start);
        const c = this.close(open);
        if (c > 0) end = c + 1;
      }
      // A constant whose value is changed later (`ANN.readOnlyHint = false`,
      // `HINTS.update(…)`, an alias that is written through) is not its
      // initializer. A frozen object cannot be changed.
      const frozen = /^Object\s*\.\s*freeze\s*\(/.test(decl.init);
      if (!frozen && this.changedLater(name, decl.at)) return UNKNOWN;
      const declEnv = this.envFor(env, decl.at);
      const key = declEnv ? '' : `${decl.at}:${own ? 1 : 0}`;
      if (key && this.constMemo.has(key)) return this.constMemo.get(key)!;
      const v = this.evRange(start, end, declEnv, d, own);
      if (key && v.k !== 'unknown') this.constMemo.set(key, v);
      return v;
    }
    const fn = this.py ? this.pyFnAt(name, at) : this.fnNamed(name);
    if (fn) return { k: 'fn', fn, env: null };
    return UNKNOWN;
  }

  /** Where the Python statement whose expression starts at `from` ends, or -1 when a bracket is never closed. */
  pyStatementEnd(from: number): number {
    const { src } = this;
    for (let i = from; i < src.length; i++) {
      if (!this.ctx.isCode(i)) {
        if (this.ctx.mask[i] === COMMENT) return this.trimWs(from, i)[1];
        continue;
      }
      const c = src[i]!;
      if (c === '(' || c === '[' || c === '{') {
        const e = this.close(i);
        if (e < 0) return -1;
        i = e;
      } else if ((c === '\n' && src[i - 1] !== '\\') || c === ';') return this.trimWs(from, i)[1];
    }
    return src.length;
  }

  /** Adjacent Python string literals filling a range, separated only by blanks and comments. */
  private pyStrings(from: number, to: number): [number, number][] | null {
    const { src } = this;
    const mask = this.ctx.mask;
    const out: [number, number][] = [];
    let i = from;
    while (i < to) {
      if (mask[i] === STRING) {
        const s = i;
        while (i < to && mask[i] === STRING) i++;
        out.push([s, i]);
        if (out.length > MAX_ITEMS) return null;
      } else if (mask[i] === COMMENT || /\s/.test(src[i]!) || (src[i] === '\\' && src[i + 1] === '\n')) i++;
      else return null;
    }
    return out;
  }

  /**
   * A Python name imported from one of the package's own files: a function
   * there (its name is what FastMCP calls the tool), or a constant there — a
   * string, number or boolean, read in that file alone, so a chain of imports
   * is followed one hop for a value and never loops.
   */
  private importedValue(name: string): Val {
    const pkg = this.pkg;
    if (!pkg || !pkg.has(this.ctx.path)) return UNKNOWN;
    const imp = pyImports(this.ctx).get(name);
    if (!imp) return UNKNOWN;
    const ref = pkg.refOf(this.ctx.path, imp);
    if (!ref) return UNKNOWN;
    if (ref.kind === 'fn') return { k: 'ext', name: ref.name, file: ref.file, fn: ref.fn };
    const v = constReader(ref.file).moduleConst(ref.name);
    return v.k === 'lit' ? v : UNKNOWN;
  }

  /** The value of a module-level constant of this file, when it is one literal value of a bounded size. */
  moduleConst(name: string): Val {
    if (this.imported(name)) return UNKNOWN;
    const decl = this.ctx.constInitAt(name, this.src.length);
    if (!decl) return UNKNOWN;
    const start = this.src.indexOf(decl.init, decl.at);
    const end = start < 0 ? -1 : this.pyStatementEnd(start);
    if (end < 0 || end - start > MAX_PY_CONST) return UNKNOWN;
    this.begin([]);
    return this.evIdent(name, this.src.length, null, 0, false);
  }

  private readonly pyFnMemo = new Map<string, FnInfo | null>();

  /**
   * The Python `def` a bare name refers to at `at`, scope by scope from the
   * innermost function out: a parameter, an assignment, a loop or `as` target,
   * a class of that name in a scope in between is what the name means there,
   * not the def. Two defs of the name in one scope are not one function.
   */
  pyFnAt(name: string, at: number): FnInfo | null {
    const inner = this.enclosing(at);
    const key = `${name}\u0000${inner ? inner.bodyStart : -1}`;
    const hit = this.pyFnMemo.get(key);
    if (hit !== undefined) return hit;
    let found: FnInfo | null = null;
    for (let scope: FnInfo | null = inner, n = 0; n < MAX_DEPTH; n++) {
      if (scope && scope.params.some((p) => p.name === name)) break;
      if (this.pyBound(name, scope)) break;
      const defs = this.ctx.functions().filter(
        (f) => f.name === name && f.kind !== 'method' && this.enclosing(f.headerStart) === scope && (scope !== null || !inClassBody(this.ctx, f)),
      );
      if (defs.length) {
        found = defs.length === 1 ? defs[0]! : null;
        break;
      }
      if (!scope) break;
      scope = this.enclosing(scope.headerStart);
    }
    this.pyFnMemo.set(key, found);
    return found;
  }

  private readonly pyBoundMemo = new Map<string, boolean>();

  /** Is `name` bound in this scope (module when null) by anything but a `def` — an assignment, a loop, `as`, `class`? */
  private pyBound(name: string, scope: FnInfo | null): boolean {
    const key = `${name}\u0000${scope ? scope.bodyStart : -1}`;
    const hit = this.pyBoundMemo.get(key);
    if (hit !== undefined) return hit;
    const { src } = this;
    let v = false;
    let work = 0;
    for (const i of this.identOffsetsOf(name)) {
      // A file that makes this cost more than a real one ever does: the name is
      // taken as bound, and the reading stays unknown.
      if ((work += 64) > MAX_BIND_WORK) {
        v = true;
        break;
      }
      // A class attribute binds the name in the class, not in the scope around it.
      if (this.enclosing(i) !== scope || this.pyInClass(i)) continue;
      // The line's start, looked for no further back than a binding's prefix may
      // reach: a name repeated along one 500 KB line must not rescan it each time.
      let lineStart = i;
      while (lineStart > 0 && i - lineStart <= 400 && src[lineStart - 1] !== '\n') lineStart--;
      if (i - lineStart > 400) continue;
      const prefix = src.slice(lineStart, i);
      const suffix = src.slice(i + name.length, i + name.length + 8);
      const forAt = prefix.search(/\bfor\b/);
      if (
        (forAt >= 0 && !/\bin\b/.test(prefix.slice(forAt + 3))) ||
        /\b(?:as|class)[ \t]+$/.test(prefix) ||
        /^\s*:=/.test(suffix) ||
        (this.pyDepth(i) === 0 && /^[\w\s,()*]*$/.test(prefix) && !/\bdef\s+$/.test(prefix) && this.pyAssigns(i, name.length, (n) => (work += n)))
      ) {
        v = true;
        break;
      }
    }
    this.pyBoundMemo.set(key, v);
    return v;
  }

  /**
   * Is the name at `i` an assignment target (`name = …`, `name: T = …`, `a, name = …`)?
   * The `=` is the first one at the name's own bracket depth on its logical line.
   */
  private pyAssigns(i: number, len: number, spend: (n: number) => void): boolean {
    const { src } = this;
    const d0 = this.pyDepth(i);
    let k = i + len;
    while (src[k] === ' ' || src[k] === '\t') k++;
    const annotated = src[k] === ':' && src[k + 1] !== '=';
    let n = 0;
    try {
      return this.pyAssignsFrom(k, d0, annotated, () => n++);
    } finally {
      spend(n);
    }
  }

  private pyAssignsFrom(k0: number, d0: number, annotated: boolean, tick: () => void): boolean {
    const { src } = this;
    let k = k0;
    for (let n = 0; k < src.length && n < 2000; k++, n++) {
      tick();
      const c = src[k]!;
      if (!this.ctx.isCode(k)) {
        if (this.ctx.mask[k] === COMMENT) return false;
        continue;
      }
      if (this.pyDepth(k) !== d0) continue;
      if (c === '\n') {
        if (src[k - 1] === '\\') continue;
        return false;
      }
      if (c === '=') return src[k + 1] !== '=' && !/[=!<>:]/.test(src[k - 1] ?? '');
      if (!annotated && !/[\w \t\r,()*\\]/.test(c)) return false;
    }
    return false;
  }

  private classLines?: Uint8Array;

  /** Is offset `i` in a class body (its innermost `def` or `class` block is a class)? One indentation pass per file. */
  private pyInClass(i: number): boolean {
    if (!this.classLines) {
      const { src } = this;
      const flags: number[] = [];
      const stack: { indent: number; cls: boolean }[] = [];
      let pos = 0;
      let opener: boolean | null = null;
      while (pos <= src.length) {
        const nl = src.indexOf('\n', pos);
        const end = nl < 0 ? src.length : nl;
        const ind = /^[ \t]*/.exec(src.slice(pos, Math.min(end, pos + 400)))![0].length;
        const at = pos + ind;
        // A line that starts code at the top bracket level closes the blocks indented as deep or deeper.
        if (at < end && this.ctx.isCode(at) && src[at] !== '#' && this.pyDepth(at) === 0) {
          while (stack.length && stack[stack.length - 1]!.indent >= ind) stack.pop();
          const head = /^(?:async[ \t]+)?(def|class)\b/.exec(src.slice(at, at + 12));
          opener = head ? head[1] === 'class' : null;
        } else opener = null;
        flags.push(stack.length && stack[stack.length - 1]!.cls ? 1 : 0);
        if (opener !== null) stack.push({ indent: ind, cls: opener });
        else if (stack.length && at < end && this.ctx.isCode(at) && this.pyDepth(at) === 0) {
          // An `if`/`for`/`with` block inherits the innermost def or class around it.
          const top = stack[stack.length - 1]!;
          let k = end - 1;
          while (k > at && (/\s/.test(src[k]!) || this.ctx.mask[k] === COMMENT)) k--;
          if (src[k] === ':' && this.ctx.isCode(k)) stack.push({ indent: ind, cls: top.cls });
        }
        if (nl < 0) break;
        pos = nl + 1;
      }
      this.classLines = Uint8Array.from(flags);
    }
    return this.classLines[this.ctx.line(i) - 1] === 1;
  }

  private identIndex?: Map<string, number[]>;

  /** Offsets of `name` as a bare identifier in code (not `x.name`). */
  identOffsetsOf(name: string): number[] {
    if (!this.identIndex) {
      // Every name in one pass: a scan of the file per name asked about let a
      // file of loops over tens of thousands of names cost a minute.
      const index = new Map<string, number[]>();
      const { src } = this;
      for (const m of src.matchAll(/\w+/g)) {
        const i = m.index!;
        if (/^\d/.test(m[0]) || src[i - 1] === '.' || !this.ctx.isCode(i)) continue;
        const list = index.get(m[0]);
        if (!list) index.set(m[0], [i]);
        else if (list.length < MAX_RAW_CALLS) list.push(i);
      }
      this.identIndex = index;
    }
    return this.identIndex.get(name) ?? [];
  }

  private depths?: Uint16Array;

  /** Bracket depth at an offset (code brackets only), from one pass over the file. */
  private pyDepth(i: number): number {
    if (!this.depths) {
      const n = this.src.length;
      const d = new Uint16Array(n);
      let depth = 0;
      for (let k = 0; k < n; k++) {
        d[k] = depth;
        if (!this.ctx.isCode(k)) continue;
        const c = this.src.charCodeAt(k);
        if (c === 40 || c === 91 || c === 123) depth = Math.min(depth + 1, 65535);
        else if ((c === 41 || c === 93 || c === 125) && depth > 0) depth--;
      }
      this.depths = d;
    }
    return this.depths[i] ?? 0;
  }

  private readonly aliasMemo = new Map<string, boolean>();
  private readonly changedMemo = new Map<string, boolean>();

  /** Mutated in its scope, aliased, or written through a function — once per declaration. */
  private changedLater(name: string, declAt: number): boolean {
    const key = `${name}\u0000${declAt}`;
    const hit = this.changedMemo.get(key);
    if (hit !== undefined) return hit;
    const v = this.ctx.mutated(name, this.enclosing(declAt)) || this.aliasedOrPassed(name);
    this.changedMemo.set(key, v);
    return v;
  }

  /** Is a constant aliased (`const a = ANN`) or handed to a same-file function that writes into its parameter? */
  private aliasedOrPassed(name: string): boolean {
    const hit = this.aliasMemo.get(name);
    if (hit !== undefined) return hit;
    const n = name.replace(/[$]/g, '\\$');
    // An alias is an assignment STATEMENT (`const a = ANN;`, `a = ANN` on its own
    // line) — not a keyword argument (`annotations=ANN`) or a parameter default.
    let v = new RegExp(`(?:^|[;{}])[ \\t]*(?:(?:const|let|var)[ \\t]+)?[A-Za-z_$][\\w$]*[ \\t]*=[ \\t]*${n}[ \\t]*(?:;|$)`, 'm').test(this.src);
    if (!v) {
      for (const m of this.src.matchAll(new RegExp(`(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*\\(\\s*${n}\\s*[,)]`, 'g'))) {
        const f = this.fnNamed(m[1]!);
        const p = f?.params[0]?.name;
        if (!f || !p) continue;
        const body = this.src.slice(f.bodyStart, f.bodyEnd);
        if (new RegExp(`(?<![\\w$.])${p.replace(/[$]/g, '\\$')}\\s*(?:\\.[\\w$]+|\\[[^\\]]{0,100}\\])\\s*=(?![=>])`).test(body)) {
          v = true;
          break;
        }
      }
    }
    this.aliasMemo.set(name, v);
    return v;
  }

  private importedNames?: Set<string>;

  imported(name: string): boolean {
    if (!this.importedNames) {
      const out = new Set<string>();
      const s = this.src;
      const add = (list: string): void => {
        for (const part of list.split(',')) {
          const m = /(?:^|\s)(?:[\w$]+\s+as\s+)?([A-Za-z_$][\w$]*)\s*$/.exec(part.replace(/[{}()]/g, ' ').trim());
          if (m) out.add(m[1]!);
        }
      };
      if (this.py) {
        for (const m of s.matchAll(/^[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]+\(?([^)\n]+)\)?/gm)) add(m[1]!);
        for (const m of s.matchAll(/^[ \t]*import[ \t]+([\w., ]+)$/gm)) add(m[1]!);
        // A parenthesized list over several lines (`from pkg.contract import (\n A,\n B,\n)`).
        for (const local of pyImports(this.ctx).keys()) out.add(local);
      } else {
        // `import { a, b as c } from '…'` — found by keyword, then the clause is
        // cut at `from` with indexOf: a regex with overlapping whitespace classes
        // is quadratic on a hostile file's long run of spaces.
        for (const m of s.matchAll(/\bimport\b/g)) {
          const win = s.slice(m.index! + 6, m.index! + 1200);
          const f = win.search(/\bfrom\s{0,8}['"]/);
          if (f < 0) continue;
          const clause = win.slice(0, f);
          if (/^[\w$*{},\s]+$/.test(clause)) add(clause.replace(/\*\s+as\s+/g, ''));
        }
        for (const m of s.matchAll(/\b(?:const|let|var)\s+(\{[^}]{0,400}\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(/g)) add(m[1]!.replace(/:\s*[\w$]+/g, ''));
        for (const m of s.matchAll(/\b(?:const|let|var)\s+(\{[^}]{0,400}\}|[A-Za-z_$][\w$]*)\s*=\s*await\s+import\s*\(/g)) add(m[1]!);
      }
      this.importedNames = out;
    }
    return this.importedNames.has(name);
  }

  /** `{ … }` (JS object / Python dict) — fields in source order, spreads applied as the language does. */
  private evObject(open: number, env: Env | null, d: number, own: boolean): Val {
    const parts = this.parts(open);
    if (!parts) return UNKNOWN;
    const fields = new Map<string, Thunk>();
    let isOpen = false;
    const s = this.src;
    const clear = (): void => {
      fields.clear();
      isOpen = true;
    };
    const set = (k: string, t: Thunk): void => {
      fields.delete(k);
      fields.set(k, t);
    };
    for (const [a, b] of parts) {
      const [from, to] = this.trim(a, b);
      if (from >= to) continue;
      const head = s.slice(from, Math.min(to, from + 200));
      const spread = this.py ? /^\*\*\s*/.exec(head) : /^\.\.\.\s*/.exec(head);
      if (spread) {
        const v = this.evRange(from + spread[0].length, to, env, d, own);
        if (v.k === 'obj') {
          if (v.open) clear();
          this.copied += v.fields.size;
          if (this.copied > MAX_SPREAD_COPIES) {
            clear();
            continue;
          }
          for (const [k, t] of v.fields) set(k, t);
        } else if (v.k === 'lit' && (v.v === null || v.v === false || v.v === '' || v.v === 0)) {
          // `...undefined` / `...(x && {…})` with a falsy x adds nothing.
        } else clear();
        continue;
      }
      const kv = /^(?:([A-Za-z_$][\w$]*)|'([^'\\\n]{0,64})'|"([^"\\\n]{0,64})"|(\d+))\s*:(?!:)/.exec(head);
      if (kv) {
        set(kv[1] ?? kv[2] ?? kv[3] ?? kv[4]!, { from: from + kv[0].length, to, env, own });
        continue;
      }
      if (!this.py && /^[A-Za-z_$][\w$]*$/.test(s.slice(from, to))) {
        set(s.slice(from, to), { from, to, env, own });
        continue;
      }
      // A computed key, getter or setter could be ANY field — nothing written
      // before it is certain any more.
      if (head.startsWith('[') || /^(?:get|set)\s+[\w$[]/.test(head)) {
        clear();
        continue;
      }
      const method = /^(?:async\s+)?\*?\s*([A-Za-z_$][\w$]*)\s*\(/.exec(head);
      if (method) {
        set(method[1]!, { val: UNKNOWN });
        continue;
      }
      clear();
    }
    return { k: 'obj', fields, open: isOpen };
  }

  private evArray(open: number, env: Env | null, d: number, own: boolean): Val {
    const parts = this.parts(open);
    if (!parts) return UNKNOWN;
    const items: Thunk[] = [];
    let isOpen = false;
    for (const [a, b] of parts) {
      const [from, to] = this.trim(a, b);
      const head = this.src.slice(from, from + 4);
      if (head.startsWith('...') || (this.py && head.startsWith('*') && !head.startsWith('**'))) {
        const v = this.evRange(from + (head.startsWith('...') ? 3 : 1), to, env, d, own);
        if (v.k === 'arr') {
          items.push(...v.items);
          if (v.open) isOpen = true;
        } else isOpen = true;
        continue;
      }
      items.push({ from, to, env, own });
      if (items.length >= MAX_ITEMS) break;
    }
    return { k: 'arr', items, open: isOpen };
  }

  /** Python call arguments as an object: positional dicts and `**X` spread in, `k=v` fields. */
  evKwargs(parts: [number, number][], env: Env | null, d: number, own: boolean): Val {
    const fields = new Map<string, Thunk>();
    let isOpen = false;
    const spread = (v: Val): void => {
      if (v.k === 'obj') {
        if (v.open) {
          fields.clear();
          isOpen = true;
        }
        for (const [k, t] of v.fields) {
          fields.delete(k);
          fields.set(k, t);
        }
      } else if (!(v.k === 'lit' && v.v === null)) {
        fields.clear();
        isOpen = true;
      }
    };
    for (const [a, b] of parts) {
      const [from, to] = this.trim(a, b);
      const head = this.src.slice(from, Math.min(to, from + 120));
      if (head.startsWith('**')) {
        spread(this.evRange(from + 2, to, env, d, own));
        continue;
      }
      const kw = /^([A-Za-z_]\w*)\s*=(?!=)\s*/.exec(head);
      if (kw) {
        fields.delete(kw[1]!);
        fields.set(kw[1]!, { from: from + kw[0].length, to, env, own });
        continue;
      }
      // `dict(WRITE)` copies a mapping; anything else positional we cannot read.
      spread(this.evRange(from, to, env, d, own));
    }
    return { k: 'obj', fields, open: isOpen };
  }

  /** `Object.assign(a, b, …)` — later arguments overwrite earlier ones. */
  private merge(args: Thunk[], d: number): Val {
    const fields = new Map<string, Thunk>();
    let isOpen = false;
    for (const t of args) {
      const v = this.ev(t, d);
      if (v.k === 'obj') {
        if (v.open) {
          fields.clear();
          isOpen = true;
        }
        for (const [k, f] of v.fields) {
          fields.delete(k);
          fields.set(k, f);
        }
      } else if (!(v.k === 'lit' && v.v === null)) {
        fields.clear();
        isOpen = true;
      }
    }
    return { k: 'obj', fields, open: isOpen };
  }

  /** A string value; `partial` admits one with unreadable pieces left out (descriptions, never names). */
  str(t: Thunk | undefined, partial = false): string | undefined {
    if (!t) return undefined;
    const v = this.ev(t);
    if (v.k !== 'lit' || typeof v.v !== 'string') return undefined;
    return v.partial && !partial ? undefined : v.v;
  }

  /** The hints an `annotations` value carries, and whether they came from the call site, the helper, or both. */
  hints(v: Val): { hints?: ToolHints; source: HintSource } {
    if (v.k === 'lit' && v.v === null) return { source: 'none' };
    if (v.k !== 'obj') return { source: 'unreadable' };
    const out: ToolHints = {};
    let declared = 0;
    let dflt = 0;
    for (const [k, t] of v.fields) {
      const h = hintKey(k);
      if (!h) continue;
      const b = this.ev(t);
      if (b.k !== 'lit' || typeof b.v !== 'boolean') continue;
      out[h] = b.v;
      if (t.own) declared++;
      else dflt++;
    }
    const any = Object.keys(out).length > 0;
    // Annotations whose every hint sits under an unreadable spread say nothing we can read.
    if (!any && v.open) return { source: 'unreadable' };
    const source: HintSource = declared && dflt ? 'merged' : dflt ? 'default' : 'declared';
    return any ? { hints: out, source } : { source };
  }
}

function unescapeTemplate(s: string): string {
  return decodeEscapes(s, false, false);
}

// --- merging two reads of one tool ----------------------------------------------

/**
 * Two registrations of one name — an if/else pair, a legacy branch, a second
 * file — merge toward the riskier reading: a write declared by either is a
 * write. A decoy `readOnlyHint: true` beside the real writer must not win.
 */
export function mergeHints(a: ToolHints | undefined, b: ToolHints | undefined): ToolHints | undefined {
  if (!a) return b;
  if (!b) return a;
  const out: ToolHints = { ...a, ...b };
  if (a.readOnlyHint === false || b.readOnlyHint === false) out.readOnlyHint = false;
  if (a.destructiveHint === true || b.destructiveHint === true) out.destructiveHint = true;
  if (a.openWorldHint === true || b.openWorldHint === true) out.openWorldHint = true;
  if (a.idempotentHint === false || b.idempotentHint === false) out.idempotentHint = false;
  return out;
}

/** Both descriptions, when one does not already contain the other. */
export function mergeDescriptions(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b) return a;
  const x = a.trim();
  const y = b.trim();
  if (x.includes(y)) return a;
  if (y.includes(x)) return b;
  return `${a}\n\n${b}`.slice(0, MAX_MERGED_DESC);
}

function sameHints(a: ToolHints | undefined, b: ToolHints | undefined): boolean {
  return JSON.stringify(a ?? {}) === JSON.stringify(b ?? {});
}

// --- registrations ------------------------------------------------------------

interface RegCall {
  /** Offset of the method name (`registerTool`). */
  at: number;
  method: 'registerTool' | 'tool' | 'addTool';
  /** The receiver text before the method (`server`, `this.server`). */
  receiver: string;
  args: [number, number][];
}

/** What a registration call says, evaluated in an environment. */
interface RegView {
  name?: string;
  /** The name could not be read (budget, unknown): the tool exists but is unnamed. */
  title?: string;
  description?: string;
  params?: string[];
  annotations: Val;
  handler?: Thunk;
  /** Does the call look like a tool registration at all? (`widget.tool(a, b)` does not.) */
  shaped: boolean;
}

const RE_JS_REG = /\.\s*(registerTool|addTool|tool)\s*\(/g;

function jsRegCalls(r: Reader): RegCall[] {
  const out: RegCall[] = [];
  RE_JS_REG.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RE_JS_REG.exec(r.src))) {
    if (out.length >= MAX_RAW_CALLS) {
      truncatedFlag = true;
      break;
    }
    const at = m.index + m[0].indexOf(m[1]!);
    if (!r.ctx.isCode(at)) continue;
    const open = m.index + m[0].length - 1;
    const args = r.parts(open);
    if (!args || !args.length) continue;
    const receiver = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\)?\s*$/.exec(r.src.slice(Math.max(0, m.index - 80), m.index))?.[1] ?? '';
    out.push({ at, method: m[1] as RegCall['method'], receiver, args });
  }
  return out;
}


const isFnText = (s: string): boolean => /^(?:async\b|function\b|\([^)]{0,400}\)\s*(?::[^=]{1,80})?=>|[A-Za-z_$][\w$]*\s*=>)/.test(s.trim());

function schemaParams(r: Reader, t: Thunk | undefined): string[] | undefined {
  if (!t) return undefined;
  let v = r.ev(t);
  // `z.object({ … })` — the shape is the object inside.
  if (v.k === 'unknown' && !('val' in t)) {
    const txt = r.text(t.from, t.to);
    const zo = /^\s*z\s*\.\s*object\s*\(/.exec(txt);
    if (zo) {
      const open = t.from + zo[0].length - 1;
      const parts = r.parts(open);
      if (parts?.length === 1) v = r.evRange(parts[0]![0], parts[0]![1], t.env, 1, t.own ?? false);
    }
  }
  if (v.k !== 'obj') return undefined;
  const props = v.fields.get('properties');
  if (props) {
    const p = r.ev(props);
    if (p.k === 'obj') return [...p.fields.keys()].slice(0, 64);
  }
  const keys = [...v.fields.keys()].filter((k) => k !== 'type' && k !== 'required' && k !== 'additionalProperties' && k !== '$schema');
  return keys.length ? keys.slice(0, 64) : undefined;
}

const fieldOf = (obj: Val, key: string): Thunk | undefined => (obj.k === 'obj' ? obj.fields.get(key) : undefined);
const annotationsOf = (r: Reader, def: Val): Val => {
  if (def.k !== 'obj') return def.k === 'lit' && def.v === null ? NULLISH : UNKNOWN;
  const a = def.fields.get('annotations');
  if (a) return r.ev(a);
  return def.open ? UNKNOWN : NULLISH;
};
const hintShaped = (v: Val): boolean =>
  v.k === 'obj' && !v.open && [...v.fields.keys()].some((k) => hintKey(k) !== undefined) && [...v.fields.keys()].every((k) => k === 'title' || hintKey(k) !== undefined);

/** Read one registration call under an environment. */
function viewOf(r: Reader, call: RegCall, env: Env | null): RegView {
  const th = (i: number): Thunk | undefined => (call.args[i] ? { from: call.args[i]![0], to: call.args[i]![1], env } : undefined);
  const argText = (i: number): string => (call.args[i] ? r.text(call.args[i]![0], call.args[i]![1]).trim() : '');
  const n = call.args.length;

  // `addTool({ name, description, parameters, annotations, execute })`, and the
  // object form of `.tool({ … })`.
  if (call.method === 'addTool' || (call.method === 'tool' && n === 1 && argText(0).startsWith('{'))) {
    const def = r.ev(th(0));
    return {
      name: r.str(fieldOf(def, 'name')),
      title: r.str(fieldOf(def, 'title'), true),
      description: r.str(fieldOf(def, 'description'), true),
      params: schemaParams(r, fieldOf(def, 'parameters') ?? fieldOf(def, 'inputSchema')),
      annotations: annotationsOf(r, def),
      handler: fieldOf(def, 'execute') ?? fieldOf(def, 'handler'),
      shaped: def.k === 'obj' && ['description', 'execute', 'parameters', 'inputSchema', 'annotations'].some((k) => def.fields.has(k)),
    };
  }
  const name = r.str(th(0));
  if (call.method === 'registerTool') {
    // `registerTool(name, config, cb)`; `registerTool(name, cb)` / `registerTool(name)` carry no definition.
    const def = n > 2 || (n === 2 && !isFnText(argText(1))) ? r.ev(th(1)) : NULLISH;
    return {
      name,
      title: r.str(fieldOf(def, 'title'), true),
      description: r.str(fieldOf(def, 'description'), true),
      params: schemaParams(r, fieldOf(def, 'inputSchema') ?? fieldOf(def, 'paramsSchema')),
      annotations: n > 2 ? annotationsOf(r, def) : NULLISH,
      handler: n > 1 ? th(n - 1) : undefined,
      shaped: true,
    };
  }
  // The TS SDK's positional overloads, decided by arity as the SDK decides them:
  //   tool(name, cb)                          tool(name, description, cb)
  //   tool(name, schemaOrAnnotations, cb)     tool(name, description, schemaOrAnnotations, cb)
  //   tool(name, schema, annotations, cb)     tool(name, description, schema, annotations, cb)
  // The last argument is always the callback — a function, a reference, or a
  // wrapped call (`withErrors(async () => …)`).
  const cbText = argText(n - 1);
  const cbOk = n >= 2 && !/^[{['"`\d]/.test(cbText);
  const mid = n >= 2 ? Array.from({ length: n - 2 }, (_, i) => i + 1) : [];
  const vals = mid.map((i) => ({ i, v: r.ev(th(i)), text: argText(i) }));
  const objectish = (x: { v: Val; text: string }): boolean => x.v.k === 'obj' || /^(?:\{|z\s*\.)/.test(x.text);
  const stringish = (x: { v: Val; text: string }): boolean => (x.v.k === 'lit' && typeof x.v.v === 'string') || (x.v.k === 'unknown' && !/^(?:\{|z\s*\.)/.test(x.text));
  let description: string | undefined;
  let schema: Thunk | undefined;
  let annotations: Val = NULLISH;
  const descOf = (x: { v: Val }): string | undefined => (x.v.k === 'lit' && typeof x.v.v === 'string' ? x.v.v : undefined);
  if (vals.length === 1) {
    const [x] = vals as [(typeof vals)[number]];
    if (hintShaped(x.v)) annotations = x.v;
    else if (objectish(x)) schema = th(x.i);
    else if (stringish(x)) description = descOf(x);
  } else if (vals.length === 2) {
    const [a, b] = vals as [(typeof vals)[number], (typeof vals)[number]];
    if (objectish(a) && !stringish(a)) {
      schema = th(a.i);
      annotations = b.v;
    } else {
      description = descOf(a);
      if (hintShaped(b.v)) annotations = b.v;
      else if (b.v.k === 'unknown') annotations = UNKNOWN;
      else schema = th(b.i);
    }
  } else if (vals.length === 3) {
    description = descOf(vals[0]!);
    schema = th(vals[1]!.i);
    annotations = vals[2]!.v;
  } else if (vals.length > 3) annotations = UNKNOWN;
  const toolShaped = (v: Val): boolean =>
    v.k === 'obj' && [...v.fields.keys()].some((k) => /^(?:description|inputSchema|parameters|annotations|title)$/.test(k) || hintKey(k) !== undefined);
  const shaped = cbOk && (n >= 3 || isFnText(cbText) || description !== undefined || vals.some((x) => toolShaped(x.v)));
  return { name, description, params: schemaParams(r, schema), annotations, handler: cbOk ? th(n - 1) : undefined, shaped };
}

// --- conditions ---------------------------------------------------------------

interface IfStmt {
  at: number;
  fn: FnInfo | null;
  expr: string;
  exprFrom: number;
  exprTo: number;
  /** Consequent `[start, end]`. */
  then: [number, number];
  /** Else branch, when there is one. */
  else?: [number, number];
  /** An early exit (`return` / `throw` / `continue`) at the top level of its function. */
  exit: false | 'return' | 'throw' | 'continue';
  /** The if statement sits at the top level of its function body. */
  top: boolean;
  /** Brace depth at the `if`. */
  depth: number;
}

const ifCache = new WeakMap<Reader, IfStmt[]>();
/** Entry guards — `require.main === module`, `import.meta.url === …` — select a process, not a configuration. */
const MAIN_GUARD = /require\.main\s*===?\s*module|import\.meta\.(?:url|main|filename)|process\.argv\s*\[\s*1\s*\]|__name__\s*==\s*['"]__main__['"]/;

/** Every `if` statement of the file, read once, in source order. */
function ifStatements(r: Reader): IfStmt[] {
  const hit = ifCache.get(r);
  if (hit) return hit;
  const { src, ctx } = r;
  const raw: { at: number; open: number; close: number }[] = [];
  for (const m of src.matchAll(/\bif\s*\(/g)) {
    if (!ctx.isCode(m.index!)) continue;
    const open = m.index! + m[0].length - 1;
    const close = r.close(open);
    if (close > 0) raw.push({ at: m.index!, open, close });
    if (raw.length >= 20_000) break;
  }
  const fns = raw.map((x) => r.enclosing(x.at));
  const depthAt = braceDepths(src, ctx.mask, [...raw.map((x) => x.at), ...fns.filter((f): f is FnInfo => Boolean(f)).map((f) => f.bodyStart)]);
  const out: IfStmt[] = [];
  raw.forEach((x, i) => {
    const fn = fns[i]!;
    let j = x.close + 1;
    while (j < src.length && /\s/.test(src[j]!)) j++;
    const thenEnd = src[j] === '{' ? r.close(j) : statementEnd(r, j);
    if (thenEnd < 0) return;
    let k = thenEnd + 1;
    while (k < src.length && /\s/.test(src[k]!)) k++;
    let els: [number, number] | undefined;
    if (src.startsWith('else', k) && !/[\w$]/.test(src[k + 4] ?? '')) {
      let e = k + 4;
      while (e < src.length && /\s/.test(src[e]!)) e++;
      const elseEnd = src[e] === '{' ? r.close(e) : statementEnd(r, e);
      if (elseEnd > 0) els = [e, elseEnd];
    }
    const top = (depthAt.get(x.at) ?? 0) === (fn ? depthAt.get(fn.bodyStart) ?? 0 : 0);
    out.push({
      at: x.at,
      fn,
      expr: src.slice(x.open + 1, x.close).trim().replace(/\s+/g, ' ').slice(0, 160),
      exprFrom: x.open + 1,
      exprTo: x.close,
      then: [j, thenEnd],
      ...(els ? { else: els } : {}),
      exit: exitOf(r, j, thenEnd),
      top,
      depth: depthAt.get(x.at) ?? 0,
    });
  });
  ifCache.set(r, out);
  return out;
}

/** Does this consequent leave the function (or loop iteration) — anywhere at its own top level? */
function exitOf(r: Reader, from: number, to: number): IfStmt['exit'] {
  const { src } = r;
  if (src[from] !== '{') {
    const m = /^(return|throw|continue)\b/.exec(src.slice(from, from + 12));
    return m ? (m[1] as 'return' | 'throw' | 'continue') : false;
  }
  for (let i = from + 1; i < to; i++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = r.close(i);
      if (e < 0) return false;
      i = e;
      continue;
    }
    if (/[rtc]/.test(c) && !/[\w$.]/.test(src[i - 1] ?? '')) {
      const m = /^(return|throw|continue)\b/.exec(src.slice(i, i + 9));
      if (m) {
        // A direct statement of this block — not the consequent of a nested
        // braceless `if (x) continue;` (preceded by its `)`), nor an `else return`.
        let k = i - 1;
        while (k > from && /\s/.test(src[k]!)) k--;
        if (src[k] === '{' || src[k] === ';' || src[k] === '}') return m[1] as 'return' | 'throw' | 'continue';
      }
    }
  }
  return false;
}

function statementEnd(r: Reader, from: number): number {
  const { src, ctx } = r;
  // Bracket groups are stepped over through the file's bracket table, so a
  // braceless `if (a) f(() => { … })` costs one jump, not a scan of its body.
  let steps = 0;
  for (let i = from; i < src.length && steps < 4000; i++, steps++) {
    if (!ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const close = r.close(i);
      if (close < 0) return -1;
      i = close;
    } else if (c === ')' || c === ']' || c === '}') return i;
    else if (c === ';' || c === '\n') return i;
  }
  return -1;
}

/**
 * Not a configuration: `if (!server) throw …` validates an argument, and
 * `if (done) return; done = true;` makes a setup idempotent. Neither decides
 * which tools a configured server exposes.
 */
function isGuard(r: Reader, st: IfStmt): boolean {
  if (MAIN_GUARD.test(st.expr)) return true;
  const fn = st.fn;
  const id = /^!?\s*(?:this\.)?([A-Za-z_$][\w$]*)$|^([A-Za-z_$][\w$]*)\s*[=!]==?\s*(?:null|undefined)$|^typeof\s+([A-Za-z_$][\w$]*)\s*[=!]==?/.exec(st.expr);
  const name = id ? id[1] ?? id[2] ?? id[3] : undefined;
  if (!name) return false;
  if (st.exit === 'throw' && fn?.params.some((p) => p.name === name)) return true;
  if (st.exit === 'return' && !st.expr.startsWith('!')) {
    // `if (done) return;` … `done = true;` later in the same function.
    const after = r.src.slice(st.then[1], fn ? fn.bodyEnd : r.src.length);
    if (new RegExp(`(?<![\\w$.])(?:this\\.)?${name.replace(/[$]/g, '\\$')}\\s*=\\s*true\\b`).test(after)) return true;
  }
  return false;
}

const condMemo = new WeakMap<Reader, Map<string, RegistrationCondition | null>>();

function conditionAt(r: Reader, at: number, hop = 0): RegistrationCondition | undefined {
  let memo = condMemo.get(r);
  if (!memo) condMemo.set(r, (memo = new Map()));
  const key = `${at}:${hop}`;
  if (memo.has(key)) return memo.get(key) ?? undefined;
  const v = r.py ? pyCondition(r, at) : jsCondition(r, at, hop);
  memo.set(key, v ?? null);
  return v;
}

function jsCondition(r: Reader, at: number, hop: number): RegistrationCondition | undefined {
  const fn = r.enclosing(at);
  let found: RegistrationCondition | undefined;
  const all = ifStatements(r);
  // Binary search the first if at or after the function body.
  let lo = 0;
  let hi = all.length;
  const start = fn ? fn.bodyStart : 0;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (all[mid]!.at < start) lo = mid + 1;
    else hi = mid;
  }
  for (let k = lo; k < all.length; k++) {
    const st = all[k]!;
    if (st.at >= at) break;
    if (st.fn !== fn || isGuard(r, st)) continue;
    if (at >= st.then[0] && at <= st.then[1]) {
      found = { kind: 'if', expr: st.expr, line: r.ctx.line(st.at) };
      continue;
    }
    if (st.else && at >= st.else[0] && at <= st.else[1]) {
      found = { kind: 'else', expr: st.expr, line: r.ctx.line(st.at) };
      continue;
    }
    // An early exit at the function's top level gates everything after it.
    if ((st.exit === 'return' || st.exit === 'throw') && st.top && st.then[1] < at) found ??= { kind: 'unless', expr: st.expr, line: r.ctx.line(st.at) };
  }
  // `key && server.registerTool(…)`, `key ? server.registerTool(…) : null`.
  found ??= expressionCondition(r, at);
  if (found) return found;
  if (!fn) return undefined;
  // A callback (`TOOLS.forEach((t) => …)`, `ready.then(() => …)`) inherits the
  // conditions of the place it is passed from.
  if (!fn.name && hop < 4) return conditionAt(r, fn.headerStart, hop + 1);
  if (hop > 0 || !fn.name) return undefined;
  // One hop: a local function every same-file caller invokes behind ONE AND THE
  // SAME condition. An exported factory has callers elsewhere; callers in both
  // branches of an if/else cover every case.
  if (!r.fnNamed(fn.name) || r.ctx.escapes(fn.name)) return undefined;
  const calls = r.ctx.callSitesOf(fn.name);
  if (!calls.length || calls.length > 50) return undefined;
  const conds = calls.map((c) => conditionAt(r, c.index, hop + 1));
  if (!conds.every(Boolean)) return undefined;
  const first = conds[0]!;
  return conds.every((c) => c!.kind === first.kind && c!.expr === first.expr && c!.line === first.line) ? first : undefined;
}

/** A registration inside `X && …` or a ternary branch of the same statement. */
function expressionCondition(r: Reader, at: number): RegistrationCondition | undefined {
  const { src } = r;
  // Back to the start of the call expression (the receiver chain), then to the statement start.
  let i = at;
  // Back over the receiver chain — `this.server?.` included: `?.` is not a ternary.
  while (i > 0 && src[i - 1] !== '\n' && (/[\w$.\s]/.test(src[i - 1]!) || (src[i - 1] === '?' && src[i] === '.'))) i--;
  let j = i;
  let steps = 0;
  while (j > 0 && steps++ < 400) {
    const c = src[j - 1]!;
    if (r.ctx.isCode(j - 1) && (c === ';' || c === '{' || c === '}' || c === '\n')) break;
    if (r.ctx.isCode(j - 1) && (c === ')' || c === ']')) {
      // Step over a bracketed group backwards cheaply: give up on deep nesting.
      break;
    }
    j--;
  }
  const prefix = src.slice(j, i).trim();
  if (!prefix || prefix.length > 300) return undefined;
  const and = /^(?:return\s+|await\s+)?(.{1,200}?)\s*&&\s*(?:await\s+)?$/.exec(prefix);
  if (and) return { kind: 'if', expr: and[1]!.trim(), line: r.ctx.line(j) };
  const thenBranch = /^(?:return\s+|await\s+)?([^?]{1,200}?)\s*\?\s*(?:await\s+)?$/.exec(prefix);
  if (thenBranch) return { kind: 'if', expr: thenBranch[1]!.trim(), line: r.ctx.line(j) };
  const elseBranch = /^(?:return\s+|await\s+)?([^?]{1,200}?)\s*\?[^:]{0,400}:\s*(?:await\s+)?$/.exec(prefix);
  if (elseBranch) return { kind: 'else', expr: elseBranch[1]!.trim(), line: r.ctx.line(j) };
  return undefined;
}

function pyCondition(r: Reader, at: number): RegistrationCondition | undefined {
  const { src, ctx } = r;
  const lineStart = src.lastIndexOf('\n', at - 1) + 1;
  let indent = /^[ \t]*/.exec(src.slice(lineStart))![0].length;
  let pos = lineStart - 1;
  const fn = ctx.enclosingFn(at);
  const floor = fn ? fn.bodyStart : 0;
  while (pos > floor && indent > 0) {
    const ls = src.lastIndexOf('\n', pos - 1) + 1;
    const line = src.slice(ls, pos);
    pos = ls - 1;
    if (!line.trim() || !ctx.isCode(ls + line.length - line.trimStart().length)) continue;
    const ind = line.length - line.trimStart().length;
    if (ind >= indent) continue;
    indent = ind;
    const m = /^[ \t]*(if|elif)[ \t]+(\S[^\n]*):[ \t]*$/.exec(line);
    if (m) {
      if (MAIN_GUARD.test(m[2]!)) return undefined;
      return { kind: 'if', expr: m[2]!.trim().slice(0, 160), line: ctx.line(ls) };
    }
    if (/^[ \t]*else[ \t]*:[ \t]*$/.test(line)) {
      // The else belongs to the nearest `if` above at the same indentation.
      const head = pyIfAbove(r, ls, ind);
      return head ? { kind: 'else', expr: head.expr, line: head.line } : undefined;
    }
  }
  // An early exit at the TOP LEVEL of the enclosing function — `if not KEY:`
  // followed by a block that returns or raises (after a log line, too) — not
  // one inside a nested def (the body of the tool registered just above).
  if (fn) {
    const body = src.slice(fn.bodyStart, at);
    const bodyIndent = /^(?:[ \t]*\n)*([ \t]+)\S/.exec(body)?.[1];
    if (bodyIndent) {
      const re = /^([ \t]+)if[ \t]+(\S[^\n]*):[ \t]*$/gm;
      let m: RegExpExecArray | null;
      while ((m = re.exec(body))) {
        if (m[1] !== bodyIndent || !ctx.isCode(fn.bodyStart + m.index + m[1].length)) continue;
        const after = body.slice(m.index + m[0].length + 1);
        const block = /^((?:[ \t]*\n|[ \t]+\S[^\n]*\n?){1,40})/.exec(after)?.[1] ?? '';
        const lines = block.split('\n').filter((l) => l.trim());
        const inner = lines.filter((l) => l.length - l.trimStart().length > bodyIndent.length);
        const leaves = inner.some((l) => /^\s*(?:return|raise)\b/.test(l));
        const isArgGuard = /^not\s+[A-Za-z_]\w*$/.test(m[2]!.trim()) && inner.every((l) => !/^\s*return\b/.test(l)) && fn.params.some((p) => p.name === m![2]!.trim().slice(4));
        if (leaves && !isArgGuard && !MAIN_GUARD.test(m[2]!)) return { kind: 'unless', expr: m[2]!.trim().slice(0, 160), line: ctx.line(fn.bodyStart + m.index) };
      }
    }
  }
  return undefined;
}

function pyIfAbove(r: Reader, from: number, indent: number): { expr: string; line: number } | undefined {
  const { src, ctx } = r;
  let pos = from - 1;
  for (let k = 0; k < 2000 && pos > 0; k++) {
    const ls = src.lastIndexOf('\n', pos - 1) + 1;
    const line = src.slice(ls, pos);
    pos = ls - 1;
    if (!line.trim()) continue;
    const ind = line.length - line.trimStart().length;
    if (ind < indent) return undefined;
    if (ind > indent) continue;
    const m = /^[ \t]*if[ \t]+(\S[^\n]*):[ \t]*$/.exec(line);
    if (m) return { expr: m[1]!.trim().slice(0, 160), line: ctx.line(ls) };
    if (!/^[ \t]*elif\b/.test(line)) return undefined;
  }
  return undefined;
}

/** Two conditions on one tool that together always hold (the if and the else of one statement). */
function complementary(a: RegistrationCondition, b: RegistrationCondition): boolean {
  return a.line === b.line && a.expr === b.expr && ((a.kind === 'else') !== (b.kind === 'else'));
}

// --- handler behaviour --------------------------------------------------------

/** Receivers that are an HTTP client by name. */
const HTTP_CLIENT = /^(?:axios|got|ky|superagent|request|http|https|api|apiClient|client|httpClient|rest|restClient|fetcher|session|requests|httpx|aiohttp|instance|\$http|ofetch|undici)$/i;
/** Receivers that are never HTTP: collections, headers, KV bindings, routers. */
const NOT_HTTP = /^(?:map|set|weakmap|weakset|cache|caches|store|storage|localstorage|sessionstorage|headers|params|searchparams|query|formdata|cookies|kv|redis|router|routes|route|app|server|express|fastify|hono|koa|registry|emitter|events|listeners|subscribers|queue|seen|visited|pending|state|data|items|list|index|tree|graph)$/i;
/** A POST that only asks a question — GraphQL, a search endpoint. Read only from the URL argument. */
const READ_ONLY_POST = /graphql|search|query|lookup/i;
/**
 * …or one whose last path segment is a read verb under a resource —
 * `/jobs/list`, `/attempt/get_for_job`, `/v1/describeStacks` — or that names an
 * Ethereum getter as its `method=` query parameter. Case-sensitive: `/getaway`
 * is not `get`. The segment before the verb must be a path segment, not the
 * host (`https://collector.example.net/get` asks nothing), and whatever follows
 * the verb must not name a write (`/get_or_create`, `/listAndDelete`).
 */
const READ_PATH =
  /(?<=[^/:]\/[A-Za-z_$][\w$-]{0,60})\/(?:get|list|read|search|query|describe)((?:[A-Z_.-][\w.-]{0,80})?)\/?(?=[?#'"`]|$)|[?&]method=eth_get[A-Z]/;
/** A word that makes a read-verb path or method name a write: `get_or_create`, `listAndDelete`, `read_and_update`. */
const WRITE_WORD =
  /^(?:create|update|delete|remove|destroy|set|put|write|send|save|insert|upsert|post|patch|modify|edit|exec|execute|run|transfer|mint|burn|approve|sign|submit|add|clear|reset|drop|purge|or|and)$/;
/** Does a name tail (`_or_create`, `AndDelete`, `ForJob`) carry a write word? */
function namesWrite(tail: string): boolean {
  return tail
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .some((w) => WRITE_WORD.test(w));
}
/** JSON-RPC methods that only read: Ethereum's getters and calls… */
const READ_ETH_METHOD = /^(?:eth_(?:get[A-Z]\w*|call|blockNumber|chainId|estimateGas|gasPrice|feeHistory|maxPriorityFeePerGas|syncing|accounts|protocolVersion)|net_\w+|web3_clientVersion)$/;
/** …and, in a request that is JSON-RPC by its URL or body, any `get…`/`list…` method (`getBalance`) that names no write (`getOrCreateAccount`). */
const READ_RPC_METHOD = /^(?:get|list|read|search|query|describe)([A-Z_]\w*)$/;
const HTTP_VERB = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i;
/**
 * A body that carries the environment, a file read or a secret is a delivery,
 * whatever the endpoint is called: `axios.post('…/get', { env: process.env })`.
 */
const CARRIES_SECRET =
  /\bprocess\.env\b|\bos\.environ\b|\bgetenv\s*\(|\breadFile(?:Sync)?\s*\(|\bsecret|\bpassword|\bpasswd|\bprivate_?key|\bcredential/i;
/** A value read from the filesystem, the environment, the OS or a command's output. */
const LOCAL_DATA =
  /\bprocess\.env\b|\bos\.environ\b|\bgetenv\s*\(|\b(?:readFile(?:Sync)?|createReadStream|readdirSync|execSync|execFileSync|spawnSync|check_output|getoutput)\s*\(|\bos\.(?:userInfo|hostname|networkInterfaces)\s*\(|\bopen\s*\([^()\n]{0,200}\)\s*\.\s*read(?:lines)?\s*\(|\.\s*read_(?:text|bytes)\s*\(/;
/** …of which everything but the environment: a header may carry an API key from the environment, never a file. */
const FILE_DATA =
  /\b(?:readFile(?:Sync)?|createReadStream|readdirSync|execSync|execFileSync|spawnSync|check_output|getoutput)\s*\(|\bos\.(?:userInfo|hostname|networkInterfaces)\s*\(|\bopen\s*\([^()\n]{0,200}\)\s*\.\s*read(?:lines)?\s*\(|\.\s*read_(?:text|bytes)\s*\(/;
/**
 * The whole environment rather than one variable of it — `JSON.stringify(process.env)`,
 * `{ ...process.env }`, `os.environ.copy()`. No header carries that to authenticate.
 */
const WHOLE_ENV = /\bprocess\s*(?:\.\s*env|\[\s*['"]env['"]\s*\])(?!\s*(?:\??\.\s*[A-Za-z_$]|\[))|\bos\s*\.\s*environ(?!\s*(?:\[|\.\s*get\s*\())/;
/** Request options that configure the transport, not what is sent: timeouts, TLS, redirects. */
const TRANSPORT_KEY =
  /^(?:cert|verify|timeout|allow_redirects|follow_redirects|stream|signal|httpsAgent|httpAgent|agent|withCredentials|responseType|validateStatus|maxRedirects|retry|throwHttpErrors|credentials|mode|cache|redirect|keepalive)$/;
/**
 * The options that authenticate the request or route it: `auth=(user, pw)`,
 * axios `{ auth: { username, password } }`, `{ proxy: { host, auth } }`. They
 * leave the machine with the request, so they are read like the headers: the
 * API's (or the proxy's) own credentials from the environment, never a file, a
 * command's output or the whole environment.
 */
const CREDENTIAL_KEY = /^(?:auth|proxy|proxies)$/;
/** The option keys and keywords that carry the payload: `body:`, `data:`, `json=`, `files=`. */
const BODY_KEY = /^(?:body|data|json|json_body|content|files|form|formData)$/;
/** A header that authenticates the request: the API key read from the environment for the API being asked. */
const AUTH_HEADER = /auth|token|api[-_]?key|apikey|secret|cookie|session|bearer|signature|subscription|^x-key$/i;
/** A name in a value: not a property (`x.toString`), not a key (`c:`), not inside a string. */
const VALUE_NAME = /(?<![\w$.'"`])[A-Za-z_$][\w$]*(?![\w$]|\s*:(?!:)|['"`])/g;
/** One assignment: `name = …`, `const name: T = …` (a chain `a = b = c` is read link by link). */
const ASSIGNMENT = /(?:^|[^\w$.])([A-Za-z_$][\w$]*)\s*(?::[^=\n;{}()]{1,80})?=(?![=>])\s*([^;\n]{0,400})/g;
const DESTRUCTURE = /[{[]([^{}[\]=\n]{0,400})[}\]]\s*=\s*([^;\n]{0,400})/g;
/** A name bound to a file by the language: `with open(p) as f`, `fs.readFile(p, (err, data) => …)`, `readFile(p).then((data) => …)`. */
const FILE_BINDING =
  /\bwith\s+open\s*\([^()\n]{0,200}\)\s+as\s+([A-Za-z_]\w*)|\b(?:readFile|createReadStream|readdir|exec|execFile)\s*\([^()\n]{0,200}?,\s*(?:async\s*)?(?:function\s*[\w$]*\s*)?\(\s*[A-Za-z_$][\w$]*\s*,\s*([A-Za-z_$][\w$]*)|\breadFile\s*\([^()\n]{0,200}\)\s*\.\s*then\s*\(\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)/g;
/**
 * A write INTO a name after it was assigned — `p.env = …`, `p['k'] = …`,
 * `parts.push(…)`, `payload.update(…)`, `Object.assign(p, …)`: its initializer
 * no longer says all it holds, so what is written in is judged too. The name
 * starts at a boundary, so a long identifier is read once.
 */
const MUTATION =
  /(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\??\.\s*[A-Za-z_$][\w$]*|\[[^\]\n]{0,80}\]){0,3}\s*(?:(?:\??\.\s*[A-Za-z_$][\w$]*|\[[^\]\n]{0,80}\])\s*=(?![=>])|\??\.\s*(?:push|unshift|splice|set|append|extend|insert|update|setdefault|add|put|fill)\s*\()|\bObject\s*\.\s*assign\s*\(\s*([A-Za-z_$][\w$]*)/g;
/** …and an augmented assignment, which adds to what the name held: `query += JSON.stringify(process.env)`, `name += open(p).read()`, `args.note += secret`. */
const AUGMENTED =
  /(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*(?:\??\.\s*[A-Za-z_$][\w$]*|\[[^\]\n]{0,80}\])){0,4}\s*(?:\*\*|\/\/|<<|>>>?|\|\||&&|\?\?|[-+*/%&|^@])=(?![=>])/g;

interface Assigned {
  at: number;
  rhs: string;
  /** Where the right-hand side starts in the file. */
  rhsAt: number;
  /** Bound to a file by the language itself (see `FILE_BINDING`). */
  file?: boolean;
}
const bodyIndexMemo = new WeakMap<Reader, Map<number, Map<string, Assigned[]>>>();
const MAX_ASSIGNMENTS = 50_000;

/**
 * Every assignment in the function body [from, to), by name, in source order —
 * read once per body. A body padded with thousands of requests is still read
 * whole: the variable a sink sends may be set anywhere before it, not only in
 * the few kilobytes next to the call.
 */
function bodyIndex(r: Reader, from: number, to: number): Map<string, Assigned[]> {
  let memo = bodyIndexMemo.get(r);
  if (!memo) bodyIndexMemo.set(r, (memo = new Map()));
  const hit = memo.get(from);
  if (hit) return hit;
  const index = new Map<string, Assigned[]>();
  let count = 0;
  const add = (name: string, at: number, rhs: string, rhsAt: number, file?: boolean): void => {
    if (++count > MAX_ASSIGNMENTS) return;
    const list = index.get(name) ?? [];
    list.push({ at, rhs, rhsAt, ...(file ? { file } : {}) });
    index.set(name, list);
  };
  const src = r.src.slice(from, to);
  const re = new RegExp(ASSIGNMENT.source, 'g');
  let m: RegExpExecArray | null;
  // Only code assigns: `params = { "job_id": 1 }` in a docstring's example
  // does not change what `params` holds.
  while ((m = re.exec(src)) && count <= MAX_ASSIGNMENTS) {
    const rhsAt = m.index + m[0].length - m[2]!.length;
    if (r.ctx.isCode(from + m.index + m[0].indexOf(m[1]!))) add(m[1]!, from + m.index, m[2]!, from + rhsAt);
    // Continue at the right-hand side, so `a = b = c` also records `b`.
    re.lastIndex = rhsAt > m.index ? rhsAt : m.index + 1;
  }
  for (const d of src.matchAll(DESTRUCTURE)) {
    if (count > MAX_ASSIGNMENTS) break;
    if (!r.ctx.isCode(from + d.index!)) continue;
    const rhsAt = from + d.index! + d[0].length - d[2]!.length;
    // The name follows a boundary directly (a lookbehind, not a consumed `\s*`), so a run of spaces is read once.
    for (const n of d[1]!.matchAll(/(?<=^|[,{\s])(?:\.\.\.)?([A-Za-z_$][\w$]*)\s*(?=[,}\]=]|$)/g)) add(n[1]!, from + d.index!, d[2]!, rhsAt);
  }
  for (const f of src.matchAll(FILE_BINDING)) {
    if (count > MAX_ASSIGNMENTS) break;
    if (!r.ctx.isCode(from + f.index!)) continue;
    add((f[1] ?? f[2] ?? f[3])!, from + f.index!, f[0], from + f.index!, true);
  }
  for (const list of index.values()) list.sort((x, y) => x.at - y.at);
  memo.set(from, index);
  return index;
}

/** The last assignment of `name` before `at`. */
function assignedBefore(index: Map<string, Assigned[]>, name: string, at: number): Assigned | undefined {
  const list = index.get(name);
  if (!list) return undefined;
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid]!.at < at) lo = mid + 1;
    else hi = mid;
  }
  return lo > 0 ? list[lo - 1] : undefined;
}

/**
 * Does `text` carry a value of `kind` (local data, file data, or the whole
 * environment) — written in it, or through the names it uses, and the names
 * those were computed from, two links deep: `const raw = fs.readFileSync(p);
 * const enc = Buffer.from(raw).toString('base64'); post(…, { enc })`. Bounded:
 * 24 names per link.
 */
function carries(index: Map<string, Assigned[]>, text: string, kind: RegExp, at: number, depth: number): boolean {
  if (kind.test(text)) return true;
  if (depth === 0) return false;
  let n = 0;
  for (const m of text.matchAll(VALUE_NAME)) {
    if (++n > 24) break;
    const a = assignedBefore(index, m[0], at);
    if (a && assignmentCarries(index, a, kind, depth - 1)) return true;
  }
  return false;
}

const carryMemo = new WeakMap<Assigned, Map<string, boolean>>();
/** One key per kind of value `carries` looks for: the memo of one kind is never read for another. */
const kindIds = new WeakMap<RegExp, number>();
let nextKindId = 0;
function kindKey(kind: RegExp): number {
  let id = kindIds.get(kind);
  if (id === undefined) kindIds.set(kind, (id = nextKindId++));
  return id;
}

/**
 * Does one assignment's value carry `kind`, `depth` links further? Memoised per
 * assignment: two thousand requests sending the same thirty names follow each
 * name once, not once per request.
 */
function assignmentCarries(index: Map<string, Assigned[]>, a: Assigned, kind: RegExp, depth: number): boolean {
  if (a.file) return true;
  const key = `${kindKey(kind)}:${depth}`;
  let memo = carryMemo.get(a);
  if (!memo) carryMemo.set(a, (memo = new Map()));
  const hit = memo.get(key);
  if (hit !== undefined) return hit;
  memo.set(key, false); // a name defined through itself carries nothing new
  const v = carries(index, a.rhs, kind, a.at, depth);
  memo.set(key, v);
  return v;
}

// --- positive evidence: a payload known to carry nothing local ----------------------
// A POST to a read-looking endpoint (`/jobs/list`, a JSON-RPC getter, a SELECT)
// is a read only when what it sends is PROVEN harmless: nothing, literals, the
// tool's own arguments (`args.id`, a destructured parameter, a Python
// parameter) and pure conversions of them, followed through local names two
// links deep. An unknown name, a file or environment read, a derived value
// more than two links away, a spread, an object written into after it was
// built — none of that is known to be harmless, and the POST stays a sink.

/** What a payload may name and still carry nothing the tool did not receive: literals, keywords, pure conversions. */
const PURE_NAME = new Set([
  'true', 'false', 'null', 'undefined', 'NaN', 'Infinity', 'None', 'True', 'False',
  'JSON', 'String', 'Number', 'Boolean', 'BigInt', 'Math', 'Date', 'Array', 'Object', 'parseInt', 'parseFloat',
  'encodeURIComponent', 'encodeURI', 'URL', 'URLSearchParams', 'str', 'int', 'float', 'bool', 'len', 'list', 'dict', 'tuple', 'json',
  'await', 'new', 'typeof', 'void', 'in', 'of', 'instanceof', 'as', 'satisfies', 'and', 'or', 'not', 'is', 'if', 'else', 'for',
  'lambda', 'async',
]);
/** A schema validating the tool's arguments returns them: `Input.parse(args)`, `Model.model_validate(args)`. */
const VALIDATES = /^\s*\??\.\s*(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|cast|model_validate|parse_obj)\s*\(/;
/** Callback and comprehension variables: they range over a value that is judged on its own. */
const BOUND_NAMES =
  /\(\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*){0,5})\s*\)\s*=>|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=>|\bfor\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*){0,5})\s+in\b|\blambda\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*){0,5})\s*:/g;

/** A write into a name: where it is, and where the value written starts (or the `(` of the call that writes it). */
interface Write {
  at: number;
  value: number;
  call: boolean;
  /** `Object.assign(p, …)`: the first argument is the target, not a value. */
  target?: boolean;
}
interface Proof {
  r: Reader;
  index: Map<string, Assigned[]>;
  /** Where each name is written into (see `MUTATION`), in source order. */
  mutations: Map<string, Write[]>;
  /** The function's own parameters and the keys destructured from them. */
  inputs: Set<string>;
  /** The default each of them takes when the caller passes nothing (`{ name = process.env.SECRET }`). */
  defaults: Map<string, [number, number]>;
  /** Whether that default is harmless, once judged. */
  defaultOk: Map<string, boolean>;
}
const proofMemo = new WeakMap<Reader, Map<number, Proof>>();

/** The evidence for the function whose body is [from, to) — built once per body. */
function proofOf(r: Reader, from: number, to: number): Proof {
  let memo = proofMemo.get(r);
  if (!memo) proofMemo.set(r, (memo = new Map()));
  const hit = memo.get(from);
  if (hit) return hit;
  const inputs = new Set<string>();
  const defaults = new Map<string, [number, number]>();
  const fn = r.ctx.functions().find((f) => f.bodyStart === from);
  for (const p of fn ? r.params(fn) : []) {
    if (p.name) inputs.add(p.name);
    if (p.name && p.dflt) defaults.set(p.name, p.dflt);
    for (const k of p.keys ?? []) {
      inputs.add(k.local);
      if (k.dflt) defaults.set(k.local, k.dflt);
    }
    if (p.restKey) inputs.add(p.restKey);
    for (const it of p.items ?? []) if (it) inputs.add(it);
  }
  const mutations = new Map<string, Write[]>();
  const body = r.src.slice(from, to);
  let n = 0;
  const add = (name: string, write: Write): void => {
    const list = mutations.get(name) ?? [];
    list.push(write);
    mutations.set(name, list);
  };
  for (const m of body.matchAll(MUTATION)) {
    if (++n > MAX_ASSIGNMENTS) break;
    const at = from + m.index!;
    if (!r.ctx.isCode(at)) continue;
    const end = at + m[0].length;
    add((m[1] ?? m[2])!, m[0].endsWith('=') ? { at, value: end, call: false } : m[2] ? { at, value: at + m[0].indexOf('('), call: true, target: true } : { at, value: end - 1, call: true });
  }
  for (const m of body.matchAll(AUGMENTED)) {
    if (++n > MAX_ASSIGNMENTS) break;
    if (!r.ctx.isCode(from + m.index!)) continue;
    add(m[1]!, { at: from + m.index!, value: from + m.index! + m[0].length, call: false });
  }
  for (const list of mutations.values()) list.sort((x, y) => x.at - y.at);
  // One hop of aliasing: a local assigned an argument itself (`const a = args`)
  // writes into the argument when it is written into — `a.name = …`,
  // `Object.assign(a, …)`, `a.note += …` — from that assignment to its next.
  // An alias of an alias is not followed. Both lists are in source order, so
  // each write is looked at once.
  const index = bodyIndex(r, from, to);
  let aliased = false;
  for (const [alias, writes] of [...mutations]) {
    const list = inputs.has(alias) ? undefined : index.get(alias);
    if (!list) continue;
    let w = 0;
    for (let k = 0; k < list.length; k++) {
      const a = list[k]!;
      const until = list[k + 1]?.at ?? Infinity;
      const opener = r.src[a.at];
      // A destructuring (`const { a } = args`) copies a key; it is no alias.
      const target = a.file || opener === '{' || opener === '[' ? undefined : /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(a.rhs)?.[1];
      while (w < writes.length && writes[w]!.at <= a.at) w++;
      for (; w < writes.length && writes[w]!.at < until; w++) {
        if (target && target !== alias && inputs.has(target)) {
          add(target, writes[w]!);
          aliased = true;
        }
      }
    }
  }
  if (aliased) for (const list of mutations.values()) list.sort((x, y) => x.at - y.at);
  const proof: Proof = { r, index, mutations, inputs, defaults, defaultOk: new Map() };
  memo.set(from, proof);
  return proof;
}

/**
 * Is `name` written into somewhere in (after, before) with a value not known to
 * be harmless? `body["statuses"] = [params.status]` keeps a payload harmless;
 * `p.env = process.env` does not.
 */
function writtenBetween(p: Proof, name: string, after: number, before: number, depth: number): boolean {
  const list = p.mutations.get(name);
  if (!list) return false;
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid]!.at <= after) lo = mid + 1;
    else hi = mid;
  }
  for (let k = lo, seen = 0; k < list.length && list[k]!.at < before; k++) {
    // Past the last link, a write is not known to be harmless.
    if (++seen > 16 || depth <= 0) return true;
    if (!writeHarmless(p, list[k]!, depth)) return true;
  }
  return false;
}

const writeMemo = new WeakMap<Write, Map<number, boolean>>();

/** Is the value written by `w` harmless, `depth` links deep? Memoised per write: every later read of the name asks again. */
function writeHarmless(p: Proof, w: Write, depth: number): boolean {
  let memo = writeMemo.get(w);
  if (!memo) writeMemo.set(w, (memo = new Map()));
  const hit = memo.get(depth);
  if (hit !== undefined) return hit;
  memo.set(depth, false); // a write through itself proves nothing
  let value: string | null;
  if (w.call) {
    const close = p.r.close(w.value);
    const args = close > w.value ? splitTop(p.r.src.slice(w.value + 1, Math.min(close, w.value + 8000))) : null;
    value = args ? (w.target ? args.slice(1) : args).join(', ') : null;
  } else {
    value = exprAt(p.r, w.value);
  }
  const v = value !== null && harmless(value, p, w.at, depth - 1);
  memo.set(depth, v);
  return v;
}

/**
 * Is the tool's own argument `name` still what the caller passed when it is
 * read at `at`? Not when the function reassigned it (`name =
 * fs.readFileSync(…)`, `name = os.environ[…]`), added to it (`query +=
 * JSON.stringify(process.env)`), wrote into it (`args.extra = process.env`,
 * `Object.assign(args, …)`), or gave it a default that is not harmless (`{ name
 * = process.env.SECRET }`): then it is judged by what was put in it.
 */
function inputHarmless(p: Proof, name: string, at: number, depth: number): boolean {
  if (assignedBefore(p.index, name, at)) return nameHarmless(p, name, at, depth);
  if (writtenBetween(p, name, -1, at, depth)) return false;
  const d = p.defaults.get(name);
  if (!d) return true;
  let ok = p.defaultOk.get(name);
  if (ok === undefined) {
    p.defaultOk.set(name, false); // a default naming itself proves nothing
    ok = harmless(p.r.src.slice(d[0], d[1]), p, d[0], depth);
    p.defaultOk.set(name, ok);
  }
  return ok;
}

const helperMemo = new WeakMap<Reader, Map<string, boolean>>();
/**
 * A function of the same file that reads nothing local — no file, no
 * environment, no command (`_resolve_latest_job_id(connection_id)` asks the API
 * for an id): what it returns is computed from its arguments, which are judged
 * where it is called.
 */
function readsNothingLocal(r: Reader, name: string): boolean {
  let memo = helperMemo.get(r);
  if (!memo) helperMemo.set(r, (memo = new Map()));
  const hit = memo.get(name);
  if (hit !== undefined) return hit;
  const f = r.fnNamed(name);
  const body = f && f.kind !== 'method' && f.bodyEnd - f.bodyStart <= 50_000 ? r.src.slice(f.bodyStart, f.bodyEnd) : null;
  const v = body !== null && !LOCAL_DATA.test(body) && !CARRIES_SECRET.test(body) && !new RegExp(FILE_BINDING.source).test(body);
  memo.set(name, v);
  return v;
}

/**
 * The whole expression starting at `start`: an object or a call spread over
 * several lines is read to its closing bracket. Ends at `;`, at a line break or
 * at the enclosing bracket; null when it is empty or runs off the end.
 */
function exprAt(r: Reader, start: number): string | null {
  const { src } = r;
  let i = start;
  while (i < src.length && /\s/.test(src[i]!)) i++;
  const begin = i;
  const end = Math.min(src.length, begin + 20_000);
  for (; i < end; i++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = r.close(i);
      if (e < 0 || e >= end) return null;
      i = e;
    } else if (c === ';' || c === '\n' || c === ')' || c === ']' || c === '}' || c === ',') {
      break;
    }
  }
  return i > begin && i < end ? src.slice(begin, i) : null;
}

const harmlessMemo = new WeakMap<Assigned, Map<number, boolean>>();
const constMemo = new WeakMap<Proof, Map<string, Map<number, boolean>>>();
/** How many names one function body may prove harmless through the file's constants. */
const MAX_CONST_NAMES = 64;

/** A constant of the file: where its name and its initializer are, and the `{` of the block it lives in (-1 at the top level). */
interface FileConst {
  at: number;
  init: number;
  block: number;
}
const fileConstsMemo = new WeakMap<Reader, Map<string, FileConst | null>>();

/** The identifiers in a binding list: `{ a, b: c }`, `[x, , y]`, `k, v`. */
const IDENTS = /[A-Za-z_$][\w$]*/g;
const JS_DECL = /\b(const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]{1,200}?)?=(?![=>])/g;
/** Every other way a JavaScript name is bound: a loop head, a catch clause, a destructuring, a bare `let`, an assignment, `++`. */
const JS_BINDINGS: RegExp[] = [
  /\bfor\s*\(\s*(?:const|let|var)?\s*([^;)]{1,200}?)\s+(?:of|in)\b/g,
  /\bcatch\s*\(\s*([^)]{1,200})\)/g,
  /\b(?:const|let|var)\s*([{[][^=;]{0,400}[}\]])\s*=/g,
  /[[{]([^=;[\]{}()]{0,200})[\]}]\s*=(?![=>])/g,
  /\b(?:let|var)\s+([A-Za-z_$][\w$]*)\s*[;,\n]/g,
  /(?:\+\+|--)\s*([A-Za-z_$][\w$]*)|(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\+\+|--)/g,
];
const JS_ASSIGNED = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\*\*|<<|>>>?|\|\||&&|\?\?|[-+*/%&|^])?=(?![=>])/g;
const PY_DECL = /^([A-Za-z_]\w*)\s*(?::[^=\n]{1,80})?=(?!=)/gm;
/**
 * …and a Python one: inside a function, by a loop, `as`, `global`, a lambda, a
 * walrus, a tuple target, an augmented assignment. Every name starts at a
 * boundary: the walrus pattern had none, and restarted at each position of a
 * long name or hex literal — a 495 KB server.py took 104 s on Node 20.
 */
const PY_BINDINGS: RegExp[] = [
  /^[ \t]+([A-Za-z_]\w*)\s*(?::[^=\n]{1,80})?=(?!=)/gm,
  /^[ \t]*([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)+)[ \t]*=(?!=)/gm,
  /\bfor\s+([^\n:]{1,200}?)\s+in\b/g,
  /\bas\s+([A-Za-z_]\w*)/g,
  /\b(?:global|nonlocal)\s+([^\n]{1,200})/g,
  /\blambda\s+([^:\n]{1,100}):/g,
  /(?<!\w)([A-Za-z_]\w*)\s*:=/g,
  /(?<![\w.])([A-Za-z_]\w*)\s*(?:\*\*|\/\/|<<|>>|[-+*/%&|^@])=/g,
];

/**
 * The file's constants by name, found in one pass over it: a `const` (or, in
 * Python, a top-level assignment) declared once, and bound nowhere else in the
 * file — not as a parameter, a loop variable, a destructured name or an
 * assignment target. Which value a name has where it is used is then known
 * without reading the file again: a body sending a thousand constants looks each
 * one up here. A name declared twice or bound elsewhere is null.
 */
function fileConsts(r: Reader): Map<string, FileConst | null> {
  const hit = fileConstsMemo.get(r);
  if (hit) return hit;
  const { src, ctx } = r;
  const out = new Map<string, FileConst | null>();
  const decls: { name: string; at: number; init: number; ok: boolean }[] = [];
  const bound = new Set<string>();
  const bindAll = (text: string): void => {
    for (const n of text.matchAll(IDENTS)) bound.add(n[0]);
  };
  if (r.py) {
    for (const m of src.matchAll(PY_DECL)) if (ctx.isCode(m.index!)) decls.push({ name: m[1]!, at: m.index!, init: m.index! + m[0].length, ok: true });
    for (const re of PY_BINDINGS) for (const m of src.matchAll(re)) if (ctx.isCode(m.index!)) bindAll(m[1]!);
  } else {
    const re = new RegExp(JS_DECL.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      const nameAt = m.index + m[0].indexOf(m[2]!, m[1]!.length);
      if (ctx.isCode(m.index)) decls.push({ name: m[2]!, at: nameAt, init: m.index + m[0].length, ok: m[1] === 'const' });
      re.lastIndex = nameAt + 1; // a declaration inside another one's type annotation is read too
    }
    for (const b of JS_BINDINGS) for (const x of src.matchAll(b)) if (ctx.isCode(x.index!)) bindAll(x[1] ?? x[2] ?? '');
    const own = new Set(decls.map((d) => d.at));
    for (const x of src.matchAll(JS_ASSIGNED)) {
      const at = x.index! + x[0].indexOf(x[1]!);
      if (ctx.isCode(at) && !own.has(at)) bound.add(x[1]!);
    }
  }
  for (const fn of ctx.functions()) {
    for (const p of fn.params) {
      bound.add(p.name);
      for (const local of p.keys?.values() ?? []) bound.add(local);
    }
  }
  // The block each declaration lives in: the innermost `{` open at it, in one pass.
  const stack: number[] = [];
  let k = 0;
  const blocks = new Map<number, number>();
  for (let i = 0; i <= src.length && k < decls.length; i++) {
    while (k < decls.length && decls[k]!.at === i) blocks.set(decls[k++]!.at, r.py ? -1 : (stack[stack.length - 1] ?? -1));
    if (r.py || i === src.length || !ctx.isCode(i)) continue;
    if (src[i] === '{') stack.push(i);
    else if (src[i] === '}') stack.pop();
  }
  for (const d of decls) {
    const ok = d.ok && !out.has(d.name) && !bound.has(d.name);
    out.set(d.name, ok ? { at: d.at, init: d.init, block: blocks.get(d.at) ?? -1 } : null);
  }
  fileConstsMemo.set(r, out);
  return out;
}

/** Is the local (or file constant) `name`, as it stands at `at`, harmless `depth` links deep? */
function nameHarmless(p: Proof, name: string, at: number, depth: number): boolean {
  if (depth <= 0) return false;
  const a = assignedBefore(p.index, name, at);
  if (a) {
    if (a.file || writtenBetween(p, name, a.at, at, depth)) return false;
    let memo = harmlessMemo.get(a);
    if (!memo) harmlessMemo.set(a, (memo = new Map()));
    const hit = memo.get(depth);
    if (hit !== undefined) return hit;
    memo.set(depth, false); // a name defined through itself proves nothing
    const rhs = exprAt(p.r, a.rhsAt);
    const v = rhs !== null && harmless(rhs, p, a.at, depth - 1);
    memo.set(depth, v);
    return v;
  }
  // A constant of the file (`const API_VERSION = '2024-01'`), never an import.
  if (p.r.imported(name)) return false;
  let names = constMemo.get(p);
  if (!names) constMemo.set(p, (names = new Map()));
  let memo = names.get(name);
  if (!memo) {
    // A payload naming more constants than any client does proves nothing.
    if (names.size >= MAX_CONST_NAMES) return false;
    names.set(name, (memo = new Map()));
  }
  const hit = memo.get(depth);
  if (hit !== undefined) return hit;
  memo.set(depth, false);
  const c = fileConsts(p.r).get(name);
  const visible = c && (c.block < 0 || (at > c.block && at < p.r.close(c.block)));
  const init = visible ? exprAt(p.r, c.init) : null;
  const v = init !== null && harmless(init, p, c!.at, depth - 1);
  memo.set(depth, v);
  return v;
}

/**
 * The end of the string literal opening at `q`, or -1. A template's `${…}` and
 * an f-string's `{…}` are handed to `inner`, which judges what they interpolate.
 */
function stringEnd(s: string, q: number, to: number, fstring: boolean, inner: (a: number, b: number) => boolean, nest = 0): number {
  if (nest > 16) return -1;
  const quote = s[q]!;
  const triple = quote !== '`' && s.startsWith(quote.repeat(3), q);
  for (let j = q + (triple ? 3 : 1); j < to; j++) {
    const c = s[j]!;
    if (c === '\\') {
      j++;
      continue;
    }
    const tpl = quote === '`' && c === '$' && s[j + 1] === '{';
    if (tpl || (fstring && c === '{')) {
      if (!tpl && s[j + 1] === '{') {
        j++; // `{{` is a literal brace
        continue;
      }
      const open = tpl ? j + 1 : j;
      const close = braceEnd(s, open, to, nest + 1);
      if (close < 0 || !inner(open + 1, close)) return -1;
      j = close;
      continue;
    }
    if (triple ? s.startsWith(quote.repeat(3), j) : c === quote) return j + (triple ? 3 : 1);
    if (c === '\n' && quote !== '`' && !triple) return -1;
  }
  return -1;
}

/** The `}` that closes the `{` at `open` within [open, to), strings skipped; -1 when there is none. */
function braceEnd(s: string, open: number, to: number, nest: number): number {
  if (nest > 16) return -1;
  let depth = 0;
  for (let j = open; j < to; j++) {
    const c = s[j]!;
    if (c === '"' || c === "'" || c === '`') {
      const e = stringEnd(s, j, to, false, () => true, nest + 1);
      if (e < 0) return -1;
      j = e - 1;
    } else if (c === '{') {
      depth++;
    } else if (c === '}' && --depth === 0) {
      return j;
    }
  }
  return -1;
}

/**
 * Is `expr` built only from literals, the function's own arguments, pure
 * conversions of them and locals that are themselves harmless (`depth` links)?
 */
function harmless(expr: string, p: Proof, at: number, depth: number): boolean {
  if (expr.length > 8000) return false;
  const bound = new Set<string>();
  let k = 0;
  for (const m of expr.matchAll(BOUND_NAMES)) {
    if (++k > 32) return false;
    for (const n of (m[1] ?? m[2] ?? m[3] ?? m[4] ?? '').split(',')) bound.add(n.trim());
  }
  return harmlessIn(expr, 0, expr.length, p, at, depth, bound, 0);
}

function harmlessIn(s: string, from: number, to: number, p: Proof, at: number, depth: number, bound: Set<string>, nest: number): boolean {
  if (nest > 16) return false;
  const inner = (a: number, b: number): boolean => harmlessIn(s, a, b, p, at, depth, bound, nest + 1);
  let prev = ''; // the last significant character
  let prevWord = '';
  for (let i = from; i < to; ) {
    const c = s[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    // A string — with its Python prefix (`f"…{x}…"`, `rb'…'`) — or a template.
    let q = c === '"' || c === "'" || c === '`' ? i : -1;
    let fstring = false;
    if (q < 0 && /[rRbBuUfF]/.test(c) && !/[\w$]/.test(s[i - 1] ?? '')) {
      const pre = /^[rRbBuUfF]{1,2}(?=["'])/.exec(s.slice(i, i + 3));
      if (pre) {
        q = i + pre[0].length;
        fstring = /f/i.test(pre[0]);
      }
    }
    if (q >= 0) {
      const end = stringEnd(s, q, to, fstring, inner);
      if (end < 0) return false;
      i = end;
      prev = 'v';
      prevWord = '';
      continue;
    }
    if (c === '.' && s.startsWith('...', i)) return false; // a spread: of what, is not known
    if (c === '*' && s[i + 1] === '*' && (prev === '' || prev === '(' || prev === ',' || prev === '{')) return false; // `**kwargs`
    if (/[0-9]/.test(c)) {
      while (i < to && /[\w.]/.test(s[i]!)) i++;
      prev = 'v';
      prevWord = '';
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < to && /[\w$]/.test(s[j]!)) j++;
      const name = s.slice(i, j);
      const after = s.slice(j, Math.min(to, j + 40));
      const ok =
        prev === '.' || // a property
        ((prev === '{' || prev === ',') && /^\s*:(?!:)/.test(after)) || // an object key
        ((prev === '(' || prev === ',') && /^\s*=(?![=>])/.test(after)) || // a keyword argument
        prevWord === 'as' ||
        prevWord === 'satisfies' || // a type
        PURE_NAME.has(name) ||
        (p.inputs.has(name) && inputHarmless(p, name, at, depth)) ||
        bound.has(name) ||
        VALIDATES.test(after) ||
        (/^\s*\(/.test(after) && readsNothingLocal(p.r, name)) ||
        nameHarmless(p, name, at, depth);
      if (!ok) return false;
      i = j;
      prev = 'v';
      prevWord = name;
      continue;
    }
    prev = c;
    prevWord = '';
    i++;
  }
  return true;
}

/**
 * The URL less a leading base taken from configuration — `base + '/v1/…'`,
 * `${API}/v1/…`, f"{BASE}/…", or a URL that is only a name (`RPC_URL`). The
 * rest (a path, a query string) is what the request carries.
 */
function urlTail(url: string): string {
  const t = url.trim();
  if (/^[A-Za-z_$][\w$.]*$/.test(t)) return '';
  const plus = /^[A-Za-z_$][\w$.]*(?:\(\s*\))?\s*\+\s*/.exec(t);
  if (plus) return t.slice(plus[0].length);
  const tpl = /^`\$\{[^{}`\n]{1,200}\}/.exec(t);
  if (tpl) return '`' + t.slice(tpl[0].length);
  const f = /^([fF][rR]?|[rR][fF])(["'])\{[^{}"'\n]{1,200}\}/.exec(t);
  if (f) return f[1]! + f[2]! + t.slice(f[0].length);
  return t;
}

/**
 * The top-level comma-separated parts of `s`, outside strings and brackets;
 * null when `s` is too long or its brackets do not balance.
 */
function splitTop(s: string): string[] | null {
  if (s.length > 20_000) return null;
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '"' || c === "'" || c === '`') {
      const e = stringEnd(s, i, s.length, false, () => true);
      if (e < 0) return null;
      i = e - 1;
    } else if (c === '(' || c === '[' || c === '{') {
      depth++;
    } else if (c === ')' || c === ']' || c === '}') {
      if (--depth < 0) return null;
    } else if (c === ',' && depth === 0) {
      out.push(s.slice(start, i).trim());
      start = i + 1;
    }
  }
  if (depth !== 0) return null;
  out.push(s.slice(start).trim());
  return out.filter(Boolean);
}

/** The entries of an object or dict literal: `key: value`, a shorthand `name`, a spread `...x` / `**x`. */
function objectEntries(text: string): { key: string; value: string; spread?: boolean }[] | null {
  const t = text.trim();
  if (!t.startsWith('{') || !t.endsWith('}')) return null;
  const parts = splitTop(t.slice(1, -1));
  if (!parts) return null;
  return parts.map((e) => {
    if (e.startsWith('...') || e.startsWith('**')) return { key: '', value: e, spread: true };
    const m = /^(?:(["'`])([^"'`\\\n]{0,80})\1|([A-Za-z_$][\w$-]*)|\[([^\]\n]{1,80})\])\s*:(?!:)\s*/.exec(e);
    if (m) return { key: m[2] ?? m[3] ?? m[4] ?? '', value: e.slice(m[0].length) };
    return { key: /^[A-Za-z_$][\w$]*/.exec(e)?.[0] ?? '', value: e };
  });
}

/** One request, split by what each part does: where it goes, what it sends, how it authenticates, and the rest. */
interface RequestParts {
  url: string;
  body: string[];
  headers: string[];
  /** `auth`, `proxy` (see `CREDENTIAL_KEY`). */
  credentials: string[];
  extra: string[];
}

/** File one option or keyword of a request: `data:` / `json=` is the payload, `headers` the headers, a transport option nothing. */
function fileOption(req: RequestParts, key: string, value: string): void {
  if (BODY_KEY.test(key)) req.body.push(value);
  else if (key === 'headers') req.headers.push(value);
  else if (key === 'url' || key === 'uri') req.url ||= value;
  else if (CREDENTIAL_KEY.test(key)) req.credentials.push(value);
  else if (key !== 'method' && !TRANSPORT_KEY.test(key)) req.extra.push(value);
}

/**
 * File an options object — inline, or a local name bound to one (`const opts =
 * { method: 'POST', body }`). Options that cannot be read go to `unknown`: the
 * payload where the options carry it (`fetch(url, opts)`), the rest where the
 * payload is an argument of its own (an axios config).
 */
function fileOptions(r: Reader, req: RequestParts, text: string, index: Map<string, Assigned[]>, at: number, unknown: 'body' | 'extra'): void {
  let t = text.trim();
  if (/^[A-Za-z_$][\w$]*$/.test(t)) {
    const a = assignedBefore(index, t, at);
    t = (a && !a.file && exprAt(r, a.rhsAt)) || t;
  }
  const entries = objectEntries(t);
  if (!entries) {
    req[unknown].push(text);
    return;
  }
  for (const e of entries) {
    if (e.spread) req.body.push(e.value);
    else fileOption(req, e.key, e.value);
  }
}

/**
 * The parts of `client.post(url, …args)`: Python keywords by name, the first
 * positional argument as the payload — or, for got / ky, as the options — and
 * any later one as an options object (an axios config).
 */
function postParts(r: Reader, url: string, args: string[], recv: string, index: Map<string, Assigned[]>, at: number): RequestParts {
  const req: RequestParts = { url, body: [], headers: [], credentials: [], extra: [] };
  const optionsFirst = /^(?:got|ky|ofetch|\$fetch)$/i.test(recv);
  let positional = 0;
  for (const a of args) {
    const kw = /^([A-Za-z_]\w*)\s*=(?![=>])\s*/.exec(a);
    if (kw) fileOption(req, kw[1]!, a.slice(kw[0].length));
    else if (positional++ === 0 && !optionsFirst) req.body.push(a);
    else fileOptions(r, req, a, index, at, optionsFirst ? 'body' : 'extra');
  }
  return req;
}

/** A spread (`...defaults`, `**extra`) read as the name it spreads. */
const named = (s: string): string => s.replace(/(?:\.\.\.|\*\*)(?=[A-Za-z_$])/g, ' ');
/** A query parameter that authenticates the request (`?api_key=${…}`, `&token={…}`): the API's own key. */
const AUTH_QUERY = /[?&][\w-]{0,30}(?:key|token|auth|secret|signature|sig)[\w-]{0,30}=(?:\$\{[^{}\n]{1,200}\}|\{[^{}\n]{1,200}\})/gi;

/**
 * Do the headers carry data? Never a file, never the whole environment; one
 * environment variable only under an auth-like name (`Authorization: \`Bearer
 * ${process.env.API_TOKEN}\``, f"Bearer {os.environ['T']}").
 */
function headersCarry(r: Reader, p: Proof, headers: string[], at: number): boolean {
  for (const h of headers.slice(0, 8)) {
    let t = h.trim();
    if (/^[A-Za-z_$][\w$]*$/.test(t)) {
      const a = assignedBefore(p.index, t, at);
      if (a?.file) return true;
      t = (a && exprAt(r, a.rhsAt)) || t;
    }
    const entries = objectEntries(t) ?? [{ key: '', value: t }];
    for (const e of entries.slice(0, 32)) {
      const v = named(e.value);
      if (carries(p.index, v, FILE_DATA, at, 2) || carries(p.index, v, WHOLE_ENV, at, 2)) return true;
      if ((e.spread || !AUTH_HEADER.test(e.key)) && carries(p.index, v, LOCAL_DATA, at, 2)) return true;
    }
  }
  return false;
}

/**
 * A literal SELECT is a read only when it is the whole question: the SQL key is
 * the only key besides parameters, and the statement is one plain SELECT — no
 * `;` (a second statement), no `INTO`, no `FOR UPDATE`, no interpolation.
 */
const SELECT_BODY =
  /^\s*(?:\{\s*["']?(?:sql|query|statement|q)["']?\s*[:=]\s*)?(['"`])\s*(SELECT\b(?:(?!\1)[^\\\n]){0,2000})\1\s*(?:,\s*["']?(?:params|parameters|args|bindings|values|limit|offset|timeout)["']?\s*[:=]\s*[^,{}[\]]{0,200})*\s*(?:\}\s*)?$/i;
const SELECT_WRITES = /;|\bINTO\b|\bFOR\s+UPDATE\b|\$\{|\b(?:INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|CREATE|TRUNCATE|GRANT)\b/i;

/**
 * Does this POST only ask a question? Its headers and other options are read
 * for what they carry. A search / GraphQL endpoint (1.16.0's reads) stays a read
 * unless it carries a file or the whole environment. The read-looking requests
 * of 1.16.1 — a read verb as the last path segment, a JSON-RPC request whose
 * every `method` is a read, a SELECT (literal, or one the function refuses to
 * send otherwise: `if (!q.startsWith('SELECT')) throw`) — read only on POSITIVE
 * evidence: a payload proven harmless (see `harmless`) and nothing but a base
 * URL from configuration ahead of the path. `byName`: the URL may be a name
 * (`SEARCH_URL`) for the search test. `from`..`to` is the function body; `at`
 * the call.
 */
function requestReads(r: Reader, req: RequestParts, from: number, to: number, at: number, byName: boolean): boolean {
  const p = proofOf(r, from, to);
  const u = req.url.trim().slice(0, 400);
  const tail = urlTail(u).replace(AUTH_QUERY, '');
  if (READ_ONLY_POST.test(u) && (byName || /^(?:[`'"]|[fFrRbBuU]{1,2}['"])/.test(u))) {
    // A search / GraphQL endpoint asks a question, unless a file or the whole
    // environment rides along, or the query string carries a local value.
    const heavy = (x: string): boolean => carries(p.index, named(x), FILE_DATA, at, 2) || carries(p.index, named(x), WHOLE_ENV, at, 2);
    return ![...req.body, ...req.headers, ...req.credentials, ...req.extra].some(heavy) && !carries(p.index, tail, LOCAL_DATA, at, 2);
  }
  if (headersCarry(r, p, req.headers, at)) return false;
  if (req.credentials.some((x) => carries(p.index, named(x), FILE_DATA, at, 2) || carries(p.index, named(x), WHOLE_ENV, at, 2))) return false;
  if (req.extra.some((x) => carries(p.index, named(x), LOCAL_DATA, at, 2))) return false;
  const proven = (): boolean => (tail === '' || harmless(tail, p, at, 2)) && req.body.every((b) => harmless(b, p, at, 2));
  const path = READ_PATH.exec(u);
  if (path && !namesWrite(path[1] ?? '')) return proven();
  const { text: b, mutated } = requestBody(r, req.body.join(',\n'), from, at);
  if (mutated) return false; // `payload.method = args.method` after a read literal
  const methods = [...b.matchAll(/\bmethod["']?\s*[:=]\s*(['"`])([\w./-]{1,64})\1/g)].map((m) => m[2]!).filter((m) => !HTTP_VERB.test(m));
  const rpc = /rpc/i.test(u) || /jsonrpc/i.test(b);
  const readMethod = (m: string): boolean => {
    if (READ_ETH_METHOD.test(m)) return true;
    const g = rpc ? READ_RPC_METHOD.exec(m) : null;
    return g !== null && !namesWrite(g[1]!);
  };
  // Every method key has to be a literal read: a batch that names one by a
  // variable (`method: SEND`) is not known to read.
  const methodKeys = (b.match(/\bmethod["']?\s*[:=](?!\s*(['"`])(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1)/gi) ?? []).length;
  if (methods.length && methods.length === methodKeys && methods.every(readMethod)) return proven();
  const select = SELECT_BODY.exec(b);
  if (select && !SELECT_WRITES.test(select[2]!.slice(6))) return proven();
  // A guarded SELECT is the guarded argument itself, sent on: it carries
  // nothing local, and nothing else rides along.
  return (
    /sql|query/i.test(u + ' ' + b.slice(0, 400)) &&
    selectOnlyGuard(r, Math.max(from, at - NEAR_CALL), at, b) &&
    (tail === '' || harmless(tail, p, at, 2)) &&
    !req.body.some((x) => CARRIES_SECRET.test(x) || carries(p.index, named(x), LOCAL_DATA, at, 2))
  );
}

/** How far before a request its body's assignment or its guard is looked for. */
const NEAR_CALL = 8000;

/**
 * `if (!q.trim().toUpperCase().startsWith('SELECT')) throw …` / `if not
 * q.startswith("select"): raise …` — in code (not a comment or a string), on the
 * same variable the request sends, and unconditional: a guard with `&&` / `||`
 * (`!ALLOW_WRITE && !q.startsWith('SELECT')`) lets writes through.
 */
function selectOnlyGuard(r: Reader, base: number, at: number, sent: string): boolean {
  const text = r.src.slice(base, at);
  let seen = 0;
  for (const m of text.matchAll(/\.\s*(?:startsWith|startswith)\s*\(\s*['"`](?:SELECT|select|Select)\b/g)) {
    if (++seen > 16) break;
    const pos = m.index!;
    if (!r.ctx.isCode(base + pos)) continue;
    // The guard's own line, at most 200 characters back, and the line after it.
    const head = text.slice(Math.max(0, pos - 200), pos);
    const before = head.slice(head.lastIndexOf('\n') + 1);
    const tail = text.slice(pos, pos + 300).split('\n', 2).join('\n');
    if (!/\bif\b/.test(before) || !/!|\bnot\s/.test(before) || !/\b(?:throw|raise|return)\b/.test(tail)) continue;
    if (/&&|\|\||\band\b|\bor\b/.test(before + tail.split(/\b(?:throw|raise|return)\b/, 1)[0])) continue;
    const recv =
      /(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:\??\.\s*(?:trim|trimStart|trimEnd|toUpperCase|toLowerCase|toLocaleUpperCase|upper|lower|strip|lstrip)\s*\(\s*\)\s*)*$/.exec(before)?.[1];
    if (recv && new RegExp(`(?<![\\w$.])${recv.replace(/\$/g, '\\$')}(?![\\w$])`).test(sent)) return true;
  }
  return false;
}

/**
 * The body an argument names, with one assignment in the same function followed:
 * `json=payload`, `JSON.stringify(payload)`, `{ method: 'POST', body: JSON.stringify(rpc) }`.
 * `mutated` reports a later assignment into that object (`payload.method = …`),
 * which makes its literal fields no evidence of what is sent.
 */
function requestBody(r: Reader, arg: string, from: number, at: number): { text: string; mutated: boolean } {
  const t = arg.trim().replace(/^(?:json|data|json_body|body|content)\s*=\s*/, '').slice(0, 2000);
  const ident =
    /^(?:JSON\.stringify\(\s*)?([A-Za-z_$][\w$]*)\s*\)?$/.exec(t)?.[1] ??
    /\bbody\s*:\s*(?:JSON\.stringify\(\s*)?([A-Za-z_$][\w$]*)\s*\)?\s*[,}]/.exec(t)?.[1];
  if (!ident) return { text: t, mutated: false };
  const base = Math.max(from, at - NEAR_CALL);
  const src = r.src.slice(base, at);
  const esc = ident.replace(/\$/g, '\\$');
  let last: RegExpMatchArray | undefined;
  for (const m of src.matchAll(new RegExp(`(?:^|[\\s;(])(?:const\\s+|let\\s+|var\\s+)?${esc}\\s*(?::[^=\\n]{1,80})?=\\s*\\{`, 'g'))) last = m;
  if (!last) return { text: t, mutated: false };
  const open = base + last.index! + last[0].length - 1;
  const close = r.close(open);
  if (!(close > open && close < at)) return { text: t, mutated: false };
  const mutated = new RegExp(`(?<![\\w$.])${esc}\\s*(?:\\.\\s*[\\w$]+|\\[[^\\]\\n]{1,40}\\])\\s*=(?!=)`).test(r.src.slice(close, at));
  return { text: `${t}\n${r.src.slice(open, Math.min(close + 1, open + NEAR_CALL))}`, mutated };
}

const evidenceMemo = new WeakMap<Reader, Map<string, HandlerEvidence[]>>();

function handlerEvidence(r: Reader, handler: Thunk | undefined, env: Env | null): HandlerEvidence[] {
  if (!handler) return [];
  // One handler shared by thousands of registrations is read once.
  const v0 = r.ev(handler);
  // A function with no closure environment (a named, same-file function) reads
  // the same from every registration that passes it.
  const memoKey = v0.k === 'fn' && (!env || !v0.env) ? `${v0.fn.bodyStart}` : undefined;
  let memo = evidenceMemo.get(r);
  if (!memo) evidenceMemo.set(r, (memo = new Map()));
  if (memoKey !== undefined && memo.has(memoKey)) return memo.get(memoKey)!;
  const result = handlerEvidenceUncached(r, handler, env);
  if (memoKey !== undefined) memo.set(memoKey, result);
  return result;
}

function handlerEvidenceUncached(r: Reader, handler: Thunk, env: Env | null): HandlerEvidence[] {
  const bodies: [number, number][] = [];
  const seen = new Set<number>();
  const visit = (t: Thunk, depth: number): void => {
    if (depth > 3) return;
    const v = r.ev(t);
    if (v.k !== 'fn' || seen.has(v.fn.bodyStart)) return;
    seen.add(v.fn.bodyStart);
    bodies.push([v.fn.bodyStart, v.fn.bodyEnd]);
    // A wrapper calls its parameter (`handler(input)`) — follow it to what the
    // call site passed. A same-file function is followed only when the call hands
    // it the tool's input: a token-refresh POST every tool shares
    // (`authHeaders()`) is not what each tool does; `removePage(id)` is.
    const inputs = new Set<string>();
    for (const p of r.params(v.fn)) {
      if (p.name) inputs.add(p.name);
      for (const k of p.keys ?? []) inputs.add(k.local);
      if (p.restKey) inputs.add(p.restKey);
      for (const it of p.items ?? []) if (it) inputs.add(it);
    }
    const body = r.text(v.fn.bodyStart, v.fn.bodyEnd);
    const esc = (n: string): string => n.replace(/[$]/g, '\\$');
    // Locals derived from the input (`const pid = id.trim()`) carry it too.
    for (let pass = 0; pass < 2 && inputs.size; pass++) {
      const any = new RegExp(`(?<![\\w$.])(?:${[...inputs].map(esc).join('|')})(?![\\w$])`);
      for (const m of body.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,300})/g)) {
        if (!inputs.has(m[1]!) && any.test(m[2]!)) inputs.add(m[1]!);
      }
    }
    const usesInput = inputs.size ? new RegExp(`(?<![\\w$.])(?:${[...inputs].map(esc).join('|')})(?![\\w$])`) : null;
    for (const m of body.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(/g)) {
      const at = v.fn.bodyStart + m.index!;
      if (!r.ctx.isCode(at)) continue;
      const bound = r.lookup(v.env, m[1]!);
      if (bound) {
        visit(bound, depth + 1);
        continue;
      }
      const f = r.fnNamed(m[1]!);
      if (!f || f.kind === 'method' || seen.has(f.bodyStart) || !usesInput) continue;
      const open = at + m[0].length - 1;
      const args = (r.parts(open) ?? []).map(([a, b]) => r.text(a, b));
      if (usesInput && args.some((a) => usesInput.test(a))) visit({ val: { k: 'fn', fn: f, env: null } }, depth + 1);
    }
  };
  visit(handler, 0);
  const out: HandlerEvidence[] = [];
  const v = r.ev(handler);
  const read = v.k === 'fn' ? inputFetch(r, v.fn) : undefined;
  if (read) out.push(read);
  // What the handler's own writes carry out is read first: a secret leaving is
  // the read leg, whatever else the handler shows.
  const secretInputs = v.k === 'fn' ? secretInputsOf(r, v.fn) : undefined;
  let leak: HandlerEvidence | undefined;
  for (const [from, to] of bodies) {
    leak ??= leaksIn(r, from, to, from === bodies[0]![0] ? secretInputs : undefined);
    for (const ev of writesIn(r, from, to)) {
      if (out.length < 3 && !out.some((o) => o.why === ev.why)) out.push(ev);
    }
    if (out.length >= 3 && leak) break;
  }
  if (leak) out.push(leak);
  return out;
}

/** A credential file by its path, read: SSH keys, cloud, registry and Git credentials, `.env`, `.netrc`, a keychain. */
const CREDENTIAL_PATH = String.raw`(?:\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\.docker\/config|\.kube\/config|\.pgpass\b|\.env\b|\bcredentials\b|\bkeychain\b|\bwallet\b)`;
const CREDENTIAL_FILE = new RegExp(
  String.raw`\b(?:readFile(?:Sync)?|createReadStream|open)\s*\([^()\n]{0,200}?${CREDENTIAL_PATH}|${CREDENTIAL_PATH}[^\n]{0,200}?\.\s*read_(?:text|bytes)\s*\(`,
  'i',
);

/**
 * The handler's inputs named for a secret, as a pattern over its code: a
 * destructured `{ secret }`, a Python `client_secret` parameter, a member
 * `args.secret`. Undefined when it takes none.
 */
function secretInputsOf(r: Reader, fn: FnInfo): RegExp | undefined {
  const locals: string[] = [];
  const holders: string[] = [];
  const secretNamed = (n: string): boolean => nameWordsOf(n).some((w) => w === 'secret' || w === 'secrets');
  for (const p of r.params(fn).slice(0, MAX_PIN_INPUTS)) {
    if (p.name && !/^(?:self|cls|this|ctx|context)$/.test(p.name)) (secretNamed(p.name) ? locals : holders).push(p.name);
    for (const k of p.keys ?? []) if (secretNamed(k.key)) locals.push(k.local);
  }
  const esc = (n: string): string => n.replace(/\$/g, '\\$');
  const parts = [
    // A value, not a key: `{ page, secret }`, `{"s": secret}` — never `{ secret: true }` or `"secret"`.
    ...(locals.length ? [`(?<![\\w$.'"\`])(?:${locals.map(esc).join('|')})(?![\\w$]|\\s*:(?!:)|['"\`])`] : []),
    ...(holders.length ? [`(?<![\\w$.'"\`])(?:${holders.map(esc).join('|')})\\s*\\??\\.\\s*[\\w$]*(?:secret|Secret|SECRET)[\\w$]*(?![\\w$]|\\s*:(?!:))`] : []),
  ];
  return parts.length ? new RegExp(parts.join('|')) : undefined;
}

/**
 * Does a write in this body send a secret out (1.17)? The whole environment
 * (`axios.post(…, { env: process.env })`), a credential file, or an input
 * named for a secret (`{ page, secret }`) in what the request carries after
 * its URL, written there or through the names it uses: the handler reads that
 * secret, whatever its parameters are called. The API's own key from one
 * environment variable in a header is not this.
 */
function leaksIn(r: Reader, from: number, to: number, secretInputs: RegExp | undefined): HandlerEvidence | undefined {
  const { sites } = writesOf(r, from, to);
  if (!sites.length) return undefined;
  const index = bodyIndex(r, from, to);
  for (const site of sites) {
    const sent = named(site.sent.map(([a, b]) => r.src.slice(a, Math.min(b, a + 4000))).join(',\n'));
    const what = carries(index, sent, WHOLE_ENV, site.at, 2)
      ? 'the whole environment'
      : carries(index, sent, CREDENTIAL_FILE, site.at, 2)
        ? 'a credential file'
        : secretInputs && carries(index, sent, secretInputs, site.at, 2)
          ? 'an input named for a secret'
          : undefined;
    if (what) return { tag: 'sensitive-source', why: `${site.why.replace(/^handler sends/, `handler sends ${what} in`)}`, line: r.ctx.line(site.at) };
  }
  return undefined;
}

/**
 * A GET-shaped request: `fetch(…)`, `got(…)`, `urlopen(…)`, or `<client>.get(…)` / `.head(…)`.
 * The receiver starts at a word boundary: unanchored, every position inside a
 * long identifier or hex literal restarted the scan of its tail, and a 500 KB
 * handler took minutes.
 */
const GET_REQUEST = /(?<![\w$.])(?:fetch|\$fetch|ofetch|got|ky|urlopen)\s*\(|(?<![\w$])([A-Za-z_$][\w$]*)\s*\.\s*(?:get|head|urlopen)\s*\(/g;

/**
 * Does the handler `fn` fetch a URL that IS one of its inputs — `fetch(url)`,
 * `axios.get(args.url)`, `requests.get(url)`, `fetch(new URL(input.href))`? Then
 * it takes in whatever the caller points it at: untrusted input, read from the
 * handler rather than the prose. A URL built on a fixed base (`${API}/items/${id}`)
 * is an API read, not this.
 */
function inputFetch(r: Reader, fn: FnInfo): HandlerEvidence | undefined {
  const inputs = new Set<string>();
  for (const p of r.params(fn)) {
    if (p.name) inputs.add(p.name);
    for (const k of p.keys ?? []) inputs.add(k.local);
  }
  if (!inputs.size) return undefined;
  const names = [...inputs].map((n) => n.replace(/[$]/g, '\\$')).join('|');
  const isInput = new RegExp(
    `^(?:await\\s+)?(?:(?:new\\s+URL|String|str|encodeURI)\\s*\\(\\s*)?(?:${names})(?:\\s*\\??\\.\\s*[A-Za-z_$][\\w$]*|\\[\\s*['"][\\w-]{1,40}['"]\\s*\\]){0,2}\\s*\\)?$|^\`\\$\\{\\s*(?:${names})(?:\\s*\\??\\.\\s*[A-Za-z_$][\\w$]*){0,2}\\s*\\}\`$`,
  );
  const body = r.src.slice(fn.bodyStart, fn.bodyEnd);
  let seen = 0;
  for (const m of body.matchAll(GET_REQUEST)) {
    if (++seen > 64) break;
    const at = fn.bodyStart + m.index!;
    if (!r.ctx.isCode(at)) continue;
    if (m[1] !== undefined && !HTTP_CLIENT.test(m[1])) continue;
    const args = r.parts(at + m[0].length - 1) ?? [];
    const first = args[0] ? r.src.slice(args[0][0], args[0][1]).trim() : '';
    if (first && isInput.test(first.slice(0, 200))) {
      return { tag: 'untrusted-input', why: `handler fetches a URL taken from its input (${clip(m[0] + first)})`, line: r.ctx.line(at) };
    }
  }
  return commandFetch(r, fn, isInput, names);
}

/**
 * A download program named as the command a local runner starts: `runCmd('curl',
 * [...])`, `execFile("wget", [...])`, a list `["curl", "-s", url]`, a command line
 * `` `curl -sk ${url}` `` / f"wget {url}".
 */
const FETCH_COMMAND = /(["'])(?:curl|wget)(?:\.exe)?\1\s*,\s*\[|\[\s*(["'])(?:curl|wget)(?:\.exe)?\2\s*,|`(?:curl|wget)\s[^`]{0,400}`|\b[fF](["'])(?:curl|wget)\s[^"'\n]{0,400}\3/g;

/**
 * …run with one of the handler's inputs as an argument (1.17): operant's
 * `runCmd("curl", ["-sk", target_url])` fetches `target_url` as surely as
 * `fetch(target_url)` does.
 */
function commandFetch(r: Reader, fn: FnInfo, isInput: RegExp, names: string): HandlerEvidence | undefined {
  const body = r.src.slice(fn.bodyStart, fn.bodyEnd);
  const interpolated = new RegExp(`\\$?\\{\\s*(?:${names})(?:\\s*\\??\\.\\s*[A-Za-z_$][\\w$]*){0,2}\\s*(?:![rsa])?\\s*\\}`);
  let seen = 0;
  for (const m of body.matchAll(FETCH_COMMAND)) {
    if (++seen > 64) break;
    const at = fn.bodyStart + m.index!;
    let takes = false;
    if (m[0].endsWith('[') || m[0].startsWith('[')) {
      // The argument list: the array after the program, or the list it heads.
      const open = m[0].startsWith('[') ? at : at + m[0].length - 1;
      if (!r.ctx.isCode(open)) continue;
      const items = r.parts(open) ?? [];
      takes = items.slice(m[0].startsWith('[') ? 1 : 0, 64).some(([a, b]) => isInput.test(r.src.slice(a, Math.min(b, a + 200)).trim()));
    } else {
      // A command line — a string in the code, not a comment — with the input interpolated into it.
      if (r.ctx.mask[m[0][0] === '`' ? at : at + 1] !== STRING) continue;
      takes = interpolated.test(m[0]);
    }
    if (takes) return { tag: 'untrusted-input', why: `handler runs a download command on a URL taken from its input (${clip(m[0])})`, line: r.ctx.line(at) };
  }
  return undefined;
}

// --- Destinations a handler pins (1.17) ------------------------------------------

/** A handler body read for where a URL parameter goes, at most. */
const MAX_PIN_BODY = 20_000;
/** Uses of one name read; a parameter used more often is not followed. */
const MAX_PIN_USES = 32;
/** Names followed per parameter: itself and the locals it is copied into. */
const MAX_PIN_NAMES = 4;
/** Inputs a handler may take for its uses to be read: a header of thousands of keys is padding. */
const MAX_PIN_INPUTS = 64;

/** A URL / host parameter by one of its words, camelCase split too: `url`, `case_uri`, `targetUrl`, `urls`. */
const namesDestinationParam = (name: string): boolean =>
  nameWordsOf(name.slice(0, 200)).some((w) => /^(?:url|uri|host|hostname)s?$/.test(w));
const nameWordsOf = (name: string): string[] =>
  name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/** Calls that hand back the value they are given, re-encoded: the use is wherever their result goes. */
const PIN_TRANSPARENT = /^(?:str|String|quote|quote_plus|unquote|encodeURIComponent|encodeURI|decodeURIComponent|(?:urllib\.)?parse\.(?:quote|quote_plus|unquote))$/;
/** Calls that only test, measure or log a value. */
const PIN_INERT_CALL = /^(?:len|isinstance|bool|type|repr|print|console\.\w+|warnings\.warn|(?:self\.|this\.)?_?(?:logger|logging|log|LOGGER|LOG)\.\w+)$/;
/** Methods whose result is a test of the value, not the value. */
const PIN_INERT_METHOD = /^\s*\.\s*(?:startswith|endswith|includes|startsWith|endsWith|test|match|count|find|index|isdigit|isalnum|isidentifier)\s*\(/;
/** The rest of a statement that copies the value, trimmed or re-cased at most: `case_uri.lstrip("/")`. */
const PIN_COPY_TAIL = /^(?:\s*\.\s*(?:strip|lstrip|rstrip|lower|upper|trim|trimStart|trimEnd|toLowerCase|toString|removeprefix|removesuffix)\s*\([^()\n]{0,40}\))*\s*(?:;|#|\/\/|\r?\n|$)/;
/** An assignment head: `x = `, `const x = `, `x: str = `, `x = await `. */
const PIN_ASSIGN_HEAD = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=\n]{1,60})?=\s*(?:await\s+)?$/;
const PIN_ID_NAME = /(?:^|_)id$|[a-z0-9]Id$/;
/** Words of a function that reaches the URL rather than parsing it. */
const PIN_FETCH_WORDS = new Set(['download', 'fetch', 'scrape', 'crawl', 'request', 'load', 'open', 'resolve', 'retrieve', 'lookup', 'http', 'curl', 'wget', 'get', 'visit', 'browse']);
/** A constructor that builds a request, a URL or a client is no data value. */
const PIN_REQUESTISH = /request|url|uri|client|session|http|fetch|connect|socket/i;
/** Words before a `(` that make it a group, not a call. */
const PIN_KEYWORDS = new Set(['if', 'elif', 'while', 'for', 'return', 'await', 'not', 'and', 'or', 'in', 'switch', 'catch', 'typeof', 'void', 'yield', 'assert', 'with', 'else', 'lambda']);

/**
 * Does the head of a URL — the text before a parameter's value is spliced in —
 * fix its host? A literal `scheme://host` closed by `/`, `?` or `#`; a path on
 * the client's own base (`/v1/items/…`, not `/…` or `//…` — where the path goes
 * is the caller's to check, see `pathBaseOpen`); or a module constant closed the
 * same way (`{TNA_BASE}/…`, `${API}/…`). `new URL(url, BASE)` is not one: an
 * absolute `url` replaces the base. Nor is a fixed host that fetches what it is
 * handed (see `FORWARDS`).
 */
function headPins(r: Reader, head: string, tainted: Set<string>): boolean {
  if (/^(?:https?|wss?):\/\/[^/?#{}\s$\\]+[/?#]/i.test(head)) return !forwards(head);
  if (/^\/[^/\\{$\s]/.test(head)) return !forwards(head);
  const m = (r.py ? /^\{\s*([A-Za-z_][\w.]{0,80})\s*\}(?=[/?#])/ : /^\$\{\s*([A-Za-z_$][\w$.]{0,80})\s*\}(?=[/?#])/).exec(head);
  if (!m || !moduleConstant(r, m[1]!, tainted)) return false;
  // The constant's own value, when the file writes it as a literal, is read with the rest.
  return !forwards(`${constValue(r, m[1]!) ?? ''}${head.slice(m[0].length)}`);
}

/**
 * A URL head that hands the value on to be fetched: a reader, a CORS or caching
 * proxy, an archive or screenshot service by its host or path (`https://r.jina.ai/${url}`,
 * `/proxy/${url}`), or a query key that names the target (`?url=`, `?target=`,
 * `?u=`). The host is fixed; what it fetches is the caller's.
 */
const FORWARD_HOST = /^(?:[a-z]+:\/\/)?[^?#]*?(?:^|[./_-])(?:jina|cors|proxy|proxies|allorigins|webcache|archive|thum|12ft|microlink|unfurl|screenshots?|scraper|scrape|crawler|crawl|reader|fetcher|fetch)(?:[./_-]|$)/i;
const FORWARD_QUERY = /[?&](?:url|uri|u|target|target_url|link|src|source|href|dest|destination|site|website|page|address|redirect|redirect_uri|to)=$/i;
function forwards(head: string): boolean {
  const h = head.slice(0, 400);
  return FORWARD_QUERY.test(h) || FORWARD_HOST.test(h.split(/[?#]/, 1)[0]!);
}

/**
 * A name that holds a module constant, not an input: an upper-case constant
 * (`API`, `TNA_BASE`, `settings.API_URL`) or a lower-case name the file
 * declares once at its top level (`const apiBase = …`). A local, an attribute
 * (`self.base_url`) or an input is not one.
 */
function moduleConstant(r: Reader, name: string, tainted: Set<string>): boolean {
  const parts = name.split('.');
  if (tainted.has(parts[0]!)) return false;
  if (/^[A-Z][A-Z0-9_]*$/.test(parts[parts.length - 1]!) && /[A-Z]/.test(parts[parts.length - 1]!)) return true;
  if (parts.length > 1) return false;
  const c = fileConsts(r).get(name);
  return !!c && c.block === -1;
}

/** The literal a constant is declared as (`const API = "https://…"`), when it is one. */
function constValue(r: Reader, name: string): string | undefined {
  const c = name.includes('.') ? undefined : fileConsts(r).get(name);
  if (!c) return undefined;
  return /^\s*(["'`])([^"'`\\\n$]{0,300})\1/.exec(r.src.slice(c.init, c.init + 320))?.[2];
}

/** A request base written in a call: a literal URL, or a module constant. */
function basePins(r: Reader, text: string, tainted: Set<string>): boolean {
  const t = text.trim();
  const lit = /^[rRbBuU]?(["'`])((?:https?|wss?):\/\/[^"'`\s{}$]+)\1$/i.exec(t);
  if (lit) return !forwards(lit[2]!);
  return /^[A-Za-z_$][\w$.]{0,80}$/.test(t) && moduleConstant(r, t, tainted) && !forwards(constValue(r, t) ?? '');
}

/**
 * Where a path (`/v1/items/…`, a template from offset `start`) is sent: joined
 * to a base the caller controls, it pins nothing (1.17). What stands before it
 * (`server + f"/api/{url}"`), the base it is resolved against (`new
 * URL(\`/x/${url}\`, domain)`, `urljoin(endpoint, f"/x/{url}")`), and — for a
 * path first assigned to a local — the same at each use of that local (`path =
 * …; fetch(server + path)`), read up to `MAX_PIN_USES` uses.
 */
function pathBaseOpen(r: Reader, start: number, from: number, to: number, tainted: Set<string>, alias = true): boolean {
  const before = concatHead(r, start, from);
  if (before !== undefined && !headOnly(r, before, tainted)) return true;
  const call = enclosingCall(r, start, from);
  if (call) {
    const k = call.args.findIndex(([a, b]) => a <= start && start < b);
    const last = call.callee.split('.').pop() ?? '';
    if (last === 'URL' && k === 0 && call.args[1]) return !basePins(r, r.src.slice(call.args[1][0], call.args[1][1]), tainted);
    if ((last === 'urljoin' || last === 'join') && k > 0) return !basePins(r, r.src.slice(call.args[0]![0], call.args[0]![1]), tainted);
  }
  if (!alias) return false;
  const stmt = r.src.slice(Math.max(from, start - 200), start);
  const target = PIN_ASSIGN_HEAD.exec(stmt.slice(stmt.lastIndexOf('\n') + 1))?.[1];
  if (!target) return false;
  const re = new RegExp(`(?<![\\w$.])${target.replace(/\$/g, '\\$')}(?![\\w$])`, 'g');
  let uses = 0;
  for (const m of r.src.slice(start, to).matchAll(re)) {
    if (++uses > MAX_PIN_USES) return true;
    const at = start + m.index!;
    const tpl = templateAround(r, at, from);
    if (tpl === 'unknown') return true;
    if (tpl) {
      if (!headOnly(r, tpl.head, tainted)) return true;
      continue;
    }
    if (r.ctx.isCode(at) && pathBaseOpen(r, at, from, to, tainted, false)) return true;
  }
  return false;
}

/** A base written whole before a path: nothing, a literal URL, or a module constant (`{BASE}`, `${API}`, `BASE + `). */
function headOnly(r: Reader, head: string, tainted: Set<string>): boolean {
  if (head === '') return true;
  if (/^(?:https?|wss?):\/\/[^?#{}\s$\\]+$/i.test(head)) return !forwards(head);
  const m = (r.py ? /^\{\s*([A-Za-z_][\w.]{0,80})\s*\}/ : /^\$\{\s*([A-Za-z_$][\w$.]{0,80})\s*\}/).exec(head);
  if (!m || !moduleConstant(r, m[1]!, tainted)) return false;
  const rest = head.slice(m[0].length);
  return (rest === '' || /^\/[^{$\s]*$/.test(rest)) && !forwards(`${constValue(r, m[1]!) ?? ''}${rest}`);
}

/**
 * The template around offset `at` — a Python f-string's `{…}`, a JS template's
 * `${…}` — as its start and the text before that interpolation; undefined when
 * the offset sits in none (plain code, a docstring, a message); `unknown` when
 * the template cannot be read within `floor`.
 */
function templateAround(r: Reader, at: number, floor: number): { start: number; head: string } | 'unknown' | undefined {
  const { src, ctx } = r;
  if (r.py) {
    if (ctx.mask[at] !== STRING) return undefined;
    let s = at;
    while (s > floor && ctx.mask[s - 1] === STRING) s--;
    const pre = /^(?:[rR]?[fF]|[fF][rR])(?=["'])/.exec(src.slice(s, s + 3))?.[0];
    if (!pre) return undefined;
    const q = src[s + pre.length]!;
    const open = src.startsWith(q.repeat(3), s + pre.length) ? 3 : 1;
    const text = src.slice(s + pre.length + open, at);
    // `at` must sit inside a `{…}` interpolation: the last single `{` not closed before it.
    let brace = -1;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (c === '{') {
        if (text[i + 1] === '{' && brace < 0) i++;
        else brace = i;
      } else if (c === '}' && brace >= 0) brace = -1;
    }
    return brace >= 0 ? { start: s, head: text.slice(0, brace) } : undefined;
  }
  if (!ctx.isCode(at)) return undefined;
  // JS: the code of a `${…}` sits right after a string-masked `${`.
  let i = at;
  while (i > floor && ctx.isCode(i - 1)) i--;
  if (i - 2 < floor || ctx.mask[i - 1] !== STRING || src[i - 1] !== '{' || src[i - 2] !== '$') return undefined;
  let s = i - 3;
  while (s > floor && !(src[s] === '`' && ctx.mask[s] === STRING && src[s - 1] !== '\\')) s--;
  if (src[s] !== '`') return 'unknown';
  return { start: s, head: src.slice(s + 1, i - 2) };
}

/** The `+` chain to the left of offset `at` as one URL head, or undefined when nothing readable is concatenated before it. */
function concatHead(r: Reader, at: number, floor: number): string | undefined {
  return concatChain(r, at, floor)?.head;
}

/** …and where that chain starts. A chain longer than six parts is not read: its head is unknown. */
function concatChain(r: Reader, at: number, floor: number): { head: string; start: number } | undefined {
  const { src, ctx } = r;
  const parts: string[] = [];
  let i = at - 1;
  let start = at;
  for (let k = 0; k < 7; k++) {
    while (i > floor && /\s/.test(src[i]!)) i--;
    if (src[i] !== '+' || !ctx.isCode(i) || src[i - 1] === '+') break;
    if (k === 6) return undefined;
    i--;
    while (i > floor && /\s/.test(src[i]!)) i--;
    if (!ctx.isCode(i)) {
      // A whole string literal: quotes (and a Python prefix) at its start, no code inside.
      let s = i;
      while (s > floor && !ctx.isCode(s - 1)) s--;
      const m = /^[rRbBuUfF]{0,2}(["'`])/.exec(src.slice(s, s + 3));
      if (!m || src[i] !== m[1]) return undefined;
      parts.unshift(src.slice(s + m[0].length, i));
      start = s;
      i = s - 1;
    } else {
      const id = /[A-Za-z_$][\w$.]{0,80}$/.exec(src.slice(Math.max(floor, i - 80), i + 1))?.[0];
      if (!id) return undefined;
      parts.unshift(r.py ? `{${id}}` : `\${${id}}`);
      i -= id.length;
      start = i + 1;
    }
  }
  return parts.length ? { head: parts.join(''), start } : undefined;
}

interface PinFrame {
  /** Start of the statement holding the offset. */
  stmt: number;
  /** The brackets around the offset inside that statement, outermost first. */
  open: number[];
}

/**
 * For each offset (ascending), its statement start and enclosing brackets, in
 * one pass over the body: a line break or `;` outside brackets ends a
 * statement, and so does a JS block's `{` or `}`.
 */
function pinFrames(r: Reader, from: number, to: number, offsets: number[]): Map<number, PinFrame> {
  const { src, ctx } = r;
  const out = new Map<number, PinFrame>();
  const stack: { at: number; block: boolean }[] = [];
  let stmt = from;
  let k = 0;
  for (let i = from; i < to && k < offsets.length; i++) {
    while (k < offsets.length && offsets[k] === i) {
      const open: number[] = [];
      for (let j = stack.length - 1; j >= 0 && !stack[j]!.block; j--) open.unshift(stack[j]!.at);
      out.set(offsets[k++]!, { stmt, open });
    }
    if (!ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const block = c === '{' && !r.py && blockBrace(src, i, from);
      stack.push({ at: i, block });
      if (block) stmt = i + 1;
    } else if (c === ')' || c === ']' || c === '}') {
      if (stack.pop()?.block) stmt = i + 1;
    } else if ((c === '\n' || c === ';') && (stack.length === 0 || stack[stack.length - 1]!.block)) stmt = i + 1;
  }
  return out;
}

/** A JS `{` that opens a block (after `)`, `=>`, `;`, a brace or `else` / `try` / `do` / `finally`), not an object. */
function blockBrace(src: string, at: number, floor: number): boolean {
  let i = at - 1;
  while (i > floor && /\s/.test(src[i]!)) i--;
  if (i <= floor) return true;
  const c = src[i]!;
  return c === ')' || c === ';' || c === '{' || c === '}' || (c === '>' && src[i - 1] === '=') || /\b(?:else|try|do|finally)$/.test(src.slice(Math.max(floor, i - 8), i + 1));
}

/**
 * The URL / host parameters (`candidates`, as the schema names them) whose
 * destination handler `fn` pins: every use of the value — or of a local copied
 * from it (`uri = case_uri.lstrip("/")`) — builds a URL whose host is fixed
 * (`f"{TNA_BASE}/{uri}/data.xml"`, `BASE + "/" + x`, `` `${API}/items/${id}` ``),
 * reduces it to an id (`video_id = extract_video_id(video_url)`), or only tests,
 * logs, raises with or returns it as data. Any other use — handed to a function
 * the handler does not show (`_http_get_json(url)`), a request made with it, a
 * template whose host it can change — leaves the destination open: nothing is
 * pinned by what the handler does not say. Bounded: the body, the uses and the
 * names followed are capped, and each pass is linear in the body.
 */
function pinnedParams(r: Reader, fn: FnInfo, candidates: string[]): string[] {
  const from = fn.bodyStart;
  const to = fn.bodyEnd;
  if (!candidates.length || to <= from || to - from > MAX_PIN_BODY) return [];
  const { src } = r;
  const body = src.slice(from, to);
  // The handler's inputs as locals: a schema key → the binding that holds it.
  const local = new Map<string, string>();
  const tainted = new Set<string>();
  for (const p of r.params(fn)) {
    if (p.name && !/^(?:self|cls|this|ctx|context)$/.test(p.name)) {
      tainted.add(p.name);
      if (r.py) local.set(p.name, p.name);
    }
    for (const k of p.keys ?? []) {
      tainted.add(k.local);
      local.set(k.key, k.local);
    }
  }
  if (!tainted.size || tainted.size > MAX_PIN_INPUTS) return [];
  // Locals computed from an input are inputs too, for the heads of other URLs.
  const assign = r.py ? /^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]{1,60})?=(?!=)([^\n]{1,300})/gm : /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,300})/g;
  for (let pass = 0; pass < 2; pass++) {
    const any = new RegExp(`(?<![\\w$.])(?:${[...tainted].map((n) => n.replace(/\$/g, '\\$')).join('|')})(?![\\w$])`);
    let n = 0;
    for (const m of body.matchAll(assign)) {
      if (++n > 400 || tainted.size >= MAX_PIN_INPUTS * 2) break;
      if (!tainted.has(m[1]!) && any.test(m[2]!)) tainted.add(m[1]!);
    }
  }
  const out: string[] = [];
  for (const cand of candidates) {
    const name = local.get(cand);
    if (name && pinsEveryUse(r, from, to, name, tainted)) out.push(cand);
  }
  return out;
}

/** Every use of `start` (and of the locals copied from it) pins or is inert, and at least one pins. */
function pinsEveryUse(r: Reader, from: number, to: number, start: string, tainted: Set<string>): boolean {
  const { src, ctx } = r;
  const names = [start];
  let pinned = false;
  for (let q = 0; q < names.length; q++) {
    if (q >= MAX_PIN_NAMES) return false;
    const name = names[q]!;
    const re = new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}(?![\\w$])`, 'g');
    const anchors = new Map<number, number>();
    let uses = 0;
    for (const m of src.slice(from, to).matchAll(re)) {
      if (++uses > MAX_PIN_USES) return false;
      const at = from + m.index!;
      const tpl = templateAround(r, at, from);
      if (tpl === 'unknown') return false;
      if (tpl) {
        // What is concatenated before the template is part of its head: `server + \`/v1/${url}\``.
        const before = concatChain(r, tpl.start, from);
        const head = (before?.head ?? '') + tpl.head;
        if (headPins(r, head, tainted) && !(head[0] === '/' && pathBaseOpen(r, before?.start ?? tpl.start, from, to, tainted))) pinned = true;
        else anchors.set(at, tpl.start);
        continue;
      }
      if (!ctx.isCode(at)) continue; // the name in text: a docstring, a message, a comment
      // A keyword argument's name or an object key is not the value: `case_uri=uri`, `{ url: x }`.
      const after = src.slice(at + name.length, at + name.length + 40);
      const before = src.slice(Math.max(from, at - 40), at);
      if (r.py ? /^\s*=(?!=)/.test(after) && /[(,]\s*$/.test(before) : /^\s*:/.test(after) && /[{,]\s*$/.test(before)) continue;
      if (PIN_INERT_METHOD.test(after)) continue;
      const chain = concatChain(r, at, from);
      if (chain !== undefined) {
        if (headPins(r, chain.head, tainted) && !(chain.head[0] === '/' && pathBaseOpen(r, chain.start, from, to, tainted))) {
          pinned = true;
          continue;
        }
        return false;
      }
      anchors.set(at, at);
    }
    if (!anchors.size) continue;
    const frames = pinFrames(r, from, to, [...new Set(anchors.values())].sort((a, b) => a - b));
    for (const [at, anchor] of anchors) {
      const frame = frames.get(anchor);
      const verdict = frame ? useVerdict(r, at, anchor, frame, name, to) : 'open';
      if (verdict === 'open') return false;
      if (verdict === 'pinned') pinned = true;
      else if (verdict !== 'inert' && !names.includes(verdict.alias)) names.push(verdict.alias);
    }
  }
  return pinned;
}

/** What one use of `name` at `at` (judged at `anchor`, its template when it sits in one) does with the value. */
function useVerdict(r: Reader, at: number, anchor: number, frame: PinFrame, name: string, to: number): 'pinned' | 'inert' | 'open' | { alias: string } {
  const { src } = r;
  const stmtText = src.slice(frame.stmt, Math.min(to, frame.stmt + 600));
  if (/^\s*(?:raise|throw)\b/.test(stmtText)) return 'inert';
  const returns = /^\s*return\b/.test(stmtText);
  // Out through the brackets around the use, innermost first.
  for (let j = frame.open.length - 1; j >= 0; j--) {
    const open = frame.open[j]!;
    const lead = src.slice(Math.max(frame.stmt, open - 80), open);
    if (src[open] === '[') {
      // A subscript (`cache[url]`) looks something up with the value; a list literal holds it.
      if (/[\w$\])]\s*$/.test(lead)) return 'open';
      continue;
    }
    if (src[open] === '{') continue;
    const callee = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*$/.exec(lead)?.[1]?.replace(/\s+/g, '') ?? '';
    if (!callee || PIN_KEYWORDS.has(callee) || PIN_TRANSPARENT.test(callee)) continue;
    if (PIN_INERT_CALL.test(callee)) return 'inert';
    const last = callee.split('.').pop()!;
    // `video_id = extract_video_id(video_url)`: the whole value is reduced to an id —
    // by a function that parses it, not one that fetches it (`download_page_id(url)`).
    if (j === 0) {
      const calleeAt = open - (/[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*$/.exec(lead)?.[0].length ?? 0);
      const target = PIN_ASSIGN_HEAD.exec(src.slice(frame.stmt, calleeAt))?.[1];
      const words = nameWordsOf(last);
      if (target && PIN_ID_NAME.test(target) && words.includes('id') && !words.some((w) => PIN_FETCH_WORDS.has(w))) return 'pinned';
    }
    // `return CitationNetwork(case_uri=uri, …)`: a data model handed back, held by nothing but data.
    const heldByData = frame.open.slice(0, j).every((o) => src[o] === '{' || (src[o] === '[' && !/[\w$\])]\s*$/.test(src.slice(Math.max(frame.stmt, o - 80), o))));
    if (returns && heldByData && /^[A-Z]/.test(last) && !PIN_REQUESTISH.test(last)) return 'inert';
    return 'open';
  }
  const prefix = src.slice(frame.stmt, anchor);
  if (anchor === at) {
    const rest = src.slice(at + name.length, Math.min(to, at + name.length + 200));
    // `uri = case_uri.lstrip("/")`: a copy, followed in its own right.
    const target = PIN_ASSIGN_HEAD.exec(prefix)?.[1];
    if (target && PIN_COPY_TAIL.test(rest)) return { alias: target };
    // The name assigned to (`url = url.strip()`): the value it takes is its own use.
    if (/^\s*$/.test(prefix) && /^\s*(?::[^=\n]{1,60})?=(?![=>])/.test(rest)) return 'inert';
  }
  // `if not url:`, `assert url`, `return url`, `return {"url": url}`.
  return /^\s*(?:else\s+)?(?:if|elif|while|assert|return)\b/.test(prefix) ? 'inert' : 'open';
}

const pinnedMemo = new WeakMap<Reader, Map<string, string[] | undefined>>();

/**
 * The URL / host parameters among a registration's schema names whose
 * destination its handler pins. One handler shared by thousands of
 * registrations is read once.
 */
function pinnedOf(r: Reader, fn: FnInfo | undefined, names: readonly string[] | undefined): string[] | undefined {
  if (!fn || !names?.length) return undefined;
  const candidates = names.filter(namesDestinationParam).slice(0, 8);
  if (!candidates.length) return undefined;
  let memo = pinnedMemo.get(r);
  if (!memo) pinnedMemo.set(r, (memo = new Map()));
  const key = `${fn.bodyStart}:${candidates.join(',')}`;
  if (memo.has(key)) return memo.get(key);
  const out = pinnedParams(r, fn, candidates);
  const result = out.length ? out : undefined;
  if (memo.size < 4096) memo.set(key, result);
  return result;
}

/** An HTTP write in a body: where the call is, and the arguments after its URL (the payload and the options). */
interface WriteSite {
  at: number;
  sent: [number, number][];
  why: string;
}
interface Writes {
  ev: HandlerEvidence[];
  sites: WriteSite[];
}
const writesMemo = new WeakMap<Reader, Map<string, Writes>>();

/** HTTP writes (external-sink) and database writes (state-write) in a handler body — once per body. */
function writesIn(r: Reader, from: number, to: number): HandlerEvidence[] {
  return writesOf(r, from, to).ev;
}

function writesOf(r: Reader, from: number, to: number): Writes {
  let m = writesMemo.get(r);
  if (!m) writesMemo.set(r, (m = new Map()));
  const key = `${from}:${to}`;
  const hit = m.get(key);
  if (hit) return hit;
  const v = writesInUncached(r, from, to);
  m.set(key, v);
  return v;
}

/**
 * How many POSTs sent with a `method:` options object are read for positive
 * evidence (see `requestReads`) in one function body. The rest are judged as
 * 1.16.0 judged them: a read only at a literal search / GraphQL URL, a sink
 * otherwise. A body of thousands of options objects is padding, not a client.
 */
const MAX_OPTIONS_READ = 64;
/** HTTP writes per body read for what they carry out (see `leaksIn`): the rest is padding. */
const MAX_WRITE_SITES = 64;

function writesInUncached(r: Reader, from: number, to: number): Writes {
  const { src, ctx } = r;
  const out: HandlerEvidence[] = [];
  const sites: WriteSite[] = [];
  const body = src.slice(from, to);

  for (const m of body.matchAll(/\.\s*(post|put|patch|delete)\s*\(/gi)) {
    const at = from + m.index!;
    if (!ctx.isCode(at)) continue;
    const method = m[1]!.toUpperCase();
    const chain = /([A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)\s*$/.exec(src.slice(Math.max(from, at - 80), at))?.[1] ?? '';
    const recv = chain.split(/\s*\??\.\s*/).pop() ?? '';
    // Workers bindings (`env.STATS.put`), collections, routers — not requests.
    if (!recv || NOT_HTTP.test(recv) || /^[A-Z][A-Z0-9_]+$/.test(recv) || /\benv\s*\./.test(chain)) continue;
    const open = at + m[0].length - 1;
    const args = r.parts(open) ?? [];
    // `app.post('/x', handler)` defines a route; it sends nothing.
    if (args.slice(1).some(([a, b]) => isFnText(r.text(a, b)))) continue;
    const first = args[0] ? src.slice(args[0][0], args[0][1]).trim() : '';
    const lit = /^[`'"]/.test(first) ? first.slice(1) : '';
    const urlLike = /^(?:\/|https?:\/\/)/.test(lit) || /^\$\{\s*[\w$.]*(?:url|base|host|api|endpoint|origin|server)[\w$.]*\s*\}/i.test(lit);
    // A client receiver still needs a URL-ish target: `client.put('last_read')`
    // on an etcd/KV client is not an HTTP PUT.
    const target = urlLike || /^[A-Za-z_$][\w$.]*$/.test(first) && /url|uri|path|endpoint|href|route|link/i.test(first) || /^[A-Za-z_$][\w$.]*\s*\(/.test(first) && /url|path|endpoint|route/i.test(first.split('(')[0]!);
    const http = HTTP_CLIENT.test(recv) && target;
    if (!http && !(urlLike && method !== 'DELETE')) continue;
    if (method === 'POST') {
      // The payload is the second argument (the options, for got / ky) or a
      // Python `json=` / `data=` keyword; an axios config and `headers=` are
      // read for what they carry (see `postParts`, `requestReads`).
      const req = postParts(r, first, args.slice(1).map(([a, b]) => src.slice(a, b).trim()), recv, bodyIndex(r, from, to), at);
      if (requestReads(r, req, from, to, at, true)) continue;
    }
    const why = `handler sends an HTTP ${method} (${clip(src.slice(at - chain.length - 1, open + 1) + first)})`;
    out.push({ tag: 'external-sink', why, line: ctx.line(at) });
    if (sites.length < MAX_WRITE_SITES) sites.push({ at, sent: args.slice(1), why });
  }

  // `fetch(url, { method: 'POST' })`, `axios({ method: 'put' })` — the method key
  // must sit in an object passed to a request function, and only that call's URL
  // decides whether it is a read-only query.
  let optionsRead = 0;
  for (const mm of body.matchAll(/\bmethod\s*:\s*(['"`])(POST|PUT|PATCH|DELETE)\1/gi)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    // The options object sits in the call, or is built first and passed by name: `const opts = { method: 'POST', body }; fetch(url, opts)`.
    const call = [enclosingCall(r, at, from), optionsSentByName(r, at, from, to)].find((c) => c && REQUEST_FN.test(c.callee));
    if (!call) continue;
    const a0 = call.args[0] ? src.slice(call.args[0][0], call.args[0][1]).trim() : '';
    // `axios({ method, url, data })` holds its URL in the config; `fetch(url, { method, body })` takes it first.
    const config = a0.startsWith('{') || (call.args.length === 1 && /^[A-Za-z_$][\w$]*$/.test(a0) && !/url|uri|endpoint|href/i.test(a0));
    const url = config ? '' : a0;
    const method = mm[2]!.toUpperCase();
    if (method === 'POST') {
      if (++optionsRead > MAX_OPTIONS_READ) {
        if (READ_ONLY_POST.test(a0) && /^[`'"]/.test(a0)) continue;
      } else {
        const req: RequestParts = { url, body: [], headers: [], credentials: [], extra: [] };
        for (const [a, b] of config ? call.args : call.args.slice(1)) fileOptions(r, req, src.slice(a, b), bodyIndex(r, from, to), at, 'body');
        if (requestReads(r, req, from, to, at, false)) continue;
      }
    }
    const why = `handler sends an HTTP ${method} (${clip(call.callee + '(' + (url || a0).trim())})`;
    out.push({ tag: 'external-sink', why, line: ctx.line(at) });
    if (sites.length < MAX_WRITE_SITES) sites.push({ at, sent: config ? call.args : call.args.slice(1), why });
  }

  // Python: `requests.request("DELETE", url)`, `session.request('post', …)`. A
  // POST is read by its URL argument as the `.post(…)` form is (`/jobs/list`).
  for (const mm of body.matchAll(/\.\s*request\s*\(\s*(['"])(POST|PUT|PATCH|DELETE)\1/gi)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    const method = mm[2]!.toUpperCase();
    const args = r.parts(at + mm[0].indexOf('(')) ?? [];
    if (method === 'POST') {
      const url = args[1] ? src.slice(args[1][0], args[1][1]).trim() : '';
      const req = postParts(r, url, args.slice(2).map(([a, b]) => src.slice(a, b).trim()), 'requests', bodyIndex(r, from, to), at);
      if (requestReads(r, req, from, to, at, false)) continue;
    }
    const why = `handler sends an HTTP ${method} (request("${mm[2]}", …))`;
    out.push({ tag: 'external-sink', why, line: ctx.line(at) });
    if (sites.length < MAX_WRITE_SITES) sites.push({ at, sent: args.slice(2), why });
  }

  // Database writes: an ORM mutation, a Mongo write, a write statement in SQL.
  for (const mm of body.matchAll(/\b(prisma|db|this\.prisma|this\.db)\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*(create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/g)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    out.push({ tag: 'state-write', why: `handler writes to the database (${mm[1]}.${mm[2]}.${mm[3]}(…))`, line: ctx.line(at) });
  }
  for (const mm of body.matchAll(/\.\s*(insertOne|insertMany|updateOne|updateMany|replaceOne|deleteOne|deleteMany|findOneAndUpdate|findOneAndDelete|findOneAndReplace|bulkWrite)\s*\(/g)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    out.push({ tag: 'state-write', why: `handler writes to the database (${mm[1]}(…))`, line: ctx.line(at) });
  }
  for (const mm of body.matchAll(/\.\s*(?:query|execute|exec|run|prepare)\s*\(\s*[`'"]\s*(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|REPLACE|MERGE|UPSERT)\b/gi)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    out.push({ tag: 'state-write', why: `handler runs a ${mm[1]!.toUpperCase()} statement`, line: ctx.line(at) });
  }
  return { ev: out, sites };
}

const clip = (s: string): string => {
  const t = s.replace(/\s+/g, ' ');
  return t.length > 90 ? `${t.slice(0, 90)}…` : t;
};

/** The call whose argument list contains offset `at` (via an object literal), within `floor`. */
function enclosingCall(r: Reader, at: number, floor: number): { callee: string; args: [number, number][] } | undefined {
  const { src } = r;
  let depth = 0;
  for (let i = at - 1, steps = 0; i >= floor && steps < 3000; i--, steps++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === ')' || c === ']' || c === '}') depth++;
    else if (c === '(' || c === '[' || c === '{') {
      if (depth > 0) {
        depth--;
        continue;
      }
      if (c !== '(') continue; // the object literal holding `method:`; keep climbing to its call
      const callee = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*$/.exec(src.slice(Math.max(floor, i - 80), i))?.[1]?.replace(/\s+/g, '') ?? '';
      const args = r.parts(i) ?? [];
      return { callee, args };
    }
  }
  return undefined;
}

/** A function that sends a request when called with an options object. */
const REQUEST_FN = /(?:^|\.)(?:fetch|\$fetch|ofetch|axios|request|got|ky|undici|fetchJson|apiFetch|http|https)$/i;

/** A call of a request function, by name: `fetch(`, `api.request(`, `this.client.fetchJson(`. */
const REQUEST_CALL = /(?<![\w$])((?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:fetch|\$fetch|ofetch|axios|request|got|ky|fetchJson|apiFetch))\s*\(/g;

interface RequestCall {
  at: number;
  callee: string;
  /** The `(` of the call. */
  open: number;
  /** Its arguments, split on first use. */
  args?: [number, number][];
}
const requestCallsMemo = new WeakMap<Reader, Map<string, RequestCall[]>>();

/**
 * Every request call in the function body [from, to), in source order — found
 * once per body. A body of fifty thousand options objects looks each one's
 * request up here instead of scanning the rest of the body again.
 */
function requestCalls(r: Reader, from: number, to: number): RequestCall[] {
  let memo = requestCallsMemo.get(r);
  if (!memo) requestCallsMemo.set(r, (memo = new Map()));
  const key = `${from}:${to}`;
  const hit = memo.get(key);
  if (hit) return hit;
  const out: RequestCall[] = [];
  for (const m of r.src.slice(from, to).matchAll(REQUEST_CALL)) {
    out.push({ at: from + m.index!, callee: m[1]!.replace(/\s+/g, ''), open: from + m.index! + m[0].length - 1 });
  }
  memo.set(key, out);
  return out;
}

/**
 * `const opts = { method: 'POST', body }; await fetch(url, opts)` — the request
 * the options object holding `at` is passed to by name, among the first sixteen
 * request calls after it in [floor, to).
 */
function optionsSentByName(r: Reader, at: number, floor: number, to: number): { callee: string; args: [number, number][] } | undefined {
  const { src } = r;
  let depth = 0;
  let open = -1;
  for (let i = at - 1, steps = 0; i >= floor && steps < 3000; i--, steps++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === ')' || c === ']' || c === '}') depth++;
    else if (c === '(' || c === '[' || c === '{') {
      if (depth > 0) {
        depth--;
        continue;
      }
      if (c === '{') open = i;
      break;
    }
  }
  if (open < 0) return undefined;
  const name = /(?:^|[\s;(])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{1,80})?=\s*$/.exec(src.slice(Math.max(floor, open - 160), open))?.[1];
  const close = r.close(open);
  if (!name || close < 0) return undefined;
  const calls = requestCalls(r, floor, to);
  let lo = 0;
  let hi = calls.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (calls[mid]!.at < close) lo = mid + 1;
    else hi = mid;
  }
  for (let k = lo; k < calls.length && k < lo + 16; k++) {
    const call = calls[k]!;
    if (!r.ctx.isCode(call.at)) continue;
    call.args ??= r.parts(call.open) ?? [];
    if (call.args.some(([a, b]) => src.slice(a, b).trim() === name)) return { callee: call.callee, args: call.args };
  }
  return undefined;
}

// --- parameters -------------------------------------------------------------------

interface Param {
  index: number;
  /** A plain binding (`name`, `name = default`). */
  name?: string;
  /** `...rest` */
  rest?: boolean;
  /** An object pattern: key → local, with per-key defaults and an optional rest. */
  keys?: { key: string; local: string; dflt?: [number, number] }[];
  restKey?: string;
  /** An array pattern. */
  items?: string[];
  dflt?: [number, number];
}

/** The parameters of a JS function, read from its header: patterns, defaults and rests included. */
function paramsOf(r: Reader, fn: FnInfo): Param[] {
  const { src } = r;
  // The parameter list: the first `(` after the header that closes before the body.
  let open = -1;
  for (let i = fn.headerStart; i < fn.bodyStart && i < fn.headerStart + 400; i++) {
    if (src[i] === '(' && r.ctx.isCode(i)) {
      open = i;
      break;
    }
  }
  if (open < 0) {
    // `x => …`
    const id = /^[A-Za-z_$][\w$]*/.exec(src.slice(fn.headerStart));
    return id ? [{ index: 0, name: id[0] }] : [];
  }
  const close = r.close(open);
  if (close < 0 || close > fn.bodyStart) return fn.params.map((p) => ({ index: p.index, ...(p.name ? { name: p.name } : {}) }));
  const out: Param[] = [];
  const parts = paramParts(r, open, close);
  parts.forEach(([a, b], index) => {
    const [from, to] = r.trim(a, b);
    const t = src.slice(from, to);
    if (t.startsWith('...')) {
      const id = /^\.\.\.\s*([A-Za-z_$][\w$]*)/.exec(t);
      out.push({ index, ...(id ? { name: id[1]! } : {}), rest: true });
      return;
    }
    if (src[from] === '{' || src[from] === '[') {
      const end = r.close(from);
      if (end < 0 || end >= to) return out.push({ index });
      const p: Param = { index };
      const eq = /^\s*(?::[^=]{1,200}?)?=(?![=>])/.exec(src.slice(end + 1, to));
      if (eq) p.dflt = [end + 1 + eq[0].length, to];
      if (src[from] === '[') {
        p.items = src.slice(from + 1, end).split(',').map((x) => (/^\s*([A-Za-z_$][\w$]*)/.exec(x)?.[1] ?? ''));
      } else {
        p.keys = [];
        for (const [ea, eb] of r.parts(from) ?? []) {
          const [ef, et] = r.trim(ea, eb);
          const e = src.slice(ef, et);
          const rest = /^\.\.\.\s*([A-Za-z_$][\w$]*)$/.exec(e);
          if (rest) {
            p.restKey = rest[1]!;
            continue;
          }
          const m = /^([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?\s*(=(?![=>]))?/.exec(e);
          if (!m) continue;
          p.keys.push({ key: m[1]!, local: m[2] ?? m[1]!, ...(m[3] ? { dflt: [ef + m[0].length, et] as [number, number] } : {}) });
        }
      }
      out.push(p);
      return;
    }
    // `name?: Type = default` — a TypeScript type may hold `=>`, a default never starts with `>`.
    const id = /^([A-Za-z_$][\w$]*)/.exec(src.slice(from, to));
    if (!id) return out.push({ index });
    const eqAt = findDefaultEq(r, from + id[0].length, to);
    out.push({ index, name: id[1]!, ...(eqAt >= 0 ? { dflt: [eqAt + 1, to] as [number, number] } : {}) });
  });
  return out;
}

/**
 * Top-level parameters between `open` and `close`: a comma inside a TypeScript
 * generic (`Map<string, unknown>`) is not a boundary.
 */
function paramParts(r: Reader, open: number, close: number): [number, number][] {
  const { src } = r;
  const out: [number, number][] = [];
  let start = open + 1;
  let angle = 0;
  for (let i = open + 1; i < close; i++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = r.close(i);
      if (e < 0 || e > close) break;
      i = e;
      continue;
    }
    if (c === '<' && /[\w$]/.test(src[i - 1] ?? '')) angle++;
    else if (c === '>' && angle > 0 && src[i - 1] !== '=') angle--;
    else if (c === ',' && angle === 0) {
      out.push([start, i]);
      start = i + 1;
    }
  }
  if (src.slice(start, close).trim()) out.push([start, close]);
  return out;
}

/** The `=` of a parameter default at the top level of a range (not `=>`, `==`, `<=`). */
function findDefaultEq(r: Reader, from: number, to: number): number {
  const { src } = r;
  let angle = 0;
  for (let i = from; i < to; i++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') {
      const e = r.close(i);
      if (e < 0) return -1;
      i = e;
      continue;
    }
    if (c === '<') angle++;
    else if (c === '>' && src[i - 1] !== '=') angle = Math.max(0, angle - 1);
    else if (c === '=' && angle === 0 && src[i + 1] !== '>' && src[i + 1] !== '=' && !/[=!<>]/.test(src[i - 1] ?? '')) return i;
  }
  return -1;
}

/** Does the function body reassign or write into this parameter? Then its value is not the argument. */
function reassigned(r: Reader, fn: FnInfo, name: string): boolean {
  const key = `${fn.bodyStart}\u0000${name}`;
  const hit = r.reassignedMemo.get(key);
  if (hit !== undefined) return hit;
  const v = computeReassigned(r, fn, name);
  r.reassignedMemo.set(key, v);
  return v;
}

function computeReassigned(r: Reader, fn: FnInfo, name: string): boolean {
  const body = r.src.slice(fn.bodyStart, fn.bodyEnd);
  const n = name.replace(/[$]/g, '\\$');
  if (r.py) {
    // A Python assignment starts a statement; `annotations=x` inside a call is a keyword argument.
    return (
      new RegExp(`^[ \\t]*${n}[ \\t]*(?:\\.[ \\t]*\\w+[ \\t]*|\\[[^\\]\\n]{0,100}\\][ \\t]*)?(?:[+\\-*/%&|^]|//|\\*\\*)?=(?!=)`, 'm').test(body) ||
      new RegExp(`(?<![\\w.])${n}\\s*\\.\\s*(?:setdefault|update|pop|clear|__setitem__)\\s*\\(`).test(body)
    );
  }
  return (
    new RegExp(`(?<![\\w$.])${n}\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*\\s*|\\[[^\\]\\n]{0,100}\\]\\s*)?(?:[+\\-*/%&|^]|\\?\\?|\\|\\||&&)?=(?![=>])`).test(body) ||
    new RegExp(`Object\\s*\\.\\s*assign\\s*\\(\\s*${n}\\b`).test(body) ||
    new RegExp(`(?<![\\w$.])${n}\\s*\\.\\s*(?:setdefault|update|pop|clear)\\s*\\(`).test(body)
  );
}

/** Bind a JS helper's parameters to one call's arguments: defaults for missing or `undefined`, patterns, rests. */
function bindParams(r: Reader, fn: FnInfo, args: [number, number][], outer: Env | null): Env {
  const vars = new Map<string, Thunk>();
  const env: Env = { vars, fn, parent: outer };
  const argThunk = (i: number): Thunk | undefined => {
    const a = args[i];
    if (!a) return undefined;
    if (/^\s*(?:undefined|void\s+0)\s*$/.test(r.text(a[0], a[1]))) return undefined;
    return { from: a[0], to: a[1], env: outer };
  };
  const dfltThunk = (d: [number, number] | undefined): Thunk => (d ? { from: d[0], to: d[1], env } : { val: NULLISH });
  for (const p of r.params(fn)) {
    if (p.rest && p.name) {
      vars.set(p.name, { val: { k: 'arr', items: args.slice(p.index).map(([a, b]) => ({ from: a, to: b, env: outer })), open: false } });
      continue;
    }
    if (p.name) {
      vars.set(p.name, reassigned(r, fn, p.name) ? { val: UNKNOWN } : (argThunk(p.index) ?? dfltThunk(p.dflt)));
      continue;
    }
    const source = argThunk(p.index) ?? (p.dflt ? dfltThunk(p.dflt) : undefined);
    const v = source ? r.ev(source) : NULLISH;
    if (p.keys) {
      for (const k of p.keys) {
        if (reassigned(r, fn, k.local)) {
          vars.set(k.local, { val: UNKNOWN });
          continue;
        }
        const f = v.k === 'obj' ? v.fields.get(k.key) : undefined;
        if (f) vars.set(k.local, f);
        else if (v.k === 'obj' && v.open) vars.set(k.local, { val: UNKNOWN });
        else if (v.k === 'obj' || (v.k === 'lit' && v.v === null)) vars.set(k.local, dfltThunk(k.dflt));
        else vars.set(k.local, { val: UNKNOWN });
      }
      if (p.restKey) {
        if (v.k !== 'obj' || reassigned(r, fn, p.restKey)) vars.set(p.restKey, { val: UNKNOWN });
        else {
          const taken = new Set(p.keys.map((k) => k.key));
          const rest = new Map([...v.fields].filter(([k]) => !taken.has(k)));
          vars.set(p.restKey, { val: { k: 'obj', fields: rest, open: v.open } });
        }
      }
    } else if (p.items) {
      p.items.forEach((nm, i) => {
        if (nm) vars.set(nm, v.k === 'arr' ? (v.items[i] ?? { val: NULLISH }) : { val: UNKNOWN });
      });
    }
  }
  return env;
}

// --- helpers ------------------------------------------------------------------

interface Helper {
  fn: FnInfo;
  name: string;
  /** Registrations (or inner helper calls) inside the helper's body. */
  inner: Array<{ reg: RegCall } | { helper: Helper; call: { index: number; args: [number, number][] } }>;
}

/** Is this name-argument expression one of the function's parameters (`name`, `def.name`, `{ name }`)? */
function paramRef(r: Reader, fn: FnInfo, from: number, to: number): boolean {
  const t = r.text(from, to).trim();
  const id = /^([A-Za-z_$][\w$]*)(?:\s*\??\.\s*name)?$/.exec(t)?.[1];
  const names = new Set<string>();
  for (const p of r.params(fn)) {
    if (p.name) names.add(p.name);
    for (const k of p.keys ?? []) names.add(k.local);
    if (p.restKey) names.add(p.restKey);
  }
  if (id) return names.has(id);
  // `addTool({ ...def })`, `addTool({ name, … })`, `addTool({ name: n, … })` —
  // an object whose `name` comes from a parameter.
  if (t.startsWith('{') && from < to) {
    for (const [a, b] of r.parts(from + (r.text(from, to).length - r.text(from, to).trimStart().length)) ?? []) {
      const part = r.text(a, b).trim();
      const spread = /^\.\.\.\s*([A-Za-z_$][\w$]*)$/.exec(part)?.[1];
      if (spread && names.has(spread)) return true;
      if (part === 'name' && names.has('name')) return true;
      const kv = /^name\s*:\s*([A-Za-z_$][\w$]*)$/.exec(part)?.[1];
      if (kv && names.has(kv)) return true;
    }
  }
  return false;
}

/** Is `name`, at offset `at`, the file's function — not a parameter or local that shadows it there? */
function unshadowed(r: Reader, name: string, at: number): boolean {
  const inner = r.enclosing(at);
  const key = `${name}\u0000${inner ? inner.bodyStart : -1}`;
  const hit = r.shadowMemo.get(key);
  if (hit !== undefined) return hit;
  let ok = true;
  // Walk out through the enclosing functions (O(depth) via the owner index).
  for (let f: FnInfo | null = inner, guard = 0; f && guard < 64; f = r.enclosing(f.headerStart > 0 ? f.headerStart - 1 : 0), guard++) {
    if (f.params.some((p) => p.name === name || [...(p.keys?.values() ?? [])].includes(name))) {
      ok = false;
      break;
    }
    if (f.headerStart <= 0) break;
  }
  if (ok) ok = !r.ctx.declsOf(name).some((d) => d.scope && at >= d.scope.bodyStart && at < d.scope.bodyEnd);
  r.shadowMemo.set(key, ok);
  return ok;
}

function findHelpers(r: Reader, regs: RegCall[], isMcp: boolean): Helper[] {
  const helpers = new Map<string, Helper>();
  for (const reg of regs) {
    if (!mcpCall(reg, isMcp)) continue;
    const fn = r.enclosing(reg.at);
    if (!fn?.name || !r.fnNamed(fn.name)) continue;
    const nameArg = reg.args[0];
    if (!nameArg || !paramRef(r, fn, nameArg[0], nameArg[1])) continue;
    const h = helpers.get(fn.name) ?? { fn, name: fn.name, inner: [] };
    h.inner.push({ reg });
    helpers.set(fn.name, h);
  }
  // A helper that calls a helper with its own parameter as the name.
  for (let pass = 0; pass < 3; pass++) {
    let grew = false;
    for (const inner of [...helpers.values()]) {
      const nameIdx = helperNameIndex(r, inner);
      if (nameIdx === undefined) continue;
      for (const call of r.ctx.callSitesOf(inner.name)) {
        const fn = r.enclosing(call.index);
        if (!fn?.name || fn === inner.fn || !r.fnNamed(fn.name) || !unshadowed(r, inner.name, call.index)) continue;
        const a = call.args.starts[nameIdx];
        if (a === undefined) continue;
        if (!paramRef(r, fn, a, a + call.args.args[nameIdx]!.length)) continue;
        const outer = helpers.get(fn.name) ?? { fn, name: fn.name, inner: [] };
        if (outer.inner.some((x) => 'call' in x && x.call.index === call.index)) continue;
        outer.inner.push({ helper: inner, call: { index: call.index, args: call.args.args.map((t, i) => [call.args.starts[i]!, call.args.starts[i]! + t.length] as [number, number]) } });
        if (!helpers.has(fn.name)) {
          helpers.set(fn.name, outer);
          grew = true;
        }
      }
    }
    if (!grew) break;
  }
  return [...helpers.values()];
}

/** Which of a helper's parameters carries the tool name. */
function helperNameIndex(r: Reader, h: Helper, depth = 0): number | undefined {
  if (depth > 4) return undefined;
  const params = r.params(h.fn);
  for (const x of h.inner) {
    let arg: [number, number] | undefined;
    if ('reg' in x) arg = x.reg.args[0];
    else {
      const i = helperNameIndex(r, x.helper, depth + 1);
      arg = i === undefined ? undefined : x.call.args[i];
    }
    if (!arg) continue;
    const t = r.text(arg[0], arg[1]).trim();
    const id = /^\{?\s*(?:\.\.\.\s*)?([A-Za-z_$][\w$]*)/.exec(t)?.[1];
    const p = params.find((q) => q.name === id || q.keys?.some((k) => k.local === id) || q.restKey === id);
    if (p) return p.index;
  }
  return undefined;
}

// --- loops --------------------------------------------------------------------

interface Loop {
  pattern: string;
  iter: [number, number];
  body: [number, number];
}

function jsLoops(r: Reader): Loop[] {
  const { src, ctx } = r;
  const out: Loop[] = [];
  for (const m of src.matchAll(/\bfor\s*\(\s*(?:const|let|var)\s+/g)) {
    if (!ctx.isCode(m.index!)) continue;
    const open = src.indexOf('(', m.index!);
    const close = r.close(open);
    if (close < 0) continue;
    const head = src.slice(open + 1, close);
    if (head.length > 600) continue;
    const of = /^\s*(?:const|let|var)\s+([\s\S]+?)\s+of\s+([\s\S]+)$/.exec(head);
    if (!of) continue;
    const iterFrom = open + 1 + head.lastIndexOf(of[2]!);
    let j = close + 1;
    while (j < src.length && /\s/.test(src[j]!)) j++;
    const end = src[j] === '{' ? r.close(j) : statementEnd(r, j);
    if (end < 0) continue;
    out.push({ pattern: of[1]!.trim(), iter: [iterFrom, iterFrom + of[2]!.length], body: [j, end] });
  }
  // `ITER.forEach((t) => …)` / `.map(…)`: the callback is an anonymous function.
  for (const f of ctx.functions()) {
    if (f.name) continue;
    const before = src.slice(Math.max(0, f.headerStart - 40), f.headerStart);
    const m = /\.\s*(?:forEach|map|flatMap)\s*\(\s*$/.exec(before);
    if (!m) continue;
    const dot = f.headerStart - (before.length - m.index);
    const recvStart = receiverStart(r, dot);
    if (recvStart < 0) continue;
    let pat = '';
    let p = f.headerStart;
    if (src.startsWith('async', p)) p += 5;
    while (/\s/.test(src[p] ?? '')) p++;
    if (src[p] === '(') {
      const pc = r.close(p);
      if (pc < 0) continue;
      const first = (r.parts(p) ?? [])[0];
      pat = first ? src.slice(first[0], first[1]).trim() : '';
    } else pat = /^[A-Za-z_$][\w$]*/.exec(src.slice(p))?.[0] ?? '';
    if (!pat) continue;
    out.push({ pattern: pat, iter: [recvStart, dot], body: [f.bodyStart, f.bodyEnd] });
  }
  return out;
}

/** Start of the receiver expression that ends right before `dot` (`Object.entries(TOOLS)`, `TOOLS`). */
function receiverStart(r: Reader, dot: number): number {
  const { src } = r;
  let i = dot;
  while (i > 0 && /\s/.test(src[i - 1]!)) i--;
  for (let guard = 0; guard < 20 && i > 0; guard++) {
    const c = src[i - 1]!;
    if (c === ')' || c === ']') {
      // Walk back to the partner bracket.
      let k = i - 2;
      let depth = 1;
      for (let steps = 0; k >= 0 && steps < 20_000; k--, steps++) {
        if (!r.ctx.isCode(k)) continue;
        const ch = src[k];
        if (ch === ')' || ch === ']') depth++;
        else if (ch === '(' || ch === '[') {
          depth--;
          if (depth === 0) break;
        }
      }
      if (k < 0 || depth !== 0) return -1;
      i = k;
      continue;
    }
    if (/[\w$]/.test(c)) {
      while (i > 0 && /[\w$]/.test(src[i - 1]!)) i--;
      if (src[i - 1] === '.') {
        i--;
        continue;
      }
      return i;
    }
    return i;
  }
  return -1;
}

/** Bind a loop pattern (`t`, `[name, def]`, `{ name, ...config }`) to one element. */
function bindPattern(r: Reader, pattern: string, el: Thunk, outer: Env | null): Env | null {
  const vars = new Map<string, Thunk>();
  const p = pattern.replace(/:\s*[\w$.<>[\]|, ]+$/, '').trim();
  if (/^[A-Za-z_$][\w$]*$/.test(p)) vars.set(p, el);
  else if (p.startsWith('[')) {
    const names = p.slice(1, -1).split(',').map((x) => x.trim());
    const v = r.ev(el);
    if (v.k !== 'arr') return null;
    names.forEach((n, i) => {
      if (/^[A-Za-z_$][\w$]*$/.test(n)) vars.set(n, v.items[i] ?? { val: NULLISH });
    });
  } else if (p.startsWith('{')) {
    const v = r.ev(el);
    if (v.k !== 'obj') return null;
    const taken = new Set<string>();
    for (const entry of p.slice(1, -1).split(',')) {
      const e = entry.trim();
      const rest = /^\.\.\.\s*([A-Za-z_$][\w$]*)$/.exec(e);
      if (rest) {
        vars.set(rest[1]!, { val: { k: 'obj', fields: new Map([...v.fields].filter(([k]) => !taken.has(k))), open: v.open } });
        continue;
      }
      const [k, local] = e.split(':').map((x) => x?.trim());
      const key = (k ?? '').replace(/\s*=.*$/, '');
      const name = (local || key).replace(/\s*=.*$/, '');
      if (!/^[A-Za-z_$][\w$]*$/.test(key) || !/^[A-Za-z_$][\w$]*$/.test(name)) continue;
      taken.add(key);
      vars.set(name, v.fields.get(key) ?? { val: v.open ? UNKNOWN : NULLISH });
    }
  } else return null;
  return { vars, fn: null, parent: outer };
}

/**
 * `if (t.disabled) continue;` as a direct statement of a loop body, evaluated for
 * one element: `skip` only when the guard certainly fires and its consequent is
 * nothing but the `continue`/`return`; a condition when it may fire or does more.
 */
const guardCache = new WeakMap<Reader, Map<number, IfStmt[]>>();

function loopGuards(r: Reader, loop: Loop, at: number): IfStmt[] {
  let m = guardCache.get(r);
  if (!m) guardCache.set(r, (m = new Map()));
  const key = loop.body[0] * 1_000_003 + at;
  const hit = m.get(key);
  if (hit) return hit;
  const all = ifStatements(r);
  let lo = 0;
  let hi = all.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (all[mid]!.at < loop.body[0]) lo = mid + 1;
    else hi = mid;
  }
  const owner = r.enclosing(at);
  const cands: IfStmt[] = [];
  for (let k = lo; k < all.length && all[k]!.at < at; k++) {
    const st = all[k]!;
    if (st.fn !== owner || (st.exit !== 'continue' && st.exit !== 'return')) continue;
    if (at >= st.then[0] && at <= st.then[1]) continue;
    cands.push(st);
  }
  // Direct statements of the loop body only: an `if` nested in another block of
  // the body guards that block, not the registration.
  const inner = r.src[loop.body[0]] === '{' ? loop.body[0] + 1 : loop.body[0];
  const base = loopDepth(r, inner);
  const out = cands.filter((c) => c.depth === base);
  m.set(key, out);
  return out;
}

const loopDepthCache = new WeakMap<Reader, Map<number, number>>();
const loopStarts = new WeakMap<Reader, number[]>();

/** Brace depth just inside a loop body — every loop's computed in one pass the first time one is asked. */
function loopDepth(r: Reader, inner: number): number {
  let m = loopDepthCache.get(r);
  if (!m) {
    const starts = loopStarts.get(r) ?? [inner];
    m = braceDepths(r.src, r.ctx.mask, starts.includes(inner) ? starts : [...starts, inner]);
    loopDepthCache.set(r, m);
  }
  if (!m.has(inner)) m.set(inner, braceDepths(r.src, r.ctx.mask, [inner]).get(inner) ?? 0);
  return m.get(inner)!;
}

function loopGuard(r: Reader, loop: Loop, at: number, env: Env): 'skip' | RegistrationCondition | undefined {
  for (const st of loopGuards(r, loop, at)) {
    const t = r.truthy(r.evRange(st.exprFrom, st.exprTo, env, 0));
    const bare = /^\{?\s*(?:continue|return)\b[^;{}]{0,200};?\s*\}?$/.test(r.text(st.then[0], st.then[1] + 1).trim());
    if (t === true && bare) return 'skip';
    if (t !== false) return { kind: 'unless', expr: st.expr, line: r.ctx.line(st.at) };
  }
  return undefined;
}

// --- MCP evidence -------------------------------------------------------------------

/** Does the file show it is an MCP server? Required before a helper or a loop may produce tools. */
function mcpFile(r: Reader): boolean {
  return r.py
    ? /^[ \t]*(?:from[ \t]+(?:mcp|fastmcp)\b|import[ \t]+(?:mcp|fastmcp)\b)|\bFastMCP\s*\(/m.test(r.src)
    : /@modelcontextprotocol\/sdk|['"]fastmcp['"]|['"]mcp-framework['"]|\bMcpServer\b|\bFastMCP\b|ListToolsRequestSchema/.test(r.src);
}

const MCP_RECEIVER = /(?:^|\.)(?:server|mcp|mcpServer|mcp_server|srv|fastmcp|app)$/i;

/**
 * May this registration call feed a helper or a loop? `registerTool` and
 * `addTool` are MCP names; a bare `.tool(` needs an MCP file or a receiver that
 * looks like a server — `tracker.tool(ev, …)` over a list of events is not.
 */
function mcpCall(call: RegCall, isMcp: boolean): boolean {
  return isMcp || call.method !== 'tool' || MCP_RECEIVER.test(call.receiver);
}

/** Is this file minified? Measured on CODE only: an embedded base64 logo or a long description is a string. */
function minified(r: Reader): boolean {
  const { src, ctx } = r;
  let code = 0;
  let longCode = 0;
  let lineStart = 0;
  let lineCode = 0;
  for (let i = 0; i <= src.length; i++) {
    if (i === src.length || src.charCodeAt(i) === 10) {
      // A long line is minified CODE only when it is dense with statements — a
      // one-line lookup table or list of numbers is data.
      if (i - lineStart > 1000) {
        const line = src.slice(lineStart, Math.min(i, lineStart + 200_000));
        const stmts = (line.match(/\b(?:function|return|var|let|const|if|for|while)\b|=>/g) ?? []).length;
        if (stmts >= 20) longCode += lineCode;
      }
      lineStart = i + 1;
      lineCode = 0;
      continue;
    }
    if (ctx.isCode(i) && src.charCodeAt(i) > 32) {
      code++;
      lineCode++;
    }
  }
  return code > 2000 && longCode / code > 0.5;
}

// --- tools/list objects ----------------------------------------------------------

/** `{ name: 'x', description, inputSchema, annotations }` objects of a low-level `tools/list` handler. */
function listToolObjects(r: Reader, file: string, emit: (o: { name: string; at: number; obj: Val; own: [number, number][] }) => void): void {
  if (!/ListToolsRequestSchema|['"`]tools\/list['"`]/.test(r.src)) return;
  let scanned = 0;
  for (const m of r.src.matchAll(/\bname\s*:\s*(['"`])([A-Za-z0-9._:-]{1,128})\1/g)) {
    if (++scanned > 2 * MAX_REGS) break;
    const at = m.index!;
    if (!r.ctx.isCode(at)) continue;
    // The object literal holding this key.
    let depth = 0;
    let open = -1;
    for (let i = at - 1, steps = 0; i >= 0 && steps < 20_000; i--, steps++) {
      if (!r.ctx.isCode(i)) continue;
      const c = r.src[i]!;
      if (c === '}' || c === ')' || c === ']') depth++;
      else if (c === '{' || c === '(' || c === '[') {
        if (depth > 0) depth--;
        else {
          open = c === '{' ? i : -1;
          break;
        }
      }
    }
    if (open < 0) continue;
    const close = r.close(open);
    if (close < 0) continue;
    r.begin([[open, close + 1]]);
    const obj = r.evRange(open, close + 1, null, 0);
    // An MCP tool object carries an inputSchema; a prompt has `arguments`, a
    // resource a `uri`, a CLI option neither — none of them is a tool.
    if (obj.k !== 'obj' || !obj.fields.has('inputSchema') || obj.fields.has('uri') || obj.fields.has('arguments')) continue;
    emit({ name: m[2]!, at, obj, own: [[open, close + 1]] });
    void file;
  }
}

// --- Python -------------------------------------------------------------------

interface PyDecorated {
  /** Offset of the `@`. */
  at: number;
  /** Decorator callee (`mcp.tool`, `write_tool`). */
  callee: string;
  args: [number, number][] | null;
  defName: string;
  defAt: number;
}

/** Decorators and the `def` each one sits on — one pass over the lines. */
function pyDecorated(r: Reader): PyDecorated[] {
  const { src, ctx } = r;
  const out: PyDecorated[] = [];
  let pending: Omit<PyDecorated, 'defName' | 'defAt'>[] = [];
  let i = 0;
  while (i < src.length && out.length < MAX_RAW_CALLS) {
    const nl = src.indexOf('\n', i);
    const end = nl < 0 ? src.length : nl;
    const lead = /^[ \t]*/.exec(src.slice(i, Math.min(end, i + 200)))![0].length;
    const at = i + lead;
    const c = src[at];
    if (c === '@' && ctx.isCode(at)) {
      const m = /^@([A-Za-z_][\w.]*)[ \t]*(\()?/.exec(src.slice(at, at + 200));
      if (m) {
        let args: [number, number][] | null = null;
        let next = end;
        if (m[2]) {
          const open = at + m[0].length - 1;
          const close = r.close(open);
          if (close > 0) {
            args = r.parts(open) ?? [];
            const nl2 = src.indexOf('\n', close);
            next = nl2 < 0 ? src.length : nl2;
          }
        }
        if (pending.length < 16) pending.push({ at, callee: m[1]!, args });
        i = next + 1;
        continue;
      }
    }
    const def = /^(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)[ \t]*\(/.exec(src.slice(at, at + 200));
    if (def && ctx.isCode(at)) {
      for (const p of pending) out.push({ ...p, defName: def[1]!, defAt: at + def[0].length - 1 });
      pending = [];
    } else if (src.slice(at, end).trim() && c !== '#') pending = [];
    i = end + 1;
  }
  return out;
}

/** A Python call's arguments: keywords by name, positionals in order, and what spreads left unknown. */
interface PyCall {
  kw: Map<string, Thunk>;
  pos: Thunk[];
  /** An unreadable `**kwargs` spread: any keyword may be in it. */
  open: boolean;
  /** An unreadable `*args` spread: the positions after it are unknown. */
  posOpen: boolean;
}

/** A Python argument's range without the blanks and comments around it (`tool(  # note\n  name="x")`). */
function pyArg(r: Reader, a: number, b: number): [number, number] {
  const mask = r.ctx.mask;
  while (a < b && (mask[a] === COMMENT || /\s/.test(r.src[a]!))) a++;
  while (b > a && (mask[b - 1] === COMMENT || /\s/.test(r.src[b - 1]!))) b--;
  return [a, b];
}

/** Keyword arguments of a Python call as name → expression, positional arguments in order. */
function pyArgs(r: Reader, args: [number, number][] | null, env: Env | null, own: boolean): PyCall {
  const kw = new Map<string, Thunk>();
  const pos: Thunk[] = [];
  let open = false;
  let posOpen = false;
  for (const [a0, b0] of args ?? []) {
    const [a, b] = pyArg(r, a0, b0);
    if (a >= b) continue;
    const t = r.text(a, b);
    const lead = t.length - t.trimStart().length;
    const m = /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*/.exec(t);
    if (m) {
      kw.set(m[1]!, { from: a + m[0].length, to: b, env, own });
      continue;
    }
    if (t.trimStart().startsWith('**')) {
      const v = r.evRange(a + lead + 2, b, env, 0, own);
      if (v.k === 'obj') {
        if (v.open) {
          kw.clear();
          open = true;
        }
        for (const [k, th] of v.fields) kw.set(k, th);
      } else if (!(v.k === 'lit' && v.v === null)) {
        kw.clear();
        open = true;
      }
      continue;
    }
    // `*args` spreads a sequence into the positions; an unreadable one hides every position after it.
    if (t.trimStart().startsWith('*')) {
      const v = posOpen ? UNKNOWN : r.evRange(a + lead + 1, b, env, 0, own);
      if (v.k === 'arr' && !v.open) pos.push(...v.items);
      else if (!(v.k === 'lit' && v.v === null)) posOpen = true;
      continue;
    }
    if (!posOpen) pos.push({ from: a, to: b, env, own });
  }
  return { kw, pos, open, posOpen };
}

/**
 * The tool name a Python registration gives itself: its `name=` keyword, or
 * the positional FastMCP reads as the name (`tool(name)`, `add_tool(fn, name)`).
 * `none` — it gives none (or `None`), so the function's own name stands;
 * `unknown` — it gives one we cannot read, and then the function's name is
 * certainly NOT the tool's.
 */
function pyExplicitName(r: Reader, call: PyCall, idx: number): { name: string } | 'none' | 'unknown' {
  const t = call.kw.get('name') ?? call.pos[idx];
  if (!t) return call.posOpen && !call.kw.has('name') ? 'unknown' : 'none';
  const v = r.ev(t);
  if (v.k === 'lit' && v.v === null) return 'none';
  if (v.k === 'lit' && typeof v.v === 'string' && !v.partial) return { name: v.v };
  return 'unknown';
}

const renamedMemo = new WeakMap<FnInfo, boolean>();
const renamedNamesMemo = new WeakMap<FileCtx, Set<string>>();

/** The names a file assigns a `__name__` to (`fn.__name__ = …`, `setattr(fn, "__name__", …)`), from one pass over it. */
function renamedNames(ctx: FileCtx): Set<string> {
  let out = renamedNamesMemo.get(ctx);
  if (!out) {
    out = new Set();
    for (const m of ctx.src.matchAll(/(?<![\w.])([A-Za-z_]\w*)\s*\.\s*__name__\s*=(?!=)|\bsetattr\s*\(\s*([A-Za-z_]\w*)\s*,\s*['"]__name__['"]/g)) {
      out.add((m[1] ?? m[2])!);
    }
    renamedNamesMemo.set(ctx, out);
  }
  return out;
}

/**
 * Does the function carry another `__name__` than its `def` says? A wrapper
 * made with `@functools.wraps(f)` takes f's name, and code that assigns
 * `fn.__name__ = …` (or `setattr(fn, "__name__", …)`) names it at run time.
 */
function renamedPyFn(ctx: FileCtx, fn: FnInfo): boolean {
  const hit = renamedMemo.get(fn);
  if (hit !== undefined) return hit;
  const { src } = ctx;
  const n = fn.name ?? '';
  // One pass per file, not one per function: thousands of functions must not each rescan it.
  let v = !n || renamedNames(ctx).has(n);
  // The decorators right above the `def`.
  let lineStart = src.lastIndexOf('\n', fn.headerStart - 1) + 1;
  for (let k = 0; !v && k < 16 && lineStart > 0; k++) {
    const prev = src.lastIndexOf('\n', lineStart - 2) + 1;
    const line = src.slice(prev, Math.min(lineStart - 1, prev + 400)).trim();
    if (!line.startsWith('@')) break;
    if (/^@\s*(?:functools\s*\.\s*)?wraps\b/.test(line)) v = true;
    lineStart = prev;
  }
  renamedMemo.set(fn, v);
  return v;
}

/** Readers of the package's other files: one per file, without the package (a constant there is read one hop deep). */
const constReaders = new WeakMap<SourceFile, Reader>();

function constReader(file: SourceFile): Reader {
  let r = constReaders.get(file);
  if (!r) constReaders.set(file, (r = new Reader(fileCtxOf(file))));
  return r;
}

/** Readers of the package's other files with the package: a function defined there reads its own imports. */
const pkgReaders = new WeakMap<PyPackage, Map<string, Reader>>();

function pkgReader(file: SourceFile, pkg: PyPackage | undefined): Reader {
  if (!pkg) return constReader(file);
  let m = pkgReaders.get(pkg);
  if (!m) pkgReaders.set(pkg, (m = new Map()));
  let r = m.get(file.path);
  if (!r) m.set(file.path, (r = new Reader(fileCtxOf(file), pkg)));
  return r;
}

/** The function FastMCP reads a tool's schema and docstring from, and the file it is in. */
interface PyTarget {
  ctx: FileCtx;
  fn: FnInfo;
  /** Another file of the package; absent for this one. */
  file?: SourceFile;
}

/** The input schema FastMCP builds for a registered function, its values folded where the function is defined. */
function pySchema(r: Reader, target: PyTarget, call: PyCall): JsonSchema | undefined {
  let exclude: Set<string> | undefined;
  const ex = call.kw.get('exclude_args');
  if (ex) {
    const v = r.ev(ex);
    if (v.k !== 'arr' || v.open) return undefined;
    exclude = new Set();
    for (const t of v.items) {
      const s = r.str(t);
      if (s === undefined) return undefined;
      exclude.add(s);
    }
  }
  const tr = target.file ? pkgReader(target.file, r.pkg) : r;
  tr.begin([]);
  return pySignatureSchema(
    target.ctx,
    target.fn,
    (a, b, text) => {
      const v = tr.evRange(a, b, null, 0);
      if (v.k !== 'lit' || (v.partial && !(text && typeof v.v === 'string'))) return undefined;
      return v.v;
    },
    exclude,
  );
}

/** One `for <targets> in <iter>:` header. */
interface PyLoopHead {
  targets: [number, number];
  iter: [number, number];
  /** Offset of the header's `:`. */
  colon: number;
  /** The names the targets bind. */
  names: string[];
}

/** The `for` header on the line starting at `lineStart`, if that line is one. */
function pyForHeader(r: Reader, lineStart: number): PyLoopHead | undefined {
  const { src } = r;
  const m = /^[ \t]*(?:async[ \t]+)?for[ \t]+/.exec(src.slice(lineStart, lineStart + 200));
  if (!m || !r.ctx.isCode(lineStart + m[0].length - 1)) return undefined;
  const tStart = lineStart + m[0].length;
  let inAt = -1;
  for (let i = tStart, n = 0; i < src.length && n < 2000; i++, n++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '\n') return undefined;
    if (c === '(' || c === '[' || c === '{') {
      const e = r.close(i);
      if (e < 0) return undefined;
      i = e;
    } else if (c === 'i' && src[i + 1] === 'n' && !/\w/.test(src[i - 1] ?? '') && !/\w/.test(src[i + 2] ?? '')) {
      inAt = i;
      break;
    }
  }
  if (inAt < 0) return undefined;
  for (let i = inAt + 2, n = 0; i < src.length && n < 20_000; i++, n++) {
    if (!r.ctx.isCode(i)) continue;
    const c = src[i]!;
    if (c === '\n' && src[i - 1] !== '\\') return undefined;
    if (c === '(' || c === '[' || c === '{') {
      const e = r.close(i);
      if (e < 0) return undefined;
      n += e - i;
      i = e;
    } else if (c === ':') {
      const names = [...r.text(tStart, inAt).matchAll(/[A-Za-z_]\w*/g)].map((x) => x[0]).slice(0, 32);
      return { targets: [tStart, inAt], iter: [inAt + 2, i], colon: i, names };
    }
  }
  return undefined;
}

/**
 * The innermost `for` loop whose body holds `at`, found by walking the lines
 * above it to the blocks that open them — never out of a `def` or a `class`.
 */
function pyLoopAt(r: Reader, at: number): PyLoopHead | undefined {
  const { src } = r;
  const lineStart = src.lastIndexOf('\n', at - 1) + 1;
  // A one-line loop: `for fn in TOOLS: mcp.add_tool(fn)`.
  const same = pyForHeader(r, lineStart);
  if (same) return same.colon < at ? same : undefined;
  let indent = /^[ \t]*/.exec(src.slice(lineStart, lineStart + 400))![0].length;
  let end = lineStart - 1;
  for (let steps = 0; end > 0 && indent > 0 && steps < 5000 && lineStart - end < 400_000; steps++) {
    const start = src.lastIndexOf('\n', end - 1) + 1;
    const ind = /^[ \t]*/.exec(src.slice(start, Math.min(end, start + 400)))![0].length;
    const c0 = start + ind;
    if (c0 < end && r.ctx.isCode(c0) && src[c0] !== '#' && ind < indent) {
      const head = src.slice(c0, Math.min(end, c0 + 20));
      if (/^(?:async[ \t]+)?(?:def|class)\b/.test(head)) return undefined;
      if (/^(?:async[ \t]+)?for\b/.test(head)) return pyForHeader(r, start);
      indent = ind;
    }
    end = start - 1;
  }
  return undefined;
}

/** Bind a loop's targets (`fn`, `fn, title`, `(name, (fn, title))`) to one element; what does not unpack is unknown. */
function bindPyTargets(r: Reader, a: number, b: number, el: Thunk, vars: Map<string, Thunk>, depth = 0): void {
  const [from, to] = r.trim(a, b);
  const parts = r.split(from, to, ',').map(([x, y]) => r.trim(x, y)).filter(([x, y]) => y > x);
  const unknown = (x: number, y: number): void => {
    for (const n of r.text(x, y).matchAll(/[A-Za-z_]\w*/g)) vars.set(n[0], { val: UNKNOWN });
  };
  if (parts.length === 1 && !/,\s*$/.test(r.text(from, to))) {
    const [x, y] = parts[0]!;
    const t = r.text(x, y);
    if (/^[A-Za-z_]\w*$/.test(t)) vars.set(t, el);
    else if (r.src[x] === '[' && r.close(x) === y - 1 && depth < 4) bindPyTargets(r, x + 1, y - 1, el, vars, depth + 1);
    else unknown(x, y);
    return;
  }
  const v = r.ev(el);
  const ok = v.k === 'arr' && !v.open && v.items.length === parts.length && depth < 4;
  parts.forEach(([x, y], i) => {
    if (ok) bindPyTargets(r, x, y, (v as { items: Thunk[] }).items[i]!, vars, depth + 1);
    else unknown(x, y);
  });
}

/** Bind a Python function's parameters to one call's arguments: positionals, keywords, `*args`, `**kwargs`, defaults. */
function pyBindCall(r: Reader, fn: FnInfo, args: [number, number][], own: boolean): Env {
  const header = r.text(fn.headerStart, fn.bodyStart);
  const kwParam = /\*\*\s*([A-Za-z_]\w*)/.exec(header)?.[1];
  const varParam = /(?<!\*)\*\s*([A-Za-z_]\w*)/.exec(header)?.[1];
  const vars = new Map<string, Thunk>();
  const extra = new Map<string, Thunk>();
  const rest: Thunk[] = [];
  let spread = false;
  let k = 0;
  for (const [a0, b0] of args) {
    const [a, b] = pyArg(r, a0, b0);
    if (a >= b) continue;
    const t = r.text(a, b);
    const m = /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*/.exec(t);
    if (m) {
      const th: Thunk = { from: a + m[0].length, to: b, env: null, own };
      if (fn.params.some((p) => p.name === m[1] && p.name !== kwParam && p.name !== varParam)) vars.set(m[1]!, th);
      else extra.set(m[1]!, th);
      continue;
    }
    // A spread at the call site: which parameter gets what is not known.
    if (/^\s*\*/.test(t)) {
      spread = true;
      continue;
    }
    const p = fn.params[k];
    if (!p || !p.name || p.name === kwParam) {
      spread = true;
      continue;
    }
    if (p.name === varParam) {
      rest.push({ from: a, to: b, env: null, own });
      continue;
    }
    vars.set(p.name, { from: a, to: b, env: null, own });
    k++;
  }
  for (const p of fn.params) {
    if (!p.name) continue;
    const changed = reassigned(r, fn, p.name);
    if (p.name === varParam) vars.set(p.name, spread || changed ? { val: UNKNOWN } : { val: { k: 'arr', items: rest, open: false } });
    else if (p.name === kwParam) vars.set(p.name, { val: { k: 'obj', fields: extra, open: spread || changed } });
    else if (vars.has(p.name)) {
      if (changed) vars.set(p.name, { val: UNKNOWN });
    } else if (spread || changed) vars.set(p.name, { val: UNKNOWN });
    else if (p.default) {
      const at = r.src.indexOf(p.default, fn.headerStart);
      vars.set(p.name, at >= 0 && at < fn.bodyStart ? { from: at, to: at + p.default.length, env: null } : { val: UNKNOWN });
    } else vars.set(p.name, { val: NULLISH });
  }
  return { vars, fn, parent: null };
}

/** Registration lines whose tool names could not be read, per file, at most. */
const MAX_UNNAMED = 50;

function pyRegistrations(r: Reader, file: string, unnamed: Set<number>): FoundRegistration[] {
  const out: FoundRegistration[] = [];
  const isMcp = mcpFile(r);
  const unknownAt = (at: number): void => {
    if (unnamed.size < MAX_UNNAMED) unnamed.add(r.ctx.line(at));
  };
  const emit = (
    d: { at: number; defName?: string; defAt?: number },
    via: FoundRegistration['via'],
    call: PyCall,
    name: string,
    target: PyTarget | undefined,
    helpers?: string[],
  ): void => {
    if (out.length >= MAX_REGS) return;
    const annT = call.kw.get('annotations');
    // `annotations` passed through an unreadable `**kwargs` may be anything.
    const ann = annT ? r.ev(annT) : call.open ? UNKNOWN : NULLISH;
    const h = r.hints(ann);
    // FastMCP: the registration's description, else the function's docstring.
    // One the registration gives but we cannot read is not replaced by the docstring.
    const descT = call.kw.get('description');
    const description = descT ? r.str(descT, true) : target ? pyDocstring(target.ctx, target.fn) : undefined;
    const title = r.str(call.kw.get('title'), true);
    const condition = conditionAt(r, d.at);
    // The decorated function IS the handler: read what its body sends or writes.
    const def = d.defAt !== undefined ? r.ctx.functions().find((f) => f.headerStart < d.defAt! && d.defAt! - f.headerStart < 160 && f.bodyStart > d.defAt!) : undefined;
    const fetched = def ? inputFetch(r, def) : undefined;
    const behavior = def ? [...(fetched ? [fetched] : []), ...writesIn(r, def.bodyStart, def.bodyEnd)].slice(0, 3) : [];
    const inputSchema = target ? pySchema(r, target, call) : undefined;
    const pinned = def ? pinnedOf(r, def, Object.keys(inputSchema?.properties ?? {})) : undefined;
    out.push({
      name, file, line: r.ctx.line(d.at), via, ...(helpers ? { helpers } : {}),
      ...(title ? { title } : {}), ...(description ? { description } : {}),
      ...(h.hints ? { hints: h.hints } : {}), hintSource: h.source,
      ...(condition ? { condition } : {}), ...(behavior.length ? { behavior } : {}), ...(pinned ? { pinned } : {}),
      ...(d.defAt !== undefined ? { defAt: d.defAt } : {}),
      ...(d.defName && d.defName !== name ? { defName: d.defName } : {}),
      ...(inputSchema ? { inputSchema } : {}),
    });
  };

  // Decorator wrappers: a named function whose body calls `X.tool(…)`.
  const wrappers = new Map<string, { fn: FnInfo; call: [number, number][] }>();
  for (const fn of r.ctx.functions()) {
    if (!fn.name) continue;
    const body = r.text(fn.bodyStart, fn.bodyEnd);
    const m = /(?<![\w.])[A-Za-z_][\w.]*\.tool\s*\(/.exec(body);
    if (!m) continue;
    const open = fn.bodyStart + m.index + m[0].length - 1;
    if (!r.ctx.isCode(open)) continue;
    const parts = r.parts(open);
    if (!parts) continue;
    wrappers.set(fn.name, { fn, call: parts });
  }

  const decorated = pyDecorated(r);
  for (const d of decorated) {
    if (out.length >= MAX_REGS) break;
    const segs = d.callee.split('.');
    const last = segs.pop()!;
    const fnDef = pyDefAt(r.ctx, d.defAt);
    const target = fnDef ? { ctx: r.ctx, fn: fnDef } : undefined;
    if (segs.length && last === 'tool') {
      // `@agent.tool` (pydantic-ai) and other frameworks' `.tool` decorators are
      // not MCP: the receiver has to look like one, or the file has to be MCP.
      if (!isMcp && !MCP_RECEIVER.test(segs.join('.'))) continue;
      r.begin(d.args ?? []);
      const call = pyArgs(r, d.args, null, true);
      const nm = pyExplicitName(r, call, 0);
      if (nm === 'unknown') unknownAt(d.at);
      else emit(d, 'decorator', call, nm === 'none' ? d.defName : nm.name, target);
      continue;
    }
    const w = wrappers.get(d.callee);
    if (!w || r.fnNamed(d.callee) !== w.fn || !isMcp) continue;
    // Bind the wrapper's parameters to the decorator call: positional, then keywords;
    // keywords it does not name go to its `**kwargs`.
    r.begin(d.args ?? []);
    const env = pyBindCall(r, w.fn, d.args ?? [], true);
    const call = pyArgs(r, w.call, env, false);
    const nm = pyExplicitName(r, call, 0);
    if (nm === 'unknown') unknownAt(d.at);
    else emit(d, 'decorator-helper', call, nm === 'none' ? d.defName : nm.name, target, [d.callee]);
  }

  /**
   * One `add_tool(fn, …)` evaluated: its explicit name, else the name of the
   * function it registers — a `def` in this file or one imported from the
   * package, never a loop variable, a parameter or a local that holds who
   * knows what. `param` — the function is a parameter of the enclosing
   * function, whose callers say which.
   */
  const addOne = (at: number, call: PyCall, via: FoundRegistration['via'], helpers?: string[]): 'done' | 'param' => {
    const nm = pyExplicitName(r, call, 1);
    if (nm === 'unknown') {
      unknownAt(at);
      return 'done';
    }
    const first = call.pos[0];
    let target: PyTarget | undefined;
    let fnName: string | undefined;
    if (first) {
      const v = r.ev(first);
      if (v.k === 'fn' && v.fn.name) {
        target = { ctx: r.ctx, fn: v.fn };
        if (!renamedPyFn(r.ctx, v.fn)) fnName = v.fn.name;
      } else if (v.k === 'ext') {
        const ctx = fileCtxOf(v.file);
        target = { ctx, fn: v.fn, file: v.file };
        if (!renamedPyFn(ctx, v.fn)) fnName = v.name;
      }
    }
    const name = nm === 'none' ? fnName : nm.name;
    if (name) {
      emit({ at, ...(target?.fn.name ? { defName: target.fn.name } : {}) }, via, call, name, target, helpers);
      return 'done';
    }
    if (!helpers && first && !('val' in first)) {
      const id = /^[A-Za-z_]\w*$/.exec(r.text(first.from, first.to).trim())?.[0];
      const owner = r.enclosing(at);
      if (id && owner?.params.some((p) => p.name === id)) return 'param';
    }
    unknownAt(at);
    return 'done';
  };

  // One more loop element or wrapper caller read, within the file's budget.
  let expansions = 0;
  const canExpand = (site: number): boolean => {
    if (++expansions <= MAX_PY_EXPANSIONS) return true;
    truncatedFlag = true;
    unknownAt(site);
    return false;
  };

  // `def register(fn): mcp.add_tool(fn)` — the tools are what its callers in this file pass.
  const expandHelper = (site: number, parts: [number, number][]): void => {
    const h = r.enclosing(site)!;
    if (!h.name || h.kind === 'method' || !h.params.length) {
      unknownAt(site);
      return;
    }
    const calls = r.ctx.callSitesOf(h.name).filter((c) => r.enclosing(c.index) !== h);
    const uses = decorated.filter((d) => d.callee === h.name && d.args === null);
    if (!calls.length && !uses.length) {
      unknownAt(site);
      return;
    }
    let n = 0;
    for (const c of calls) {
      if (++n > MAX_ITEMS || out.length >= MAX_REGS || !canExpand(site)) break;
      const args = c.args.args.map((t, i) => [c.args.starts[i]!, c.args.starts[i]! + t.length] as [number, number]);
      r.begin(args);
      const env = pyBindCall(r, h, args, true);
      addOne(c.index, pyArgs(r, parts, env, true), 'helper', [h.name]);
    }
    // `@register` on a `def`: the decorated function is the argument.
    for (const d of uses) {
      if (++n > MAX_ITEMS || out.length >= MAX_REGS || !canExpand(site)) break;
      const def = pyDefAt(r.ctx, d.defAt);
      const p0 = h.params[0]!.name;
      if (!def || !p0) continue;
      r.begin([]);
      const env = pyBindCall(r, h, [], true);
      env.vars.set(p0, { val: { k: 'fn', fn: def, env: null }, own: true });
      addOne(d.at, pyArgs(r, parts, env, true), 'helper', [h.name]);
    }
  };

  const addTool = (site: number, parts: [number, number][]): void => {
    // In a loop, a registration that reads the loop's variables is one per element.
    const loop = pyLoopAt(r, site);
    if (loop && loop.names.some((n) => r.identOffsetsOf(n).some((i) => i >= parts[0]![0] && i < parts[parts.length - 1]![1]))) {
      r.begin([]);
      const iter = r.evRange(loop.iter[0], loop.iter[1], null, 0);
      if (iter.k !== 'arr') {
        // What the loop yields is unknown; a name that does not depend on it is still read.
        const env: Env = { vars: new Map(loop.names.map((n) => [n, { val: UNKNOWN }])), fn: null, parent: null };
        r.begin(parts);
        if (addOne(site, pyArgs(r, parts, env, true), 'direct') === 'param') unknownAt(site);
        return;
      }
      for (const el of iter.items.slice(0, MAX_ITEMS)) {
        if (out.length >= MAX_REGS || !canExpand(site)) break;
        const env: Env = { vars: new Map(), fn: null, parent: null };
        bindPyTargets(r, loop.targets[0], loop.targets[1], el, env.vars);
        r.begin(parts);
        addOne(site, pyArgs(r, parts, env, true), 'loop', undefined);
      }
      if (iter.open) unknownAt(site);
      return;
    }
    r.begin(parts);
    if (addOne(site, pyArgs(r, parts, null, true), 'direct') === 'param') expandHelper(site, parts);
  };

  // `mcp.add_tool(fn, name=…, annotations=…)` and low-level `Tool(name=…, inputSchema=…, annotations=…)`.
  if (isMcp) {
    let sites = 0;
    for (const m of r.src.matchAll(/\.\s*add_tool\s*\(|(?<![\w.])(?:[A-Za-z_]\w{0,40}\.){0,4}Tool\s*\(/g)) {
      if (out.length >= MAX_REGS) break;
      if (!r.ctx.isCode(m.index!)) continue;
      const open = m.index! + m[0].length - 1;
      const parts = r.parts(open);
      if (!parts?.length) continue;
      if (m[0].includes('add_tool')) {
        if (++sites > MAX_PY_ADD_SITES) {
          truncatedFlag = true;
          break;
        }
        addTool(m.index!, parts);
        continue;
      }
      r.begin(parts);
      const call = pyArgs(r, parts, null, true);
      // A LangChain `Tool(func=…)` is not an MCP tool; the MCP type carries an inputSchema.
      if (!call.kw.has('inputSchema')) continue;
      const name = r.str(call.kw.get('name'));
      if (name) emit({ at: m.index! }, 'direct', call, name, undefined);
    }
  }
  return out;
}

// --- entry point ----------------------------------------------------------------

/** Every tool registration this file makes that can be read with certainty. */
export function readRegistrations(file: SourceFile, pkg?: PyPackage): FoundRegistration[] {
  return readRegistrationsWithStats(file, pkg).regs;
}

/**
 * {@link readRegistrations}, whether a cap stopped the reading early (then some
 * tools may be missing), and the lines of registrations whose tool names cannot
 * be read — `for fn in load_tools(): mcp.add_tool(fn)` registers tools, but
 * which is known only at run time. `pkg` lets a Python file's registrations
 * follow imports into the package's other files.
 */
export function readRegistrationsWithStats(file: SourceFile, pkg?: PyPackage): { regs: FoundRegistration[]; truncated: boolean; unnamed: number[] } {
  truncatedFlag = false;
  unnamedLines = new Set();
  const regs = readAll(file, pkg);
  return { regs, truncated: truncatedFlag, unnamed: [...unnamedLines].sort((a, b) => a - b) };
}

let truncatedFlag = false;
let unnamedLines = new Set<number>();

function readAll(file: SourceFile, pkg?: PyPackage): FoundRegistration[] {
  const ctx = fileCtxOf(file);
  const r = new Reader(ctx, pkg);
  if (r.py) {
    if (!/\.tool\b|add_tool|\bTool\s*\(/.test(file.content)) return [];
    return dedupe(pyRegistrations(r, file.path, unnamedLines));
  }
  const hasRegs = /registerTool|addTool|\.tool\s*\(/.test(file.content);
  const hasList = /ListToolsRequestSchema|['"`]tools\/list['"`]/.test(file.content);
  if (!hasRegs && !hasList) return [];
  const regs = hasRegs ? jsRegCalls(r) : [];
  // Registrations by name, merged as they come: two hundred copies of one name
  // are one tool, and must not fill the cap before a helper's tools are read.
  const byName = new Map<string, FoundRegistration>();
  const out = {
    get length(): number {
      return byName.size;
    },
    push(reg: FoundRegistration): void {
      const prev = byName.get(reg.name);
      byName.set(reg.name, prev ? mergeRegs(prev, reg) : reg);
    },
  };
  const isMcp = mcpFile(r);
  const min = minified(r);

  let evals = 0;
  const emit = (call: RegCall, env: Env | null, via: FoundRegistration['via'], site: number, own: [number, number][], helpers?: string[], guard?: RegistrationCondition): void => {
    if (++evals > MAX_EVALS) {
      truncatedFlag = true;
      return;
    }
    r.begin(own);
    const v = viewOf(r, call, env);
    if (!v.shaped || !v.name) return;
    if (out.length >= MAX_REGS && !byName.has(v.name)) {
      truncatedFlag = true;
      return;
    }
    const slugOnly = via === 'helper' || via === 'loop';
    if (slugOnly ? !SLUG.test(v.name) : !/^[A-Za-z0-9._:\- ]{1,128}$/.test(v.name) || !/[A-Za-z0-9]/.test(v.name)) return;
    const h = r.hints(v.annotations);
    const condition = guard ?? conditionAt(r, site);
    const behavior = handlerEvidence(r, v.handler, env);
    const hv = v.handler && v.params?.some(namesDestinationParam) ? r.ev(v.handler) : undefined;
    const pinned = hv?.k === 'fn' ? pinnedOf(r, hv.fn, v.params) : undefined;
    out.push({
      name: v.name, file: file.path, line: ctx.line(site), via, ...(helpers ? { helpers } : {}),
      ...(v.title ? { title: v.title } : {}), ...(v.description ? { description: v.description } : {}),
      ...(v.params ? { params: v.params } : {}),
      ...(h.hints ? { hints: h.hints } : {}), hintSource: h.source,
      ...(condition ? { condition } : {}), ...(behavior.length ? { behavior } : {}), ...(pinned ? { pinned } : {}),
    });
  };

  const helpers = min ? [] : findHelpers(r, regs, isMcp);
  const helperRegs = new Set(helpers.flatMap((h) => h.inner.filter((x): x is { reg: RegCall } => 'reg' in x).map((x) => x.reg)));
  const loops = (min ? [] : jsLoops(r)).sort((a, b) => a.body[0] - b.body[0]);
  loopStarts.set(r, loops.map((l) => (r.src[l.body[0]] === '{' ? l.body[0] + 1 : l.body[0])));
  /** The innermost loop whose body holds `at` — binary search, then a short walk back. */
  const loopAt = (at: number): Loop | undefined => {
    let lo = 0;
    let hi = loops.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (loops[mid]!.body[0] < at) lo = mid + 1;
      else hi = mid;
    }
    for (let k = lo - 1, steps = 0; k >= 0 && steps < 64; k--, steps++) {
      const l = loops[k]!;
      if (at > l.body[0] && at < l.body[1]) return l;
    }
    return undefined;
  };

  // Helper call sites with a literal name — every helper whose callers are not themselves helpers.
  const expand = (h: Helper, env: Env | null, site: number, own: [number, number][], chain: string[], depth: number): void => {
    if (depth > 4) return;
    for (const x of h.inner) {
      if ('reg' in x) emit(x.reg, env, 'helper', site, own, chain);
      else expand(x.helper, bindParams(r, x.helper.fn, x.call.args, env), site, own, [...chain, x.helper.name], depth + 1);
    }
  };
  for (const h of helpers) {
    const nameIdx = helperNameIndex(r, h);
    if (nameIdx === undefined) continue;
    for (const call of ctx.callSitesOf(h.name)) {
      if (evals > MAX_EVALS) break;
      if (!unshadowed(r, h.name, call.index)) continue;
      const owner = r.enclosing(call.index);
      const outer = helpers.find((o) => o.fn === owner);
      if (outer && outer.inner.some((x) => 'call' in x && x.call.index === call.index)) continue;
      const args = call.args.args.map((t, i) => [call.args.starts[i]!, call.args.starts[i]! + t.length] as [number, number]);
      if (!args[nameIdx]) continue;
      r.begin(args);
      expand(h, bindParams(r, h.fn, args, null), call.index, args, [h.name], 0);
    }
  }

  // Direct registrations: the name is a literal (or a same-file constant).
  for (const call of regs) {
    const nameArg = call.args[0];
    if (!nameArg || helperRegs.has(call)) continue;
    const loop = loopAt(call.at);
    if (loop && !/^\s*(['"`])/.test(r.text(nameArg[0], nameArg[1]))) {
      if (evals >= MAX_EVALS) continue;
      if (!mcpCall(call, isMcp)) continue;
      r.begin([]);
      const iter = r.evRange(loop.iter[0], loop.iter[1], null, 0);
      if (iter.k !== 'arr') continue;
      for (const el of iter.items.slice(0, MAX_ITEMS)) {
        const env = bindPattern(r, loop.pattern, el, null);
        if (!env) break;
        const own: [number, number][] = 'val' in el ? ownOfPair(el) : [[el.from, el.to]];
        r.begin(own);
        const g = loopGuard(r, loop, call.at, env);
        if (g === 'skip') continue;
        emit(call, env, 'loop', call.at, own, undefined, g ?? undefined);
      }
      continue;
    }
    emit(call, null, 'direct', call.at, call.args);
  }

  // The low-level `tools/list` handler's objects: their hints, for the names the line matcher finds.
  listToolObjects(r, file.path, ({ name, at, obj, own }) => {
    if (out.length >= MAX_REGS && !byName.has(name)) return;
    r.begin(own);
    const h = r.hints(annotationsOf(r, obj));
    const description = r.str(fieldOf(obj, 'description'), true);
    // The table's own schema: a tool whose line-matcher read found none still has parameters.
    const params = schemaParams(r, fieldOf(obj, 'inputSchema'));
    const condition = conditionAt(r, at);
    out.push({
      name, file: file.path, line: ctx.line(at), via: 'direct',
      ...(description ? { description } : {}),
      ...(params ? { params } : {}),
      ...(h.hints ? { hints: h.hints } : {}), hintSource: h.source,
      ...(condition ? { condition } : {}),
    });
  });
  return [...byName.values()];
}

/** For an `Object.entries` pair, the source range of its value. */
function ownOfPair(el: { val: Val }): [number, number][] {
  const v = el.val;
  if (v.k !== 'arr') return [];
  return v.items.filter((t): t is { from: number; to: number; env: Env | null } => !('val' in t)).map((t) => [t.from, t.to] as [number, number]);
}

/**
 * Two registrations of one name — `if (x) reg(a) else reg(b)`, a legacy branch —
 * merge toward the riskier reading: hints toward a write, handler evidence
 * united. The tool is conditional only if every registration is, and not when
 * the two sit in the if and the else of one statement.
 */
function mergeRegs(prev: FoundRegistration, r: FoundRegistration): FoundRegistration {
  const richer = (x: FoundRegistration): number => (x.description ? 2 : 0) + (x.params || x.inputSchema ? 1 : 0);
  const keep: FoundRegistration = { ...(richer(r) > richer(prev) ? r : prev) };
  // Every text the server may present under this name is scanned: a poisoned
  // description beside a longer clean one must not be the one dropped.
  const description = mergeDescriptions(prev.description, r.description);
  if (description !== undefined) keep.description = description;
  const hints = mergeHints(prev.hints, r.hints);
  if (hints) keep.hints = hints;
  keep.hintSource = prev.hints && r.hints && !sameHints(prev.hints, r.hints) ? 'merged' : prev.hints ? prev.hintSource : r.hintSource;
  const behavior = [...(prev.behavior ?? []), ...(r.behavior ?? [])].filter((b, i, all) => all.findIndex((x) => x.why === b.why) === i);
  if (behavior.length) keep.behavior = behavior.slice(0, 3);
  // A destination is pinned only where every handler of the name pins it.
  const pinned = (prev.pinned ?? []).filter((p) => r.pinned?.includes(p));
  if (pinned.length) keep.pinned = pinned;
  else delete keep.pinned;
  if (!(prev.condition && r.condition) || complementary(prev.condition, r.condition)) delete keep.condition;
  return keep;
}

function dedupe(regs: FoundRegistration[]): FoundRegistration[] {
  const by = new Map<string, FoundRegistration>();
  for (const r of regs) {
    const prev = by.get(r.name);
    by.set(r.name, prev ? mergeRegs(prev, r) : r);
  }
  return [...by.values()];
}
