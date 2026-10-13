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

import type { CapabilityTag, SourceFile } from '../types.js';
import { type FileCtx, type FnInfo, fileCtxOf } from '../util/fileCtx.js';
import { fold } from '../util/constFold.js';
import { CODE, braceDepths, splitArgs } from '../util/jsLex.js';

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
  /** Python: offset of the `(` of the `def` the decorator sits on (for the docstring). */
  defAt?: number;
  /** Python: the decorated function's own name, when the tool is registered under another. */
  defName?: string;
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

  constructor(ctx: FileCtx) {
    this.ctx = ctx;
    this.src = ctx.src;
    this.py = ctx.lang === 'py';
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
    if (!a) return null;
    return a.args.map((t, i) => [a.starts[i]!, a.starts[i]! + t.length] as [number, number]);
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
    // A name this file imports is defined somewhere we did not read.
    if (this.imported(name)) return UNKNOWN;
    const decl = this.ctx.constInitAt(name, at);
    if (decl && decl.init && decl.init !== name) {
      // The whole initializer, not readInit's 4,000-character prefix: a table of
      // fourteen tool definitions is longer than that.
      const start = this.src.indexOf(decl.init, decl.at);
      if (start < 0) return UNKNOWN;
      let end = start + decl.init.length;
      if (this.src[start] === '{' || this.src[start] === '[') {
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
    const fn = this.fnNamed(name);
    if (fn) return { k: 'fn', fn, env: null };
    return UNKNOWN;
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
  return s.replace(/\\([`$\\])/g, '$1').replace(/\\n/g, '\n').replace(/\\t/g, '\t');
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
  for (const [from, to] of bodies) {
    for (const ev of writesIn(r, from, to)) {
      if (!out.some((o) => o.why === ev.why)) out.push(ev);
      if (out.length >= 3) return out;
    }
  }
  return out;
}

const writesMemo = new WeakMap<Reader, Map<string, HandlerEvidence[]>>();

/** HTTP writes (external-sink) and database writes (state-write) in a handler body — once per body. */
function writesIn(r: Reader, from: number, to: number): HandlerEvidence[] {
  let m = writesMemo.get(r);
  if (!m) writesMemo.set(r, (m = new Map()));
  const key = `${from}:${to}`;
  const hit = m.get(key);
  if (hit) return hit;
  const v = writesInUncached(r, from, to);
  m.set(key, v);
  return v;
}

function writesInUncached(r: Reader, from: number, to: number): HandlerEvidence[] {
  const { src, ctx } = r;
  const out: HandlerEvidence[] = [];
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
    if (method === 'POST' && READ_ONLY_POST.test(first)) continue;
    out.push({ tag: 'external-sink', why: `handler sends an HTTP ${method} (${clip(src.slice(at - chain.length - 1, open + 1) + first)})`, line: ctx.line(at) });
  }

  // `fetch(url, { method: 'POST' })`, `axios({ method: 'put' })` — the method key
  // must sit in an object passed to a request function, and only that call's URL
  // decides whether it is a read-only query.
  for (const mm of body.matchAll(/\bmethod\s*:\s*(['"`])(POST|PUT|PATCH|DELETE)\1/gi)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    const call = enclosingCall(r, at, from);
    if (!call || !/(?:^|\.)(?:fetch|\$fetch|ofetch|axios|request|got|ky|undici|fetchJson|apiFetch|http|https)$/i.test(call.callee)) continue;
    const url = call.args[0] ? src.slice(call.args[0][0], call.args[0][1]) : '';
    const method = mm[2]!.toUpperCase();
    if (method === 'POST' && READ_ONLY_POST.test(url) && /^[`'"]/.test(url.trim())) continue;
    out.push({ tag: 'external-sink', why: `handler sends an HTTP ${method} (${clip(call.callee + '(' + url.trim())})`, line: ctx.line(at) });
  }

  // Python: `requests.request("DELETE", url)`, `session.request('post', …)`.
  for (const mm of body.matchAll(/\.\s*request\s*\(\s*(['"])(POST|PUT|PATCH|DELETE)\1/gi)) {
    const at = from + mm.index!;
    if (!ctx.isCode(at)) continue;
    out.push({ tag: 'external-sink', why: `handler sends an HTTP ${mm[2]!.toUpperCase()} (request("${mm[2]}", …))`, line: ctx.line(at) });
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
  return out;
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

/** Keyword arguments of a Python call as name → expression, positional arguments in order. */
function pyArgs(r: Reader, args: [number, number][] | null, env: Env | null, own: boolean): { kw: Map<string, Thunk>; pos: Thunk[]; open: boolean } {
  const kw = new Map<string, Thunk>();
  const pos: Thunk[] = [];
  let open = false;
  for (const [a, b] of args ?? []) {
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
    pos.push({ from: a, to: b, env, own });
  }
  return { kw, pos, open };
}

function pyRegistrations(r: Reader, file: string): FoundRegistration[] {
  const out: FoundRegistration[] = [];
  const isMcp = mcpFile(r);
  const emit = (
    d: { at: number; defName?: string; defAt?: number },
    via: FoundRegistration['via'],
    call: { kw: Map<string, Thunk>; pos: Thunk[]; open: boolean },
    nameAt: number,
    helpers?: string[],
  ): void => {
    if (out.length >= MAX_REGS) return;
    // FastMCP: `tool(name=None, …)` — the first positional is the name;
    // `add_tool(fn, name=None, …)` — the second.
    const name = r.str(call.kw.get('name')) ?? r.str(call.pos[nameAt]) ?? d.defName;
    if (!name) return;
    const annT = call.kw.get('annotations');
    // `annotations` passed through an unreadable `**kwargs` may be anything.
    const ann = annT ? r.ev(annT) : call.open ? UNKNOWN : NULLISH;
    const h = r.hints(ann);
    const description = r.str(call.kw.get('description'), true);
    const title = r.str(call.kw.get('title'), true);
    const condition = conditionAt(r, d.at);
    // The decorated function IS the handler: read what its body sends or writes.
    const def = d.defAt !== undefined ? r.ctx.functions().find((f) => f.headerStart < d.defAt! && d.defAt! - f.headerStart < 160 && f.bodyStart > d.defAt!) : undefined;
    const behavior = def ? writesIn(r, def.bodyStart, def.bodyEnd).slice(0, 3) : [];
    out.push({
      name, file, line: r.ctx.line(d.at), via, ...(helpers ? { helpers } : {}),
      ...(title ? { title } : {}), ...(description ? { description } : {}),
      ...(h.hints ? { hints: h.hints } : {}), hintSource: h.source,
      ...(condition ? { condition } : {}), ...(behavior.length ? { behavior } : {}),
      ...(d.defAt !== undefined ? { defAt: d.defAt } : {}),
      ...(d.defName && d.defName !== name ? { defName: d.defName } : {}),
    });
  };

  // Decorator wrappers: a named function whose body calls `X.tool(…)`.
  const wrappers = new Map<string, { fn: FnInfo; call: [number, number][]; kwParam?: string }>();
  for (const fn of r.ctx.functions()) {
    if (!fn.name) continue;
    const body = r.text(fn.bodyStart, fn.bodyEnd);
    const m = /(?<![\w.])[A-Za-z_][\w.]*\.tool\s*\(/.exec(body);
    if (!m) continue;
    const open = fn.bodyStart + m.index + m[0].length - 1;
    if (!r.ctx.isCode(open)) continue;
    const parts = r.parts(open);
    if (!parts) continue;
    const header = r.text(fn.headerStart, fn.bodyStart);
    const kwParam = /\*\*\s*([A-Za-z_]\w*)/.exec(header)?.[1];
    wrappers.set(fn.name, { fn, call: parts, ...(kwParam ? { kwParam } : {}) });
  }

  for (const d of pyDecorated(r)) {
    if (out.length >= MAX_REGS) break;
    const segs = d.callee.split('.');
    const last = segs.pop()!;
    if (segs.length && last === 'tool') {
      // `@agent.tool` (pydantic-ai) and other frameworks' `.tool` decorators are
      // not MCP: the receiver has to look like one, or the file has to be MCP.
      if (!isMcp && !MCP_RECEIVER.test(segs.join('.'))) continue;
      const own = d.args ?? [];
      r.begin(own);
      emit(d, 'decorator', pyArgs(r, d.args, null, true), 0);
      continue;
    }
    const w = wrappers.get(d.callee);
    if (!w || r.fnNamed(d.callee) !== w.fn || !isMcp) continue;
    // Bind the wrapper's parameters to the decorator call: positional, then keywords;
    // keywords it does not name go to its `**kwargs`.
    const vars = new Map<string, Thunk>();
    const extra = new Map<string, Thunk>();
    let pos = 0;
    const own = d.args ?? [];
    r.begin(own);
    for (const [a, b] of d.args ?? []) {
      const m = /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*/.exec(r.text(a, b));
      if (m) {
        const t: Thunk = { from: a + m[0].length, to: b, env: null, own: true };
        if (w.fn.params.some((p) => p.name === m[1] && p.name !== w.kwParam)) vars.set(m[1]!, t);
        else extra.set(m[1]!, t);
      } else {
        const p = w.fn.params[pos++];
        if (p?.name) vars.set(p.name, { from: a, to: b, env: null, own: true });
      }
    }
    for (const p of w.fn.params) {
      if (!p.name || vars.has(p.name)) {
        if (p.name && vars.has(p.name) && reassigned(r, w.fn, p.name)) vars.set(p.name, { val: UNKNOWN });
        continue;
      }
      if (p.name === w.kwParam) {
        // A wrapper that edits its **kwargs (`kwargs.setdefault(…)`) decides values we cannot see.
        vars.set(p.name, { val: { k: 'obj', fields: extra, open: reassigned(r, w.fn, p.name) } });
      } else if (p.default) {
        const at = r.src.indexOf(p.default, w.fn.headerStart);
        vars.set(p.name, at >= 0 && !reassigned(r, w.fn, p.name) ? { from: at, to: at + p.default.length, env: null } : { val: UNKNOWN });
      } else vars.set(p.name, reassigned(r, w.fn, p.name) ? { val: UNKNOWN } : { val: NULLISH });
    }
    const env: Env = { vars, fn: w.fn, parent: null };
    emit(d, 'decorator-helper', pyArgs(r, w.call, env, false), 0, [d.callee]);
  }

  // `mcp.add_tool(fn, name=…, annotations=…)` and low-level `Tool(name=…, inputSchema=…, annotations=…)`.
  if (isMcp) {
    for (const m of r.src.matchAll(/\.\s*add_tool\s*\(|(?<![\w.])(?:[A-Za-z_]\w{0,40}\.){0,4}Tool\s*\(/g)) {
      if (out.length >= MAX_REGS) break;
      if (!r.ctx.isCode(m.index!)) continue;
      const open = m.index! + m[0].length - 1;
      const parts = r.parts(open);
      if (!parts?.length) continue;
      const isAdd = m[0].includes('add_tool');
      r.begin(parts);
      const call = pyArgs(r, parts, null, true);
      // A LangChain `Tool(func=…)` is not an MCP tool; the MCP type carries an inputSchema.
      if (!isAdd && !call.kw.has('inputSchema')) continue;
      const fnName = isAdd ? /^[A-Za-z_]\w*$/.exec(r.text(parts[0]![0], parts[0]![1]).trim())?.[0] : undefined;
      emit({ at: m.index!, ...(fnName ? { defName: fnName } : {}) }, 'direct', call, isAdd ? 1 : 99);
    }
  }
  return out;
}

// --- entry point ----------------------------------------------------------------

/** Every tool registration this file makes that can be read with certainty. */
export function readRegistrations(file: SourceFile): FoundRegistration[] {
  return readRegistrationsWithStats(file).regs;
}

/** {@link readRegistrations}, and whether a cap stopped the reading early (then some tools may be missing). */
export function readRegistrationsWithStats(file: SourceFile): { regs: FoundRegistration[]; truncated: boolean } {
  truncatedFlag = false;
  const regs = readAll(file);
  return { regs, truncated: truncatedFlag };
}

let truncatedFlag = false;

function readAll(file: SourceFile): FoundRegistration[] {
  const ctx = fileCtxOf(file);
  const r = new Reader(ctx);
  if (r.py) {
    if (!/\.tool\b|add_tool|\bTool\s*\(/.test(file.content)) return [];
    return dedupe(pyRegistrations(r, file.path));
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
    out.push({
      name: v.name, file: file.path, line: ctx.line(site), via, ...(helpers ? { helpers } : {}),
      ...(v.title ? { title: v.title } : {}), ...(v.description ? { description: v.description } : {}),
      ...(v.params ? { params: v.params } : {}),
      ...(h.hints ? { hints: h.hints } : {}), hintSource: h.source,
      ...(condition ? { condition } : {}), ...(behavior.length ? { behavior } : {}),
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
    const condition = conditionAt(r, at);
    out.push({
      name, file: file.path, line: ctx.line(at), via: 'direct',
      ...(description ? { description } : {}),
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
  const richer = (x: FoundRegistration): number => (x.description ? 2 : 0) + (x.params ? 1 : 0);
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
