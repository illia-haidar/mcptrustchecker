/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Per-file lexical context shared by the source analyses: the code/string mask,
 * line lookup, a light index of the functions a file defines (name, parameters,
 * body range) and their call sites. Everything is computed lazily and cached,
 * so a file that never needs the function index never pays for it.
 */

import {
  type ArgList,
  type Lang,
  CODE,
  codeMask,
  identOffsets,
  langOf,
  lineAt,
  lineStarts,
  matchBracket,
  splitArgs,
  splitTopLevel,
} from './jsLex.js';

export interface FnParam {
  /** Local binding name (`host`, `args`); for a destructured parameter, '' . */
  name: string;
  /** For `{ a, b: c }`: key → local name (`a→a`, `b→c`). */
  keys?: Map<string, string>;
  /** Position in the parameter list. */
  index: number;
  /** The default value's expression text (`cmd = process.env.CMD`), if any. */
  default?: string;
}

export interface FnInfo {
  /** Declared or assigned name, or null for an anonymous function. */
  name: string | null;
  /**
   * How it is defined. A `method` (class/object method) or a `property`
   * (`obj = { run: (c) => … }`) can be called through ANY receiver from
   * anywhere, so its call sites are never all in view.
   */
  kind: 'function' | 'arrow' | 'method' | 'property';
  params: FnParam[];
  /** Offset where the header begins (the name, `function`, or the parameter list). */
  headerStart: number;
  /** Body range: `[bodyStart, bodyEnd)`. For an expression arrow, the expression. */
  bodyStart: number;
  bodyEnd: number;
}

export interface Decl {
  at: number;
  init: string;
  scope: FnInfo | null;
  /** For a block-scoped `const`/`let` inside a nested `{ … }`: that block's range. */
  block?: [number, number];
}

export interface CallSite {
  /** Offset of the callee name. */
  index: number;
  /** Offset of the opening parenthesis. */
  open: number;
  args: ArgList;
}

const JS_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'with', 'typeof', 'new', 'await',
  'else', 'do', 'try', 'finally', 'case', 'throw', 'delete', 'void', 'in', 'of', 'yield', 'import', 'super',
]);

export class FileCtx {
  readonly path: string;
  readonly src: string;
  readonly lang: Lang;
  readonly mask: Uint8Array;
  private _starts?: number[];
  private _fns?: FnInfo[];
  private readonly _calls = new Map<string, CallSite[]>();
  private readonly _consts = new Map<string, string | null>();

  constructor(path: string, src: string) {
    this.path = path;
    this.src = src;
    this.lang = langOf(path);
    this.mask = codeMask(src, this.lang);
  }

  isCode(i: number): boolean {
    return this.mask[i] === CODE;
  }

  line(i: number): number {
    if (!this._starts) this._starts = lineStarts(this.src);
    return lineAt(this._starts, i);
  }

  /** Every function the file defines, in source order. */
  functions(): FnInfo[] {
    if (!this._fns) this._fns = this.lang === 'py' ? indexPyFunctions(this) : indexJsFunctions(this);
    return this._fns;
  }

  private _owner?: Int32Array;
  private _close?: Int32Array;

  /** The partner of the bracket at `i` (code only), or -1 — O(1) after one pass. */
  closeOf(i: number): number {
    if (!this._close) this._close = bracketTables(this.src, this.mask).close;
    return i >= 0 && i < this.src.length ? this._close[i]! : -1;
  }

  /**
   * The innermost function whose body contains `i`, or null at top level. O(1)
   * after one sweep: a lookup per call used to walk every function, which a file
   * of deeply nested callbacks turned into minutes.
   */
  enclosingFn(i: number): FnInfo | null {
    const fns = this.functions();
    if (!fns.length || i < 0 || i >= this.src.length) return null;
    if (!this._owner) this._owner = ownerIndex(fns, this.src.length);
    const k = this._owner[i]!;
    return k < 0 ? null : fns[k]!;
  }

  /**
   * Call sites of a function the file defines: `name(`, `this.name(`,
   * `self.name(` — never the definition itself.
   */
  callSitesOf(name: string): CallSite[] {
    const cached = this._calls.get(name);
    if (cached) return cached;
    const out: CallSite[] = [];
    const headers = new Set(this.functions().filter((f) => f.name === name).map((f) => f.headerStart));
    for (const i of identOffsets(this.src, this.mask, name, false)) {
      const before = this.src.slice(Math.max(0, i - 6), i);
      if (before.endsWith('.') && !/(?:this|self)\.$/.test(before)) continue;
      if (headers.has(i)) continue;
      if (/\bfunction\s*\*?\s*$/.test(this.src.slice(Math.max(0, i - 12), i))) continue;
      if (/\bdef\s+$/.test(this.src.slice(Math.max(0, i - 6), i))) continue;
      let j = i + name.length;
      while (j < this.src.length && (this.src[j] === ' ' || this.src[j] === '\t')) j++;
      if (this.src[j] !== '(') continue;
      const args = splitArgs(this.src, this.mask, j);
      if (args) out.push({ index: i, open: j, args });
    }
    this._calls.set(name, out);
    return out;
  }

  /**
   * True when a function's callers are NOT all visible in this file: it is
   * exported, assigned onto `exports`/`module.exports`, or used as a value
   * (passed as a callback, stored in a table). A wrapper's parameter can only
   * be folded from its call sites when every call site is in view — otherwise
   * an outside caller could pass anything.
   */
  private readonly _escapes = new Map<string, boolean>();

  escapes(name: string): boolean {
    const hit = this._escapes.get(name);
    if (hit !== undefined) return hit;
    const v = this.computeEscapes(name);
    this._escapes.set(name, v);
    return v;
  }

  private computeEscapes(name: string): boolean {
    const src = this.src;
    const esc = name.replace(/[$]/g, '\\$');
    // A method or an object property can be called as `anything.name(…)` from
    // anywhere — its callers are never all in view.
    if (this.functions().some((f) => f.name === name && (f.kind === 'method' || f.kind === 'property'))) return true;
    // Someone calls it through a receiver other than this/self.
    if (new RegExp(`(?<!\\b(?:this|self))\\.${esc}\\s*\\(`).test(src)) return true;
    if (this.lang === 'py') {
      // Module-level Python functions are importable; only `_private` or nested ones are local.
      const def = this.functions().find((f) => f.name === name);
      if (!def) return true;
      const nested = this.functions().some((g) => g !== def && def.headerStart > g.bodyStart && def.headerStart < g.bodyEnd);
      if (!name.startsWith('_') && !nested) return true;
    } else if (
      new RegExp(`\\bexport\\s+(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s*${esc}\\b`).test(src) ||
      new RegExp(`\\bexport\\s*\\{[^}]*\\b${esc}\\b[^}]*\\}`).test(src) ||
      new RegExp(`\\bexport\\s+(?:const|let|var)\\s+${esc}\\b`).test(src) ||
      new RegExp(`\\bexports\\.${esc}\\s*=`).test(src) ||
      new RegExp(`module\\.exports\\s*=\\s*\\{[^}]*\\b${esc}\\b`).test(src)
    ) {
      return true;
    }
    const headers = new Set(this.functions().filter((f) => f.name === name).map((f) => f.headerStart));
    for (const i of identOffsets(src, this.mask, name, false)) {
      if (headers.has(i)) continue;
      const before = src.slice(Math.max(0, i - 12), i);
      if (/\bfunction\s*\*?\s*$/.test(before) || /\bdef\s+$/.test(before)) continue;
      if (before.endsWith('.') && !/(?:this|self)\.$/.test(before)) continue; // someone else's property
      if (/(?:const|let|var)\s+$/.test(before)) continue; // `const name = (…) =>` declaration
      let j = i + name.length;
      while (j < src.length && (src[j] === ' ' || src[j] === '\t')) j++;
      if (src[j] === '(') continue; // a call
      if (src[j] === '=' && src[j + 1] !== '=' && src[j + 1] !== '>') continue; // assignment target
      return true;
    }
    return false;
  }

  /** Every function whose body contains `i`, innermost first. */
  enclosingChain(i: number): FnInfo[] {
    return this.functions()
      .filter((f) => i >= f.bodyStart && i < f.bodyEnd)
      .sort((a, b) => a.bodyEnd - a.bodyStart - (b.bodyEnd - b.bodyStart));
  }

  private readonly _decls = new Map<string, Decl[]>();
  private _pyDecls?: Map<string, { at: number; end: number }[]>;

  /** All `const|let|var NAME = …` (JS) / module-level `NAME = …` (Python) declarations, with their scope. */
  declsOf(name: string): Decl[] {
    const hit = this._decls.get(name);
    if (hit) return hit;
    const out: Decl[] = [];
    if (this.lang === 'py') {
      // Every module-level assignment of the file in one pass, then looked up by
      // name: a scan per name asked about let a file of loops over tens of
      // thousands of names cost a minute.
      if (!this._pyDecls) {
        this._pyDecls = new Map();
        for (const m of this.src.matchAll(/^([A-Za-z_]\w*)\s*(?::[^=\n]{1,80})?=(?!=)/gm)) {
          if (!this.isCode(m.index!)) continue;
          const list = this._pyDecls.get(m[1]!);
          const d = { at: m.index!, end: m.index! + m[0].length };
          if (list) list.push(d);
          else this._pyDecls.set(m[1]!, [d]);
        }
      }
      for (const d of this._pyDecls.get(name) ?? []) out.push({ at: d.at, init: this.readInit(d.end), scope: null });
      this._decls.set(name, out);
      return out;
    }
    const esc = name.replace(/[$]/g, '\\$');
    // A TypeScript annotation may hold `;` inside an object type:
    // `const TOOLS: Array<{ name: string; description: string }> = [`.
    const re = new RegExp(`\\b(const|let|var)\\s+${esc}\\s*(?::[^=]{1,200}?)?=(?![=>])`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(this.src))) {
      if (!this.isCode(m.index)) continue;
      if (m[1] !== 'const' && this.reassigned(name)) continue;
      const nameAt = m.index + m[0].indexOf(name, m[1]!.length);
      const scope = this.enclosingFn(nameAt);
      // `const`/`let` are BLOCK-scoped: inside `if (…) { const x = … }` the binding
      // ends at that block's `}`, and a same-named parameter rules outside it.
      const block = m[1] !== 'var' ? this.blockOf(m.index, scope) : null;
      out.push({ at: nameAt, init: this.readInit(m.index + m[0].length), scope, ...(block ? { block } : {}) });
    }
    this._decls.set(name, out);
    return out;
  }

  /**
   * The initializer visible at offset `at`: the innermost declaration whose
   * scope contains `at`. A same-named `const` in an unrelated function is never
   * used — in a bundle, names repeat, and resolving the wrong one would turn a
   * runtime value into a "constant". Ambiguity resolves to undefined.
   */
  constInitAt(name: string, at: number): { init: string; at: number } | undefined {
    const visible = this.declsOf(name).filter(
      (d) => (!d.scope || (at >= d.scope.bodyStart && at < d.scope.bodyEnd)) && (!d.block || (at >= d.block[0] && at < d.block[1])),
    );
    if (!visible.length) return undefined;
    const size = (d: Decl): number => (d.block ? d.block[1] - d.block[0] : d.scope ? d.scope.bodyEnd - d.scope.bodyStart : Number.MAX_SAFE_INTEGER);
    const inner = Math.min(...visible.map(size));
    const level = visible.filter((d) => size(d) === inner);
    if (new Set(level.map((d) => d.init)).size !== 1) return undefined;
    const chosen = level[0]!;
    // A function between the use site and the declaration that has a PARAMETER
    // of this name shadows it: the value there is whatever the caller passed.
    for (const fn of this.enclosingChain(at)) {
      if (chosen.scope && !(fn.bodyStart >= chosen.scope.bodyStart && fn.bodyEnd <= chosen.scope.bodyEnd)) break;
      if (fn === chosen.scope) break;
      if (fn.params.some((p) => p.name === name || [...(p.keys?.values() ?? [])].includes(name))) return undefined;
    }
    // Any OTHER binding of the name in the declaration's scope — a for-of/in
    // variable, a catch parameter, a destructured local, a bare `let NAME;`, a
    // Python local or loop variable — may shadow it at the use site. Then the
    // declaration proves nothing about the value there.
    if (this.otherBinding(name, chosen.scope, chosen.at)) return undefined;
    return { init: chosen.init, at: chosen.at };
  }

  /** The `{ … }` block a declaration at `at` lives in, when it is narrower than the function body. */
  private blockOf(at: number, scope: FnInfo | null): [number, number] | null {
    const floor = scope ? scope.bodyStart : 0;
    let depth = 0;
    for (let i = at - 1; i >= floor; i--) {
      if (this.mask[i] !== 0) continue;
      const c = this.src[i]!;
      if (c === '}' || c === ')' || c === ']') depth++;
      else if (c === '(' || c === '[') { if (depth) depth--; }
      else if (c === '{') {
        if (depth) { depth--; continue; }
        if (scope && i === scope.bodyStart - 1) return null; // the function body itself
        const end = matchBracket(this.src, this.mask, i);
        return end > 0 ? [i, end] : null;
      }
    }
    return null;
  }

  private readonly _other = new Map<string, boolean>();

  private otherBinding(name: string, scope: FnInfo | null, declAt: number): boolean {
    const key = `${name}\u0000${scope ? scope.bodyStart : -1}\u0000${declAt}`;
    const hit = this._other.get(key);
    if (hit !== undefined) return hit;
    const v = this.computeOtherBinding(name, scope, declAt);
    this._other.set(key, v);
    return v;
  }

  private computeOtherBinding(name: string, scope: FnInfo | null, declAt: number): boolean {
    const from = scope ? scope.bodyStart : 0;
    const to = scope ? scope.bodyEnd : this.src.length;
    const region = this.src.slice(from, to);
    const n = name.replace(/[$]/g, '\\$');
    const forms =
      this.lang === 'py'
        ? [
            new RegExp(`^[ \\t]+${n}\\s*(?::[^=\\n]+)?=(?!=)`, 'gm'),
            new RegExp(`\\bfor\\s+[^\\n:]*\\b${n}\\b[^\\n:]*\\s+in\\b`, 'g'),
            new RegExp(`\\bas\\s+${n}\\b`, 'g'),
            new RegExp(`\\b(?:global|nonlocal)\\s+[^\\n]*\\b${n}\\b`, 'g'),
            new RegExp(`(?:^|[^=!<>])\\b${n}\\s*(?:\\+|-|\\*|/|\\||&)?=(?!=)`, 'gm'),
          ]
        : [
            new RegExp(`\\bfor\\s*\\(\\s*(?:const|let|var)?\\s*[\\[{]?[^;)]*\\b${n}\\b[^;)]*\\s+(?:of|in)\\b`, 'g'),
            new RegExp(`\\bcatch\\s*\\(\\s*[\\[{]?[^)]*\\b${n}\\b`, 'g'),
            new RegExp(`\\b(?:const|let|var)\\s*[\\[{][^=;]*\\b${n}\\b[^=;]*[\\]}]\\s*=`, 'g'),
            new RegExp(`\\b(?:let|var)\\s+${n}\\s*[;,\\n]`, 'g'),
            new RegExp(`\\b(?:const|let|var)\\s+${n}\\s*(?::[^=;]{1,80})?=(?!=)`, 'g'),
            new RegExp(`(?<![\\w$.])${n}\\s*(?:\\+|-|\\*|/|\\|\\||&&|\\?\\?)?=(?![=>])`, 'g'),
            // A destructuring assignment target: `[a, NAME] = …`, `({ NAME } = …)`.
            // `=>` is an arrow, not an assignment: `f(x, NAME, async () => …)`
            // read as one made NAME unreadable for the whole file.
            new RegExp(`[\\[{,]\\s*${n}\\s*[\\]},][^=;]*\\]?\\s*=(?![=>])`, 'g'),
          ];
    for (const re of forms) {
      let m: RegExpExecArray | null;
      while ((m = re.exec(region))) {
        const at = from + m.index + m[0].search(new RegExp(`\\b${n}\\b`));
        if (!this.isCode(from + m.index)) continue;
        if (Math.abs(at - declAt) < 2) continue; // the chosen declaration itself
        // The declaring statement's own `const NAME =` text is matched by two forms; skip it once.
        if (this.src.slice(Math.max(0, declAt - 12), declAt + name.length + 4).includes(this.src.slice(from + m.index, from + m.index + m[0].length).trim()) && Math.abs(from + m.index - declAt) < 16) continue;
        return true;
      }
    }
    return false;
  }

  private readonly _mutated = new Map<string, boolean>();

  /** Is NAME (an array/object) mutated anywhere in the given scope after being declared? Memoised per (name, scope). */
  mutated(name: string, scope: FnInfo | null): boolean {
    const key = `${name}\u0000${scope ? scope.bodyStart : -1}`;
    const hit = this._mutated.get(key);
    if (hit !== undefined) return hit;
    const v = this.computeMutated(name, scope);
    this._mutated.set(key, v);
    return v;
  }

  private computeMutated(name: string, scope: FnInfo | null): boolean {
    const region = scope ? this.src.slice(scope.bodyStart, scope.bodyEnd) : this.src;
    const n = name.replace(/[$]/g, '\\$');
    // Through an element (`TOOLS[1].disabled = false`, `delete TOOLS[0].x`,
    // `Object.assign(TOOLS[1], …)`) or a loop variable over it (`for (const t of TOOLS) t.x = …`).
    if (
      new RegExp(`(?<![\\w$.])${n}\\s*\\[[^\\]\\n]{0,100}\\]\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*\\s*|\\[[^\\]\\n]{0,100}\\]\\s*)*(?:=(?![=>])|\\+\\+|--)|\\bdelete\\s+${n}\\s*[[.]|Object\\.assign\\s*\\(\\s*${n}\\s*[[.]`).test(region)
    ) {
      return true;
    }
    const loopVar = new RegExp(`\\bfor\\s*\\(\\s*(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s+of\\s+${n}\\s*\\)|(?<![\\w$.])${n}\\s*\\.\\s*forEach\\s*\\(\\s*\\(?\\s*([A-Za-z_$][\\w$]*)`, 'g');
    for (const m of region.matchAll(loopVar)) {
      const v = (m[1] ?? m[2])!.replace(/[$]/g, '\\$');
      const after = region.slice(m.index!, m.index! + 4000);
      if (new RegExp(`(?<![\\w$.])${v}\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*|\\[[^\\]\\n]{0,100}\\])\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*\\s*)*=(?![=>])|Object\\.assign\\s*\\(\\s*${v}\\b|\\bdelete\\s+${v}\\s*[[.]`).test(after)) return true;
    }
    return new RegExp(
      `(?<![\\w$.])${n}\\s*(?:\\.\\s*(?:push|unshift|splice|fill|copyWithin|reverse|sort|set|add|append|extend|insert|update)\\s*\\(|\\[[^\\]]*\\]\\s*=(?!=)|\\.\\s*[A-Za-z_$][\\w$]*\\s*=(?!=)|\\.length\\s*=)|Object\\.(?:assign|defineProperty|defineProperties)\\s*\\(\\s*${n}\\b|\\.\\.\\.\\s*${n}\\b(?=[^)]*\\)\\s*=(?![=>]))`,
    ).test(region);
  }

  /**
   * The initializer of NAME when it is unambiguous file-wide (one declaration,
   * or several identical ones). Prefer {@link constInitAt} when the use site is known.
   */
  constInit(name: string): string | undefined {
    if (this._consts.has(name)) return this._consts.get(name) ?? undefined;
    const decls = this.declsOf(name);
    const value = decls.length && new Set(decls.map((d) => d.init)).size === 1 ? decls[0]!.init : undefined;
    this._consts.set(name, value ?? null);
    return value;
  }

  private reassigned(name: string): boolean {
    let n = 0;
    for (const i of identOffsets(this.src, this.mask, name)) {
      const after = this.src.slice(i + name.length, i + name.length + 4);
      if (/^\s*=(?!=)/.test(after) || /^\s*(?:\+\+|--|[+\-*/]=)/.test(after)) n++;
      if (n > 1) return true;
    }
    return false;
  }

  /** Read an initializer starting at `from` up to the end of the statement. */
  readInit(from: number): string {
    const src = this.src;
    let depth = 0;
    let i = from;
    const cap = Math.min(src.length, from + 4000);
    for (; i < cap; i++) {
      if (!this.isCode(i)) continue;
      const c = src[i]!;
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') {
        if (depth === 0) break;
        depth--;
      } else if (depth === 0 && (c === ';' || c === ',')) break;
      else if (depth === 0 && c === '\n') {
        // A newline ends the statement unless the expression visibly continues.
        const rest = src.slice(i + 1, i + 40).trimStart();
        const prev = src.slice(Math.max(from, i - 3), i).trimEnd();
        if (!/^[?:.+|&]/.test(rest) && !/[=?:+|&(,]$/.test(prev)) break;
      }
    }
    return src.slice(from, i).trim();
  }
}

// --- JS function index ------------------------------------------------------

/**
 * Remove TypeScript generic arguments from a parameter list: a comma inside
 * `Map<string, unknown>` is not a parameter boundary, and splitting there
 * shifted every later parameter's index.
 */
export function stripGenerics(text: string): string {
  let t = text;
  for (let k = 0; k < 8; k++) {
    const next = t.replace(/([A-Za-z_$][\w$.]*)\s*<[^<>()=;]{0,400}>/g, '$1');
    if (next === t) break;
    t = next;
  }
  return t;
}

function parseParams(text: string): FnParam[] {
  const parts = splitTopLevel(stripGenerics(text), ',').filter(Boolean);
  return parts.map((raw, index) => {
    let p = raw.replace(/^\.\.\./, '').trim();
    // Strip a default value (kept: an omitted argument takes it) and a TypeScript annotation.
    const eq = splitTopLevel(p, '=');
    p = eq[0] ?? p;
    const dflt = eq.length > 1 ? eq.slice(1).join('=').trim() : undefined;
    if (p.startsWith('{')) {
      const keys = new Map<string, string>();
      const inner = p.slice(1, p.lastIndexOf('}'));
      for (const entry of splitTopLevel(inner, ',')) {
        const e = (splitTopLevel(entry, '=')[0] ?? '').replace(/^\.\.\./, '').trim();
        if (!e) continue;
        const [k, v] = splitTopLevel(e, ':');
        const key = (k ?? '').trim();
        const local = (v ?? k ?? '').trim();
        if (/^[A-Za-z_$][\w$]*$/.test(key) && /^[A-Za-z_$][\w$]*$/.test(local)) keys.set(key, local);
      }
      return { name: '', keys, index, ...(dflt !== undefined ? { default: dflt } : {}) };
    }
    const name = (splitTopLevel(p, ':')[0] ?? '').replace(/\?$/, '').trim();
    return { name: /^[A-Za-z_$][\w$]*$/.test(name) ? name : '', index, ...(dflt !== undefined ? { default: dflt } : {}) };
  });
}

function indexJsFunctions(ctx: FileCtx): FnInfo[] {
  const { src, mask } = ctx;
  const out: FnInfo[] = [];
  // Matching brackets and expression ends for the whole file, in two linear
  // passes. Calling matchBracket per function scanned every nested body again —
  // quadratic on a file of deeply nested callbacks (minutes at 180 KB).
  const t = bracketTables(src, mask);
  const matchBracket = (_s: string, _m: Uint8Array, open: number, _limit?: number): number => (open >= 0 && open < src.length ? t.close[open]! : -1);
  const matchOpen = (_s: string, _m: Uint8Array, close: number): number => (close >= 0 && close < src.length ? t.open[close]! : -1);
  const exprEnd = (_s: string, _m: Uint8Array, from: number): number => {
    let i = from;
    while (i < src.length && mask[i] !== CODE) i++;
    return i < src.length ? t.term[i]! : src.length;
  };
  const add = (name: string | null, headerStart: number, paramOpen: number, kind: FnInfo['kind']): void => {
    const close = matchBracket(src, mask, paramOpen, 20_000);
    if (close < 0) return;
    const params = parseParams(src.slice(paramOpen + 1, close));
    let j = close + 1;
    while (j < src.length && /\s/.test(src[j]!)) j++;
    // TypeScript return annotation: `): Promise<X> {`
    if (src[j] === ':') {
      while (j < src.length && src[j] !== '{' && src[j] !== '=' && src[j] !== '\n') j++;
    }
    if (src.startsWith('=>', j)) {
      j += 2;
      while (j < src.length && /\s/.test(src[j]!)) j++;
    }
    if (src[j] === '{') {
      const end = matchBracket(src, mask, j);
      if (end > 0) out.push({ name, kind, params, headerStart, bodyStart: j + 1, bodyEnd: end });
      return;
    }
    // Expression-bodied arrow: up to the end of the enclosing expression.
    const end = exprEnd(src, mask, j);
    out.push({ name, kind, params, headerStart, bodyStart: j, bodyEnd: end });
  };

  // `function name(…) {` and `function (…) {`
  const reFn = /\bfunction\b\s*\*?\s*([A-Za-z_$][\w$]*)?\s*(?:<[^()]{0,200}?>\s*)?\(/g;
  let m: RegExpExecArray | null;
  while ((m = reFn.exec(src))) {
    if (mask[m.index] !== CODE) continue;
    const open = m.index + m[0].length - 1;
    const assigned = assignedName(src, m.index);
    add(m[1] ?? assigned, m[1] ? m.index + m[0].indexOf(m[1]) : m.index, open, !m[1] && isPropertyAssignment(src, m.index) ? 'property' : 'function');
  }
  // Arrow functions: `(…) =>` and `x =>`.
  let from = 0;
  for (;;) {
    const a = src.indexOf('=>', from);
    if (a < 0) break;
    from = a + 2;
    if (mask[a] !== CODE) continue;
    let k = a - 1;
    while (k >= 0 && /\s/.test(src[k]!)) k--;
    // A TypeScript return type: `(a: A): Promise<void> =>` — step back to its `)`.
    if (src[k] !== ')') {
      const back = src.slice(Math.max(0, k - 160), k + 1);
      const rt = /\)\s*:\s*[^=;{}()]{1,150}$/.exec(back);
      if (rt) k = k - (back.length - rt.index) + 1;
    }
    if (src[k] === ')') {
      const open = matchOpen(src, mask, k);
      if (open < 0) continue;
      let h = open - 1;
      while (h >= 0 && /\s/.test(src[h]!)) h--;
      // A generic arrow: `const register = <T extends X>(server, …) => …`.
      let headAt = open;
      if (src[h] === '>' && src[h - 1] !== '=') {
        let d = 0;
        for (let q = h; q >= Math.max(0, h - 300); q--) {
          if (src[q] === '>') d++;
          else if (src[q] === '<' && --d === 0) {
            headAt = q;
            break;
          }
        }
        if (headAt !== open) {
          h = headAt - 1;
          while (h >= 0 && /\s/.test(src[h]!)) h--;
        }
      }
      const asyncKw = src.slice(Math.max(0, h - 4), h + 1) === 'async' ? h - 4 : headAt;
      add(assignedName(src, asyncKw), asyncKw, open, isPropertyAssignment(src, asyncKw) ? 'property' : 'arrow');
    } else if (/[\w$]/.test(src[k] ?? '')) {
      let s = k;
      while (s > 0 && /[\w$]/.test(src[s - 1]!)) s--;
      const param = src.slice(s, k + 1);
      if (JS_KEYWORDS.has(param)) continue;
      // Synthesize a one-parameter header.
      let j = a + 2;
      while (j < src.length && /\s/.test(src[j]!)) j++;
      const name = assignedName(src, s);
      if (src[j] === '{') {
        const end = matchBracket(src, mask, j);
        if (end > 0) out.push({ name, kind: isPropertyAssignment(src, s) ? 'property' : 'arrow', params: [{ name: param, index: 0 }], headerStart: s, bodyStart: j + 1, bodyEnd: end });
      } else {
        out.push({ name, kind: isPropertyAssignment(src, s) ? 'property' : 'arrow', params: [{ name: param, index: 0 }], headerStart: s, bodyStart: j, bodyEnd: exprEnd(src, mask, j) });
      }
    }
  }
  // Methods: `name(…) {` in a class or object literal (not a call, not a keyword).
  // Anchored by a LOOKBEHIND and horizontal whitespace only: the old form,
  // `(?:^|[;{}\n,])\s*…\s*`, let `\n` be both the anchor and part of two adjacent
  // `\s*`, which is cubic on a run of blank lines (minutes on a few thousand).
  const reMethod = /(?<=^|[;{},\n])[ \t]*(?:(?:async|static|get|set|public|private|protected|override)[ \t]+)*\*?[ \t]*(#?[A-Za-z_$][\w$]*)[ \t]*(?:<[^()\n]{0,200}?>[ \t]*)?\(/g;
  while ((m = reMethod.exec(src))) {
    const nameIdx = m.index + m[0].lastIndexOf(m[1]!);
    if (mask[nameIdx] !== CODE) continue;
    const name = m[1]!;
    if (JS_KEYWORDS.has(name)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchBracket(src, mask, open, 20_000);
    if (close < 0) continue;
    let j = close + 1;
    while (j < src.length && /\s/.test(src[j]!)) j++;
    if (src[j] === ':') while (j < src.length && src[j] !== '{' && src[j] !== '\n' && src[j] !== ';') j++;
    if (src[j] !== '{') continue; // a call statement, not a definition
    if (out.some((f) => f.headerStart === nameIdx)) continue;
    add(name.replace(/^#/, ''), nameIdx, open, 'method');
  }
  return out;
}

/** `{ NAME: <here> }` / `obj.NAME = <here>` — a function stored as a property. */
function isPropertyAssignment(src: string, at: number): boolean {
  const back = src.slice(Math.max(0, at - 80), at);
  return /(?:[{,]\s*['"]?[A-Za-z_$][\w$]*['"]?\s*:\s*|\.[A-Za-z_$][\w$]*\s*=\s*)(?:async\s+)?$/.test(back);
}

/** `const NAME = <here>` / `NAME: <here>` / `NAME = <here>` → NAME. */
function assignedName(src: string, at: number): string | null {
  const back = src.slice(Math.max(0, at - 80), at);
  const m = /([A-Za-z_$][\w$]*)\s*(?::\s*[^=,;{}()]{0,40})?\s*(?:=|:)\s*(?:async\s+)?$/.exec(back);
  return m ? m[1]! : null;
}

function matchOpen(src: string, mask: Uint8Array, close: number): number {
  let depth = 0;
  for (let i = close; i >= 0 && i > close - 20_000; i--) {
    if (mask[i] !== CODE) continue;
    const c = src[i]!;
    if (c === ')' || c === ']' || c === '}') depth++;
    else if (c === '(' || c === '[' || c === '{') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** End of an expression starting at `from`: the first top-level `,` `)` `]` `}` or `;`. */
function exprEnd(src: string, mask: Uint8Array, from: number): number {
  let depth = 0;
  const cap = Math.min(src.length, from + 20_000);
  for (let i = from; i < cap; i++) {
    if (mask[i] !== CODE) continue;
    const c = src[i]!;
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) return i;
      depth--;
    } else if (depth === 0 && (c === ',' || c === ';')) return i;
  }
  return cap;
}

// --- Python function index --------------------------------------------------

function indexPyFunctions(ctx: FileCtx): FnInfo[] {
  const { src, mask } = ctx;
  const out: FnInfo[] = [];
  const re = /^([ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    if (mask[m.index + m[1]!.length] !== CODE) continue;
    const indent = m[1]!.length;
    const open = m.index + m[0].length - 1;
    const close = matchBracket(src, mask, open, 20_000);
    if (close < 0) continue;
    const params = parseParams(src.slice(open + 1, close).replace(/\*\*?/g, ''))
      .filter((p) => p.name !== 'self' && p.name !== 'cls')
      .map((p, index) => ({ ...p, index }));
    const colon = src.indexOf(':', close);
    if (colon < 0) continue;
    const bodyStart = src.indexOf('\n', colon) + 1;
    if (bodyStart <= 0) continue;
    // Body: following lines indented deeper than the `def`.
    let end = bodyStart;
    let pos = bodyStart;
    while (pos < src.length) {
      const nl = src.indexOf('\n', pos);
      const lineEnd = nl < 0 ? src.length : nl;
      const line = src.slice(pos, lineEnd);
      if (line.trim() !== '') {
        const ind = line.length - line.trimStart().length;
        if (ind <= indent && mask[pos + ind] === CODE) break;
      }
      end = lineEnd;
      if (nl < 0) break;
      pos = nl + 1;
    }
    const isMethod = /^\s*(?:self|cls)\b/.test(src.slice(open + 1, close));
    out.push({ name: m[2]!, kind: isMethod ? 'method' : 'function', params, headerStart: m.index + m[0].indexOf(m[2]!), bodyStart, bodyEnd: end });
  }
  return out;
}

// --- linear-time indexes ------------------------------------------------------

/**
 * For every bracket in code: its partner (`close[open]`, `open[close]`), and
 * for every code offset the end of the expression it starts — the first `,`
 * `;` or closing bracket at the same depth (`term`). Two passes, O(n).
 */
function bracketTables(src: string, mask: Uint8Array): { close: Int32Array; open: Int32Array; term: Int32Array } {
  const n = src.length;
  const close = new Int32Array(n).fill(-1);
  const open = new Int32Array(n).fill(-1);
  const term = new Int32Array(n).fill(n);
  const stack: number[] = [];
  for (let i = 0; i < n; i++) {
    if (mask[i] !== CODE) continue;
    const c = src.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) stack.push(i);
    else if (c === 41 || c === 93 || c === 125) {
      const o = stack.pop();
      if (o !== undefined) {
        close[o] = i;
        open[i] = o;
      }
    }
  }
  // Right to left: the nearest terminator at each depth.
  const last: number[] = [n];
  for (let i = n - 1; i >= 0; i--) {
    if (mask[i] !== CODE) {
      term[i] = last[last.length - 1]!;
      continue;
    }
    const c = src.charCodeAt(i);
    if (c === 41 || c === 93 || c === 125) {
      term[i] = last[last.length - 1]!;
      last.push(i); // inside this group, the closer ends the expression
    } else if (c === 40 || c === 91 || c === 123) {
      if (last.length > 1) last.pop();
      term[i] = last[last.length - 1]!;
    } else {
      if (c === 44 || c === 59) last[last.length - 1] = i;
      term[i] = last[last.length - 1]!;
    }
  }
  return { close, open, term };
}

/** For every offset, the index (into `fns`) of the innermost function body holding it, or -1. */
function ownerIndex(fns: FnInfo[], n: number): Int32Array {
  const owner = new Int32Array(n).fill(-1);
  const order = fns.map((_, i) => i).sort((a, b) => fns[a]!.bodyStart - fns[b]!.bodyStart || fns[b]!.bodyEnd - fns[a]!.bodyEnd);
  const stack: number[] = [];
  let k = 0;
  for (let p = 0; p < n; p++) {
    while (stack.length && fns[stack[stack.length - 1]!]!.bodyEnd <= p) stack.pop();
    while (k < order.length && fns[order[k]!]!.bodyStart <= p) {
      const f = fns[order[k]!]!;
      if (f.bodyEnd > p) stack.push(order[k]!);
      k++;
    }
    if (stack.length) owner[p] = stack[stack.length - 1]!;
  }
  return owner;
}

// --- cache ------------------------------------------------------------------

const cache = new WeakMap<object, FileCtx>();

/** One FileCtx per source-file object, so analyses share the lex pass. */
export function fileCtxOf(file: { path: string; content: string }): FileCtx {
  let c = cache.get(file);
  if (!c) {
    c = new FileCtx(file.path, file.content);
    cache.set(file, c);
  }
  return c;
}
