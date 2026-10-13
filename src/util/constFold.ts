/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * One constant folder for every rule that asks "what does this expression
 * reduce to?" — the program a process call runs (MTC-SRC-002), the path a
 * dynamic `import()` loads (MTC-SRC-005, the import graph), the elements of a
 * deny-list (MTC-SRC-006). Before this, each rule guessed on its own, and a
 * `const` one line up was enough to make a fixed program look attacker-chosen.
 *
 * Deterministic and conservative: anything it cannot reduce with certainty is
 * `unknown`, and every caller treats `unknown` exactly as it treated a
 * non-literal before. Folding can only ever remove a finding that was wrong,
 * never invent one.
 */

import type { FileCtx } from './fileCtx.js';
import { CODE, codeMask, matchBracket, splitArgs, splitTopLevel } from './jsLex.js';

export type Folded =
  /** One or more possible constant strings (a literal, or a ternary of literals). */
  | { kind: 'literal'; values: string[] }
  /** A path inside the package itself, anchored at the module's own directory. */
  | { kind: 'own-path'; value: string }
  /** The running interpreter: `process.execPath` / `sys.executable`. */
  | { kind: 'exec-path' }
  /** An array/list literal; `dynamic` when it has a spread or unknown element. */
  | { kind: 'array'; elements: Folded[]; dynamic: boolean }
  | { kind: 'unknown'; why?: string };

export interface FoldScope {
  /** Bindings the caller already resolved, e.g. a wrapper function's parameters. */
  bindings?: Map<string, Folded>;
  /** Lazy resolver for names the caller can bind on demand (enclosing functions' parameters). */
  resolve?: (name: string) => Folded | undefined;
  /** The offset the expression is evaluated at — drives scope-aware `const` lookup. */
  at?: number;
  /**
   * Fold a call like `findPackageRoot(__dirname)` to the package root. Only for
   * FILE PATHS (module loads, the import graph) and only for root-finder names —
   * never for a process's program or command line, where an arbitrary helper fed
   * `__dirname` could return anything.
   */
  pathContext?: boolean;
}

const UNKNOWN: Folded = { kind: 'unknown' };
const MAX_DEPTH = 32;
/** Hops through `const` aliases (`a = b; b = c; c = "lit"`) — the TZ asks for at least 3. */
const MAX_ALIAS_HOPS = 4;
const MAX_VALUES = 16;

/** True when the value is fully known at analysis time. */
export function isConst(f: Folded): boolean {
  if (f.kind === 'literal' || f.kind === 'own-path' || f.kind === 'exec-path') return true;
  if (f.kind === 'array') return !f.dynamic && f.elements.every(isConst);
  return false;
}

/** A short, human label for a folded value (used in finding text). */
export function describeFolded(f: Folded): string {
  switch (f.kind) {
    case 'literal':
      return f.values.length === 1 ? f.values[0]! : f.values.join(' | ');
    case 'own-path':
      return f.value === '.' ? '<this package file>' : `<package>/${f.value.replace(/^\.?\/?/, '')}`;
    case 'exec-path':
      return '<node>';
    case 'array':
      return `[${f.elements.map(describeFolded).join(', ')}${f.dynamic ? ', …' : ''}]`;
    default:
      return '<runtime value>';
  }
}

const PATH_JOIN = /^(?:path\.(?:posix\.|win32\.)?|posix\.|os\.path\.|)(?:join|resolve|normalize|abspath|realpath|normpath)$/;
const PATH_WRAP = /^(?:path\.(?:posix\.)?|url\.|os\.path\.|fs\.|node:path\.|pathlib\.|)(?:dirname|fileURLToPath|pathToFileURL|realpathSync|Path|PurePath|resolvePath|toNamespacedPath|String)$/;

export function fold(ctx: FileCtx, exprIn: string, scope?: FoldScope, depth = 0, hops = 0): Folded {
  if (depth > MAX_DEPTH || hops > MAX_ALIAS_HOPS) return UNKNOWN;
  let e = exprIn.trim();
  if (!e) return UNKNOWN;
  // TypeScript-only noise that survives in shipped `.ts` sources.
  e = e.replace(/\s+as\s+(?:const|[\w.$<>[\]| ]+)$/, '').replace(/!$/, '').replace(/^<[\w.$]+>\s*/, '');
  e = e.replace(/^await\s+/, '');
  e = stripParens(e);

  const py = ctx.lang === 'py';

  // Ternary: `c ? a : b` (JS) / `a if c else b` (Python).
  const tern = py ? splitPyTernary(e) : splitTernary(e);
  if (tern) return union(fold(ctx, tern[0], scope, depth + 1, hops), fold(ctx, tern[1], scope, depth + 1, hops));

  for (const op of py ? [' or '] : ['||', '??']) {
    const parts = splitTopLevel(e, op);
    if (parts.length > 1) return parts.map((p) => fold(ctx, p, scope, depth + 1, hops)).reduce(union);
  }

  const plus = splitPlus(e);
  if (plus.length > 1) return concat(plus.map((p) => fold(ctx, p, scope, depth + 1, hops)));

  // pathlib: `Path(__file__).parent / "x" / "y"`
  if (py) {
    const slash = splitTopLevel(e, ' / ');
    if (slash.length > 1) {
      const head = fold(ctx, slash[0]!, scope, depth + 1, hops);
      const rest = slash.slice(1).map((p) => fold(ctx, p, scope, depth + 1, hops));
      if (head.kind === 'own-path' && rest.every((r) => r.kind === 'literal' && r.values.length === 1)) {
        return { kind: 'own-path', value: joinPath(head.value, ...rest.map((r) => (r as { values: string[] }).values[0]!)) };
      }
      return UNKNOWN;
    }
  }

  return primary(ctx, e, scope, depth, hops);
}

function primary(ctx: FileCtx, e: string, scope: FoldScope | undefined, depth: number, hops: number): Folded {
  const py = ctx.lang === 'py';
  const str = readStringLiteral(e, py);
  if (str !== undefined) return { kind: 'literal', values: [str] };
  if (e.startsWith('`') && e.endsWith('`') && e.length >= 2) return foldTemplate(ctx, e.slice(1, -1), scope, depth, hops, '${', '}');
  const fstr = /^[fF][rR]?(['"])([\s\S]*)\1$/.exec(e) ?? /^[rR][fF](['"])([\s\S]*)\1$/.exec(e);
  if (py && fstr) return foldTemplate(ctx, fstr[2]!, scope, depth, hops, '{', '}');
  if (/^-?\d+(?:\.\d+)?$/.test(e)) return { kind: 'literal', values: [e] };
  if (/^(?:true|false|null|undefined|None|True|False)$/.test(e)) return { kind: 'literal', values: [e] };

  if (e.startsWith('[') && e.endsWith(']')) return foldArray(ctx, e, scope, depth, hops);
  if (py && e.startsWith('(') && e.endsWith(')') && splitTopLevel(e.slice(1, -1), ',').length > 1) {
    return foldArray(ctx, `[${e.slice(1, -1)}]`, scope, depth, hops);
  }
  if (e.startsWith('{')) return UNKNOWN;

  if (/^[A-Za-z_$][\w$]*$/.test(e)) {
    if (e === '__dirname' || e === '__filename' || e === '__file__') return { kind: 'own-path', value: '.' };
    // The innermost visible declaration wins over an enclosing function's parameter.
    const decl = scope?.at !== undefined ? ctx.constInitAt(e, scope.at) : undefined;
    const declScoped = decl ? ctx.enclosingFn(decl.at) : null;
    const bound = scope?.bindings?.get(e) ?? (decl && declScoped ? undefined : scope?.resolve?.(e));
    if (bound) return bound;
    if (decl && decl.init !== e) {
      // `const args = ['-c']; args.push(input)` — the declaration is not the value.
      if (/^[[{]/.test(decl.init.trim()) && ctx.mutated(e, ctx.enclosingFn(decl.at))) return { kind: 'unknown', why: `${e} (mutated)` };
      return fold(ctx, decl.init, { ...scope, at: decl.at }, depth + 1, hops + 1);
    }
    if (scope?.at === undefined) {
      const init = ctx.constInit(e);
      if (init !== undefined && init !== e) return fold(ctx, init, scope, depth + 1, hops + 1);
    }
    return { kind: 'unknown', why: e };
  }

  if (e === 'process.execPath' || e === 'sys.executable' || e === 'process.argv[0]' || e === 'process.argv0') return { kind: 'exec-path' };
  if (/^import\.meta\.(?:url|dirname|filename)$/.test(e)) return { kind: 'own-path', value: '.' };

  // `x.href` / `x.pathname` / `x.toString()` / `x.parent` / `x.resolve()` keep the value's nature.
  const post = /^([\s\S]+?)\.(?:href|pathname|toString\(\s*\)|parent|resolve\(\s*\)|absolute\(\s*\)|as_posix\(\s*\))$/.exec(e);
  if (post) {
    const inner = fold(ctx, post[1]!, scope, depth + 1, hops);
    if (inner.kind === 'own-path' || inner.kind === 'literal') return inner;
    return UNKNOWN;
  }

  // `new URL(lit, import.meta.url)`
  const newUrl = /^new\s+URL\s*\(/.exec(e);
  if (newUrl && e.endsWith(')')) {
    const args = argsOf(e, newUrl[0].length - 1);
    if (!args) return UNKNOWN;
    const base = args[1] !== undefined ? fold(ctx, args[1], scope, depth + 1, hops) : undefined;
    const rel = fold(ctx, args[0] ?? '', scope, depth + 1, hops);
    if (base?.kind === 'own-path' && rel.kind === 'literal' && rel.values.length === 1) {
      return { kind: 'own-path', value: joinPath(base.value, rel.values[0]!) };
    }
    if (!base && rel.kind === 'literal') return rel;
    // `new URL(import.meta.url)` — the module's own file.
    if (!base && rel.kind === 'own-path') return rel;
    return UNKNOWN;
  }

  // A call whose argument list closes the expression: `callee(args…)`.
  const call = /^([A-Za-z_$][\w$.]*)\s*\(/.exec(e);
  if (call && e.endsWith(')')) {
    const open = call[0].length - 1;
    const args = argsOf(e, open);
    if (!args) return UNKNOWN;
    const callee = call[1]!;
    if (PATH_JOIN.test(callee)) {
      const parts = args.map((a) => fold(ctx, a, scope, depth + 1, hops));
      if (!parts.length) return UNKNOWN;
      const tail = parts.slice(1);
      const tailLits = tail.every((p) => p.kind === 'literal' && p.values.length === 1);
      const lit = (p: Folded): string => (p as { values: string[] }).values[0]!;
      // `path.resolve(base, '/abs')` and Python's `os.path.join(base, '/abs')` start
      // over at an absolute segment — the result is NOT inside the package.
      const resets = /resolve$|^os\.path\.join$|abspath|realpath/.test(callee);
      const absAt = tail.findIndex((p) => p.kind === 'literal' && p.values.length === 1 && /^(?:\/|[A-Za-z]:[\\/]|~)/.test(p.values[0]!));
      if (absAt >= 0) {
        if (!resets) return UNKNOWN; // path.join keeps the base, but an absolute-looking segment is a red flag either way
        const rest = tail.slice(absAt);
        return rest.every((p) => p.kind === 'literal' && p.values.length === 1) ? { kind: 'literal', values: [rest.map(lit).join('/')] } : UNKNOWN;
      }
      if (parts[0]!.kind === 'own-path' && tailLits) return { kind: 'own-path', value: joinPath((parts[0] as { value: string }).value, ...tail.map(lit)) };
      if (parts.every((p) => p.kind === 'literal' && p.values.length === 1)) return { kind: 'literal', values: [joinPath(...parts.map(lit))] };
      return UNKNOWN;
    }
    if (PATH_WRAP.test(callee) && args.length >= 1) {
      const inner = fold(ctx, args[0]!, scope, depth + 1, hops);
      if (inner.kind === 'own-path' || inner.kind === 'literal') return inner;
      return UNKNOWN;
    }
    if (callee === 'require.resolve' && args.length === 1) return fold(ctx, args[0]!, scope, depth + 1, hops);
    // A package-root finder fed the module's own directory —
    // `findPackageRoot(moduleDir)`, `findUp('package.json', { cwd: __dirname })`.
    if (!scope?.pathContext || !/(?:root|pkg|package|find-?up|project-?dir)/i.test(callee)) return UNKNOWN;
    const folded = args.map((a) => fold(ctx, a, scope, depth + 1, hops));
    if (args.length === 1 && folded[0]!.kind === 'own-path') return { kind: 'own-path', value: '.' };
    if (args.some((a) => /^\{\s*cwd\s*:/.test(a)) && args.every((a, i) => folded[i]!.kind === 'literal' || /^\{\s*cwd\s*:\s*([\s\S]+?)\s*\}$/.test(a))) {
      const cwd = /^\{\s*cwd\s*:\s*([\s\S]+?)\s*\}$/.exec(args.find((a) => /^\{\s*cwd\s*:/.test(a))!)?.[1];
      if (cwd && fold(ctx, cwd, scope, depth + 1, hops).kind === 'own-path') return { kind: 'own-path', value: '.' };
    }
    return UNKNOWN;
  }

  return UNKNOWN;
}

function foldTemplate(ctx: FileCtx, body: string, scope: FoldScope | undefined, depth: number, hops: number, open: string, close: string): Folded {
  const parts: Folded[] = [];
  let i = 0;
  let text = '';
  while (i < body.length) {
    if (open === '{' && (body.startsWith('{{', i) || body.startsWith('}}', i))) {
      text += body[i];
      i += 2;
      continue;
    }
    if (body.startsWith(open, i)) {
      parts.push({ kind: 'literal', values: [text] });
      text = '';
      // Find the matching close brace for this interpolation.
      let d = 0;
      let j = i + open.length - 1;
      for (; j < body.length; j++) {
        if (body[j] === '{') d++;
        else if (body[j] === '}') {
          d--;
          if (d === 0) break;
        }
      }
      if (j >= body.length) return UNKNOWN;
      parts.push(fold(ctx, body.slice(i + open.length, j).replace(/[!:][^}]*$/, open === '{' ? '' : '$&'), scope, depth + 1, hops));
      i = j + close.length;
      continue;
    }
    if (body[i] === '\\' && i + 1 < body.length) {
      text += body[i + 1];
      i += 2;
      continue;
    }
    text += body[i];
    i += 1;
  }
  parts.push({ kind: 'literal', values: [text] });
  return concat(parts);
}

function foldArray(ctx: FileCtx, e: string, scope: FoldScope | undefined, depth: number, hops: number): Folded {
  const mask = codeMask(e, ctx.lang);
  const args = splitArgs(e, mask, 0);
  if (!args) return UNKNOWN;
  const elements: Folded[] = [];
  let dynamic = false;
  for (const a of args.args) {
    if (a.startsWith('...') || a.startsWith('*')) {
      const spread = fold(ctx, a.replace(/^\.\.\.|^\*/, ''), scope, depth + 1, hops);
      if (spread.kind === 'array' && !spread.dynamic) elements.push(...spread.elements);
      else dynamic = true;
      continue;
    }
    elements.push(fold(ctx, a, scope, depth + 1, hops));
  }
  return { kind: 'array', elements, dynamic };
}

/** Merge two possible values of the same expression (a ternary's branches, several call sites). */
export function union(a: Folded, b: Folded): Folded {
  if (a.kind === 'array' && b.kind === 'array') {
    // Two argv arrays: constant only if both are; the shape is what matters, not the values.
    return { kind: 'array', elements: isConst(a) && isConst(b) ? a.elements : [UNKNOWN], dynamic: !(isConst(a) && isConst(b)) };
  }
  return unionScalar(a, b);
}

function unionScalar(a: Folded, b: Folded): Folded {
  if (a.kind === 'unknown' || b.kind === 'unknown') return UNKNOWN;
  if (a.kind === 'own-path' && b.kind === 'own-path') return a;
  if (a.kind === 'literal' && b.kind === 'literal') return { kind: 'literal', values: dedupe([...a.values, ...b.values]) };
  if (a.kind === 'exec-path' && b.kind === 'exec-path') return a;
  if (isConst(a) && isConst(b)) return { kind: 'literal', values: dedupe([describeFolded(a), describeFolded(b)]) };
  return UNKNOWN;
}

function concat(parts: Folded[]): Folded {
  if (!parts.length) return UNKNOWN;
  if (parts.some((p) => p.kind === 'unknown' || p.kind === 'array')) return UNKNOWN;
  const head = parts[0]!;
  const rest = parts.slice(1);
  if (head.kind === 'own-path' && rest.every((p) => p.kind === 'literal' && p.values.length === 1)) {
    return { kind: 'own-path', value: head.value + rest.map((p) => (p as { values: string[] }).values[0]!).join('') };
  }
  if (parts.every((p) => p.kind === 'literal')) {
    let acc = [''];
    for (const p of parts as { values: string[] }[]) {
      const next: string[] = [];
      for (const x of acc) for (const y of p.values) next.push(x + y);
      acc = dedupe(next);
      if (acc.length > MAX_VALUES) return UNKNOWN;
    }
    return { kind: 'literal', values: acc };
  }
  return UNKNOWN;
}

function dedupe(v: string[]): string[] {
  return [...new Set(v)].slice(0, MAX_VALUES);
}

function joinPath(...segs: string[]): string {
  const out: string[] = [];
  for (const s of segs) {
    for (const part of s.split(/[\\/]+/)) {
      if (!part || part === '.') continue;
      // A leading `..` climbs above the module's own directory and must survive:
      // `resolve(__dirname, "../../agent/host.mjs")` is not `agent/host.mjs`.
      if (part === '..' && out.length && out[out.length - 1] !== '..') out.pop();
      else out.push(part);
    }
  }
  return out.join('/') || '.';
}

/** Read a plain (non-template) string literal that spans the whole expression. */
function readStringLiteral(e: string, py: boolean): string | undefined {
  let s = e;
  if (py) {
    const pre = /^[rRbBuU]{1,2}(?=['"])/.exec(s);
    if (pre) s = s.slice(pre[0].length);
    for (const q of ['"""', "'''"]) {
      if (s.startsWith(q) && s.endsWith(q) && s.length >= 6) return s.slice(3, -3);
    }
  }
  const q = s[0];
  if ((q !== '"' && q !== "'") || s.length < 2 || s[s.length - 1] !== q) return undefined;
  const body = s.slice(1, -1);
  // The closing quote must be the only unescaped one.
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '\\') { i++; continue; }
    if (body[i] === q) return undefined;
  }
  return body.replace(/\\(.)/g, (_m, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
}

function stripParens(e: string): string {
  for (let k = 0; k < 4 && e.startsWith('(') && e.endsWith(')'); k++) {
    const mask = codeMask(e, 'js');
    if (matchBracket(e, mask, 0) !== e.length - 1) break;
    e = e.slice(1, -1).trim();
  }
  return e;
}

function argsOf(e: string, open: number): string[] | null {
  const mask = codeMask(e, 'js');
  const r = splitArgs(e, mask, open);
  if (!r || r.end !== e.length - 1) return null;
  return r.args;
}

/** `cond ? a : b` at top level → [a, b]. */
function splitTernary(e: string): [string, string] | null {
  const mask = codeMask(e, 'js');
  let depth = 0;
  let q = -1;
  for (let i = 0; i < e.length; i++) {
    if (mask[i] !== CODE) continue;
    const c = e[i]!;
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (depth === 0 && c === '?' && e[i + 1] !== '.' && e[i + 1] !== '?' && e[i - 1] !== '?') {
      q = i;
      break;
    }
  }
  if (q < 0) return null;
  let nest = 0;
  depth = 0;
  for (let i = q + 1; i < e.length; i++) {
    if (mask[i] !== CODE) continue;
    const c = e[i]!;
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (depth === 0 && c === '?' && e[i + 1] !== '.' && e[i + 1] !== '?' && e[i - 1] !== '?') nest++;
    else if (depth === 0 && c === ':') {
      if (nest === 0) return [e.slice(q + 1, i).trim(), e.slice(i + 1).trim()];
      nest--;
    }
  }
  return null;
}

function splitPyTernary(e: string): [string, string] | null {
  const ifs = splitTopLevel(e, ' if ');
  if (ifs.length !== 2) return null;
  const els = splitTopLevel(ifs[1]!, ' else ');
  if (els.length !== 2) return null;
  return [ifs[0]!, els[1]!];
}

/** Split at top-level binary `+` (never `++`, `+=`, or a unary plus). */
function splitPlus(e: string): string[] {
  const mask = codeMask(e, 'js');
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < e.length; i++) {
    if (mask[i] !== CODE) continue;
    const c = e[i]!;
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (depth === 0 && c === '+' && e[i + 1] !== '+' && e[i + 1] !== '=' && e[i - 1] !== '+') {
      const before = e.slice(from, i).trimEnd();
      if (!before || /[=(,?:!&|+\-*/%<>]$/.test(before)) continue; // unary
      out.push(e.slice(from, i).trim());
      from = i + 1;
    }
  }
  out.push(e.slice(from).trim());
  return out.filter((s) => s.length > 0);
}
