/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The Python modules of one package, for the static tool reader: which of the
 * package's own files a `from .tools import search_web` or a
 * `from staan_mcp.contract import WEB_SEARCH_DESCRIPTION` loads, and what the
 * imported name is there — a function the file defines, a constant, or a name
 * it re-exports from a third module.
 *
 * Nothing is executed and nothing outside the scanned files is looked up: a
 * module that is not one of them (the standard library, a dependency) is simply
 * not resolved. Bounded for hostile packages: a re-export chain is followed a
 * few hops and never twice through the same file, every lookup is memoised,
 * and the files indexed are the ones the extractor itself reads.
 */

import type { SourceFile } from '../types.js';
import { type FileCtx, type FnInfo, fileCtxOf } from '../util/fileCtx.js';

/** One `from <module> import <name> [as <local>]` binding. */
export interface PyImport {
  /** The module as written: leading dots for a relative import, then the dotted path (`..tools`, `pkg.contract`). */
  module: string;
  /** The name in that module (`search_web` in `from .tools import search_web as web`). */
  name: string;
  /** Offset of the `from` keyword. */
  at: number;
}

/** What an imported name is in the package file that defines it. */
export type PyRef =
  | { kind: 'fn'; file: SourceFile; fn: FnInfo; name: string }
  | { kind: 'const'; file: SourceFile; name: string };

/** Re-exports (`from .search import search_web` in a package's `__init__.py`) followed at most this many times. */
const MAX_HOPS = 4;
/** A parenthesized import list longer than this is not read. */
const MAX_IMPORT_LIST = 20_000;
/** Characters of import lists read per file, in all. */
const MAX_IMPORT_TEXT = 1_000_000;

const importsMemo = new WeakMap<FileCtx, Map<string, PyImport | null>>();

/**
 * The `from X import …` bindings of a Python file, by local name — parenthesized
 * multi-line lists, `as` aliases and line continuations included. A local name
 * bound by two different imports maps to null: which one is live is not known.
 */
export function pyImports(ctx: FileCtx): Map<string, PyImport | null> {
  const hit = importsMemo.get(ctx);
  if (hit) return hit;
  const out = new Map<string, PyImport | null>();
  const { src } = ctx;
  let read = 0;
  for (const m of src.matchAll(/^[ \t]*from[ \t]+(\.{0,8}[\w.]{0,200})[ \t]+import[ \t]*/gm)) {
    const at = m.index! + m[0].indexOf('from');
    if (!ctx.isCode(at) || !m[1]) continue;
    if (read > MAX_IMPORT_TEXT) break;
    let from = m.index! + m[0].length;
    let to: number;
    if (src[from] === '(') {
      const close = ctx.closeOf(from);
      if (close < 0 || close - from > MAX_IMPORT_LIST) continue;
      from += 1;
      to = close;
    } else {
      // The rest of the logical line: a backslash before the newline continues it.
      to = from;
      for (let n = 0; to < src.length && n < 2000; to++, n++) {
        if (src[to] === '\n' && src[to - 1] !== '\\') break;
      }
    }
    // Code characters only: a `# comment` inside a parenthesized list is not a name.
    let list = '';
    read += to - from;
    for (let i = from; i < to; i++) list += ctx.isCode(i) ? src[i] : ' ';
    for (const part of list.replace(/\\\n/g, ' ').split(',')) {
      const b = /^\s*([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?\s*$/.exec(part);
      if (!b) continue;
      const local = b[2] ?? b[1]!;
      const imp: PyImport = { module: m[1], name: b[1]!, at };
      const prev = out.get(local);
      if (prev === undefined) out.set(local, imp);
      else if (prev && (prev.module !== imp.module || prev.name !== imp.name)) out.set(local, null);
    }
  }
  importsMemo.set(ctx, out);
  return out;
}

/** Does this function sit in a class body (a method, or a `@staticmethod` without `self`)? */
export function inClassBody(ctx: FileCtx, fn: FnInfo): boolean {
  const { src } = ctx;
  const lineStart = src.lastIndexOf('\n', fn.headerStart - 1) + 1;
  const indent = /^[ \t]*/.exec(src.slice(lineStart, lineStart + 200))![0].length;
  if (indent === 0) return false;
  // The nearest code line above it that is indented less opens its block.
  let end = lineStart - 1;
  for (let steps = 0; end > 0 && steps < 5000; steps++) {
    const start = src.lastIndexOf('\n', end - 1) + 1;
    const line = src.slice(start, Math.min(end, start + 400));
    const ind = /^[ \t]*/.exec(line)![0].length;
    if (line.trim() && ctx.isCode(start + ind) && src[start + ind] !== '@' && ind < indent) return /^class\b/.test(line.slice(ind));
    end = start - 1;
  }
  return false;
}

/** The module-level functions of a file named `name` (a nested or class-body `def` is not importable). */
export function moduleFunctions(ctx: FileCtx, name: string): FnInfo[] {
  return ctx.functions().filter((f) => f.name === name && f.kind !== 'method' && ctx.enclosingFn(f.headerStart) === null && !inClassBody(ctx, f));
}

/** The package's own Python files, and the resolution of the imports between them. */
export class PyPackage {
  private readonly byPath = new Map<string, SourceFile>();
  /** Files by their last two path segments (`tools.py`, `tools/__init__.py`): absolute imports look up a handful, not all. */
  private readonly byTail = new Map<string, SourceFile[]>();
  private readonly resolveMemo = new Map<string, SourceFile | null>();
  private readonly refMemo = new Map<string, PyRef | null>();

  constructor(files: SourceFile[]) {
    for (const f of files) {
      if (!/\.py$/i.test(f.path)) continue;
      this.byPath.set(f.path, f);
      const segs = f.path.split('/');
      const tail = segs[segs.length - 1] === '__init__.py' && segs.length > 1 ? segs.slice(-2).join('/') : segs[segs.length - 1]!;
      const list = this.byTail.get(tail);
      if (list) list.push(f);
      else this.byTail.set(tail, [f]);
    }
  }

  /** Is this file one of the package's (so a reader may follow imports out of it)? */
  has(path: string): boolean {
    return this.byPath.has(path);
  }

  /** The package file a `from <module> import …` in `fromPath` loads, or undefined. */
  resolve(fromPath: string, module: string): SourceFile | undefined {
    const key = `${fromPath}\u0000${module}`;
    const hit = this.resolveMemo.get(key);
    if (hit !== undefined) return hit ?? undefined;
    const v = this.resolveUncached(fromPath, module) ?? null;
    this.resolveMemo.set(key, v);
    return v ?? undefined;
  }

  private resolveUncached(fromPath: string, module: string): SourceFile | undefined {
    const dots = /^\.*/.exec(module)![0].length;
    const rest = module.slice(dots);
    if (rest && !/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/.test(rest)) return undefined;
    const sub = rest.replace(/\./g, '/');
    if (dots > 0) {
      // Relative: the importing file's package, then one level up per extra dot.
      const dir = fromPath.split('/').slice(0, -1);
      if (dots - 1 > dir.length) return undefined;
      const base = dir.slice(0, dir.length - (dots - 1)).join('/');
      const at = (p: string): string => (base ? `${base}/${p}` : p);
      if (!sub) return this.byPath.get(at('__init__.py'));
      return this.byPath.get(at(`${sub}.py`)) ?? this.byPath.get(at(`${sub}/__init__.py`));
    }
    // Absolute: a file at `<root>/pkg/x.py` (or `pkg/x/__init__.py`) under a root
    // the importing file also lives under — `src/` for a src-layout package. A
    // vendored copy of the same module elsewhere in the artifact is not it.
    let best: SourceFile | undefined;
    let bestRoot = -1;
    const all: SourceFile[] = [];
    for (const suffix of [`${sub}.py`, `${sub}/__init__.py`]) {
      const segs = suffix.split('/');
      const tail = segs[segs.length - 1] === '__init__.py' ? segs.slice(-2).join('/') : segs[segs.length - 1]!;
      for (const f of this.byTail.get(tail) ?? []) {
        if (f.path !== suffix && !f.path.endsWith(`/${suffix}`)) continue;
        all.push(f);
        const root = f.path.slice(0, f.path.length - suffix.length);
        if (fromPath.startsWith(root) && root.length > bestRoot) {
          best = f;
          bestRoot = root.length;
        }
      }
      if (best) return best;
    }
    return all.length === 1 ? all[0] : undefined;
  }

  /**
   * What `name`, imported in `fromPath` by `imp`, is in the file that defines
   * it: a module-level function (followed through re-exports), or a candidate
   * constant (the caller evaluates it, one hop only). Undefined when the module
   * is not one of the package's files, or the name is ambiguous there.
   */
  refOf(fromPath: string, imp: PyImport): PyRef | undefined {
    return this.follow(fromPath, imp, 0, new Set());
  }

  private follow(fromPath: string, imp: PyImport, hops: number, seen: Set<string>): PyRef | undefined {
    const key = `${fromPath}\u0000${imp.module}\u0000${imp.name}`;
    const hit = this.refMemo.get(key);
    if (hit !== undefined) return hit ?? undefined;
    if (seen.has(key) || hops > MAX_HOPS) return undefined;
    seen.add(key);
    const v = this.followUncached(fromPath, imp, hops, seen) ?? null;
    this.refMemo.set(key, v);
    return v ?? undefined;
  }

  private followUncached(fromPath: string, imp: PyImport, hops: number, seen: Set<string>): PyRef | undefined {
    const file = this.resolve(fromPath, imp.module);
    if (!file) return undefined;
    const ctx = fileCtxOf(file);
    const defs = moduleFunctions(ctx, imp.name);
    if (defs.length === 1) return { kind: 'fn', file, fn: defs[0]!, name: imp.name };
    if (defs.length > 1) return undefined;
    const again = pyImports(ctx).get(imp.name);
    if (again) return this.follow(file.path, again, hops + 1, seen);
    if (again === null) return undefined;
    return { kind: 'const', file, name: imp.name };
  }
}
