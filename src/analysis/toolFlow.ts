/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Best-effort, single-file tracking of TOOL INPUT — the arguments an MCP client
 * (and so a prompt-injected model) controls — from where a tool handler
 * receives them to where they are used.
 *
 * It marks a handler's parameters as tool input, then follows them through
 * local assignments, destructuring and direct calls to functions defined in
 * the same file, for a bounded number of rounds. It does NOT follow a function
 * passed as a value, a value stored on an object and read back elsewhere, or
 * anything across files. Its only job is to UPGRADE a finding when the flow is
 * visible; when it sees nothing, nothing is downgraded because of it.
 */

import type { FileCtx, FnInfo } from '../util/fileCtx.js';
import { splitArgs, splitTopLevel } from '../util/jsLex.js';

export interface ToolFlow {
  /** True when the expression, evaluated at offset `at`, visibly carries tool input. */
  carries(expr: string, at: number): boolean;
  /** Whether the file registers any tool handler at all. */
  hasHandlers: boolean;
}

const ROUNDS = 3;
const NONE: ToolFlow = { carries: () => false, hasHandlers: false };

const RE_REGISTER = /\.(?:registerTool|tool)\s*\(/g;
const RE_LOWLEVEL = /\.setRequestHandler\s*\(\s*CallToolRequestSchema\s*,/g;
const RE_PY_TOOL = /^[ \t]*@[\w.]*\btool\b(?:\([^)]*\))?\s*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:async\s+)?def\s+([A-Za-z_]\w*)/gm;

export function toolFlowOf(ctx: FileCtx): ToolFlow {
  const tainted = new Map<FnInfo, Set<string>>();
  const fns = ctx.functions();
  const mark = (fn: FnInfo, name: string): boolean => {
    if (!name) return false;
    let set = tainted.get(fn);
    if (!set) tainted.set(fn, (set = new Set()));
    if (set.has(name)) return false;
    set.add(name);
    return true;
  };
  const markParams = (fn: FnInfo): void => {
    for (const p of fn.params) {
      if (p.name) mark(fn, p.name);
      for (const local of p.keys?.values() ?? []) mark(fn, local);
    }
  };

  // 1. Handlers.
  if (ctx.lang === 'py') {
    let m: RegExpExecArray | null;
    RE_PY_TOOL.lastIndex = 0;
    while ((m = RE_PY_TOOL.exec(ctx.src))) {
      const fn = fns.find((f) => f.name === m![1] && f.headerStart >= m!.index);
      if (fn) {
        for (const p of fn.params) if (p.name && !/^(?:ctx|context)$/i.test(p.name)) mark(fn, p.name);
      }
    }
  } else {
    for (const re of [RE_REGISTER, RE_LOWLEVEL]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(ctx.src))) {
        if (!ctx.isCode(m.index)) continue;
        const open = m.index + m[0].lastIndexOf('(');
        const args = splitArgs(ctx.src, ctx.mask, open);
        if (!args || !args.args.length) continue;
        const last = args.args.length - 1;
        const handlerText = args.args[last]!;
        const handlerAt = args.starts[last]!;
        let fn: FnInfo | undefined;
        if (/^[A-Za-z_$][\w$]*$/.test(handlerText)) fn = fns.find((f) => f.name === handlerText);
        else fn = fns.find((f) => f.headerStart >= handlerAt && f.headerStart <= handlerAt + 12);
        if (fn) markParams(fn);
      }
    }
  }
  if (!tainted.size) return NONE;

  const byName = new Map<string, FnInfo[]>();
  for (const f of fns) if (f.name) byName.set(f.name, [...(byName.get(f.name) ?? []), f]);

  // 2. Propagate.
  for (let round = 0; round < ROUNDS; round++) {
    let changed = false;
    for (const fn of fns) {
      const set = tainted.get(fn);
      if (!set || !set.size) continue;
      const body = ctx.src.slice(fn.bodyStart, fn.bodyEnd);
      // a) local assignments and destructuring from a tainted expression
      const reAssign = /\b(?:const|let|var)\s+(\{[^}=]*\}|[A-Za-z_$][\w$]*)\s*=\s*/g;
      let a: RegExpExecArray | null;
      while ((a = reAssign.exec(body))) {
        const init = ctx.readInit(fn.bodyStart + a.index + a[0].length);
        if (!references(init, set)) continue;
        const target = a[1]!;
        if (target.startsWith('{')) {
          for (const entry of splitTopLevel(target.slice(1, -1), ',')) {
            const local = (splitTopLevel(entry, ':')[1] ?? entry).replace(/=.*$/, '').trim();
            if (/^[A-Za-z_$][\w$]*$/.test(local)) changed = mark(fn, local) || changed;
          }
        } else changed = mark(fn, target) || changed;
      }
      // b) direct calls to functions defined in this file. Walk THIS body for
      //    `name(` / `this.name(` and look the callee up — linear in the body,
      //    instead of searching the whole file for every function's call sites
      //    (which took seconds on a single-file bundle with 10k+ functions).
      const reCall = /(?<![\w$])(?:(?:this|self)\.)?([A-Za-z_$][\w$]*)\s*\(/g;
      let c: RegExpExecArray | null;
      while ((c = reCall.exec(body))) {
        const at = fn.bodyStart + c.index;
        if (!ctx.isCode(at)) continue;
        if (ctx.src[at - 1] === '.' && !/(?:this|self)\.$/.test(ctx.src.slice(at - 5, at))) continue;
        const callees = byName.get(c[1]!);
        if (!callees) continue;
        const open = fn.bodyStart + c.index + c[0].length - 1;
        const args = splitArgs(ctx.src, ctx.mask, open);
        if (!args) continue;
        for (const g of callees) {
          if (g === fn) continue;
          args.args.forEach((argText, i) => {
            const param = g.params[i];
            if (!param) return;
            if (param.keys && argText.startsWith('{')) {
              // `{ host }` / `{ host: x }` into a destructuring parameter.
              for (const entry of splitTopLevel(argText.slice(1, -1), ',')) {
                const [k, v] = splitTopLevel(entry, ':');
                const key = (k ?? '').trim();
                const value = (v ?? k ?? '').trim();
                const local = param.keys.get(key);
                if (local && references(value, set)) changed = mark(g, local) || changed;
              }
              return;
            }
            if (references(argText, set)) {
              if (param.name) changed = mark(g, param.name) || changed;
              for (const local of param.keys?.values() ?? []) changed = mark(g, local) || changed;
            }
          });
        }
      }
    }
    if (!changed) break;
  }

  return {
    hasHandlers: true,
    carries(expr: string, at: number): boolean {
      // Closures see their enclosing functions' bindings too.
      for (const fn of fns) {
        if (at < fn.bodyStart || at >= fn.bodyEnd) continue;
        const set = tainted.get(fn);
        if (set && references(expr, set)) return true;
      }
      return false;
    },
  };
}

/** Does `expr` mention any of `names` as a bare identifier (not a property name)? */
function references(expr: string, names: Set<string>): boolean {
  // Words inside string literals are text, not bindings. Template interpolations
  // (`${host}`) are code, so they are kept.
  const code = expr
    .replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, '""')
    .replace(/`(?:\\.|\$\{([^}]*)\}|[^`\\])*`/g, (t) => (t.match(/\$\{[^}]*\}/g) ?? []).join(' '));
  const re = /(?<![.\w$])([A-Za-z_$][\w$]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code))) if (names.has(m[1]!)) return true;
  return false;
}

export const NO_TOOL_FLOW = NONE;
