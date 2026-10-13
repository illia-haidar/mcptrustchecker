/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Which files of a package can the MCP SERVER actually reach?
 *
 * A published package is rarely only a server. It ships a CLI, a daemon, a
 * client for its own server, onboarding scripts. A process call in the daemon
 * says nothing about what a prompt-injected model can make the server do, yet
 * every file used to be reported as "the server's implementation".
 *
 * The algorithm is static and deterministic — nothing is executed:
 *
 *   1. SERVER ROOTS — files that build or serve an MCP server: register tools,
 *      construct an SDK server or server transport, or HANDLE `tools/call` in
 *      their own JSON-RPC loop (a client that SENDS `tools/call` is not a root).
 *   2. ENTRY POINTS — `bin`/`main`/`module`/`exports` in package.json, the
 *      console scripts of pyproject.toml / setup.cfg.
 *   3. IMPORT GRAPH — static and lazy `import`/`require`, re-exports, and
 *      dynamic loads whose path the constant folder can reduce to a file of the
 *      package itself. An edge is LAZY when the load sits inside a function or
 *      block — it only runs on one code path.
 *   4. MCP CLOSURE — for every entry that reaches a root, walk the shortest path
 *      to it; the server's code starts at the first lazily-loaded module on that
 *      path (a CLI's `mcp serve` branch), or at the entry itself when the whole
 *      path is static. The closure of those starting points is what the server
 *      can run. Files reachable only from other entries are NOT server code.
 *
 * When no entry reaches a root, or the package declares no entries, every file
 * is `unknown` and callers behave exactly as they did before this existed.
 */

import type { PackageLayout, SourceFile } from '../types.js';
import { fileCtxOf } from '../util/fileCtx.js';
import { fold, type Folded } from '../util/constFold.js';
import { braceDepths, splitArgs } from '../util/jsLex.js';

export type Reach = true | false | 'unknown';

export interface ReachInfo {
  /** `built` when at least one MCP entry was identified; otherwise everything is `unknown`. */
  status: 'built' | 'unknown';
  reach(path: string): Reach;
  /** Human label of the MCP entry that reaches `path` (when reach is true). */
  entryOf(path: string): string | undefined;
  /** Labels of the MCP entries found, e.g. "bin `srv` → dist/index.js". */
  mcpEntries: string[];
  serverRoots: string[];
  /**
   * True for a file a server entry loads STATICALLY on its way to the server
   * (a CLI's own module graph before the `mcp serve` branch). Its TOP-LEVEL code
   * runs in the server process at startup even when the file is not "server code".
   */
  loadsAtStartup(path: string): boolean;
}

interface Edge {
  to: string;
  lazy: boolean;
}

const JS_EXT = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'];
const UNKNOWN_REACH: ReachInfo = {
  status: 'unknown',
  reach: () => 'unknown',
  entryOf: () => undefined,
  mcpEntries: [],
  serverRoots: [],
  loadsAtStartup: () => false,
};

// --- server roots -------------------------------------------------------------

const JS_ROOT = [
  /\.registerTool\s*\(/,
  /\.tool\s*\(\s*['"`]/,
  /\bnew\s+McpServer\s*\(/,
  /\bnew\s+(?:Stdio|StreamableHTTP|SSE)ServerTransport\s*\(/,
  /\.setRequestHandler\s*\(\s*(?:\w+\.)?CallToolRequestSchema\b/,
  // A JSON-RPC loop that HANDLES tools/call (switch case, comparison, a handler table).
  /\bcase\s*['"`]tools\/call['"`]/,
  /[!=]==?\s*['"`]tools\/call['"`]/,
  /['"`]tools\/call['"`]\s*[!=]==?/,
  /\[[^\]\n]*['"`]tools\/call['"`][^\]\n]*\]\s*\.includes\s*\(/,
  /['"`]tools\/call['"`]\s*:\s*(?:async\s*)?(?:\(|function\b|[A-Za-z_$][\w$]*\s*=>)/,
];
const JS_SDK_SERVER = /@modelcontextprotocol\/sdk\/server/;
const PY_ROOT = [
  /^[ \t]*@[\w.]*\btool\b/m,
  /\bFastMCP\s*\(/,
  /^[ \t]*@[\w.]*\.call_tool\s*\(/m,
  /^[ \t]*@[\w.]*\.list_tools\s*\(/m,
  /\bstdio_server\s*\(/,
];

function isServerRoot(f: SourceFile): boolean {
  const src = f.content;
  if (/\.py$/i.test(f.path)) return PY_ROOT.some((re) => re.test(src));
  if (JS_ROOT.some((re) => re.test(src))) return true;
  return /\bnew\s+Server\s*\(/.test(src) && JS_SDK_SERVER.test(src);
}

// --- entry points --------------------------------------------------------------

interface Entry {
  label: string;
  file: string;
}

function entriesOf(layout: PackageLayout | undefined, has: (p: string) => string | undefined): Entry[] {
  const out: Entry[] = [];
  const add = (label: string, rel: unknown): void => {
    if (typeof rel !== 'string' || !rel) return;
    const file = has(normPath(rel));
    if (file && !out.some((e) => e.file === file && e.label === label)) out.push({ label, file });
  };
  const pkgText = layout?.files['package.json'];
  if (pkgText) {
    try {
      const pkg = JSON.parse(pkgText) as Record<string, unknown>;
      const name = typeof pkg.name === 'string' ? pkg.name : 'package';
      if (typeof pkg.bin === 'string') add(`bin \`${name.split('/').pop()}\``, pkg.bin);
      else if (pkg.bin && typeof pkg.bin === 'object') for (const [k, v] of Object.entries(pkg.bin)) add(`bin \`${k}\``, v);
      add('main', pkg.main);
      add('module', pkg.module);
      const walk = (v: unknown, key: string): void => {
        if (typeof v === 'string') add(`exports ${key}`, v);
        else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, k.startsWith('.') ? k : key);
      };
      walk(pkg.exports, '.');
    } catch {
      /* unparseable package.json — no JS entries */
    }
  }
  const scripts = pyScripts(layout);
  for (const [name, target] of scripts) {
    const mod = target.split(':')[0]!.trim().replace(/\./g, '/');
    const file = has(`${mod}.py`) ?? has(`${mod}/__init__.py`) ?? has(`src/${mod}.py`) ?? has(`src/${mod}/__init__.py`) ?? has(`${mod}/__main__.py`);
    if (file) out.push({ label: `script \`${name}\``, file });
  }
  return out;
}

/** console scripts from pyproject.toml ([project.scripts], [tool.poetry.scripts]) and setup.cfg. */
function pyScripts(layout: PackageLayout | undefined): [string, string][] {
  const out: [string, string][] = [];
  const toml = layout?.files['pyproject.toml'];
  if (toml) {
    const section = /^\[(?:project\.(?:scripts|gui-scripts)|tool\.poetry\.scripts)\]\s*$([\s\S]*?)(?=^\[|$(?![\s\S]))/gm;
    let s: RegExpExecArray | null;
    while ((s = section.exec(toml))) {
      for (const line of s[1]!.split('\n')) {
        const m = /^\s*["']?([\w.-]+)["']?\s*=\s*["']([\w.]+(?::[\w.]+)?)["']/.exec(line);
        if (m) out.push([m[1]!, m[2]!]);
      }
    }
  }
  const cfg = layout?.files['setup.cfg'];
  if (cfg) {
    const block = /^\s*console_scripts\s*=\s*\n((?:[ \t]+[^\n]*\n?)+)/m.exec(cfg);
    if (block) {
      for (const line of block[1]!.split('\n')) {
        const m = /^\s*([\w.-]+)\s*=\s*([\w.]+(?::[\w.]+)?)/.exec(line);
        if (m) out.push([m[1]!, m[2]!]);
      }
    }
  }
  return out;
}

// --- import graph --------------------------------------------------------------

// Tokens and the whitespace between them are disjoint classes, so this is linear;
// the old `[\w$*{}\s,]+?\s+from` overlapped and was quadratic on a run of spaces.
const RE_STATIC_FROM = /\b(?:import|export)\s+(?:type\s+)?(?:[\w$*{},]+(?:\s+[\w$*{},]+)*\s*from\s*)?(['"])([^'"\n]+)\1/g;
const RE_CALL_LOAD = /\b(require|import|__require)\s*\(\s*(['"`])([^'"`\n]+)\2\s*\)/g;
// A load whose argument is not a plain literal (a template with `${}` counts).
const RE_DYNAMIC_LOAD = /\b(require|import|__require)\s*\(\s*(?!['"][^'"\n]*['"]\s*\))(?=\S)(?!\))/g;
// Other ways code of the package gets loaded and run: a worker thread, a forked
// module. Their targets are part of what the server can run.
const RE_RUNS_FILE = /\bnew\s+Worker\s*\(|\bfork\s*\(/g;
// `require` handed on as a value, or other loaders we cannot follow: the graph
// may be missing edges, so nothing outside it can be called unreachable.
const RE_OPAQUE_LOADER = /\brequire\b(?!\s*(?:\(|\.resolve|\.cache|\.main|\.extensions|\s*===?|\s*!==?))|\bmodule\.constructor\._load\b|\bprocess\.mainModule\b/;

function jsEdges(f: SourceFile, resolve: (from: string, spec: string) => string | undefined, unresolved: Set<string>): Edge[] {
  const ctx = fileCtxOf(f);
  const src = f.content;
  const found: { at: number; spec: string; statement: boolean; folded?: boolean }[] = [];
  let m: RegExpExecArray | null;
  RE_STATIC_FROM.lastIndex = 0;
  while ((m = RE_STATIC_FROM.exec(src))) if (ctx.isCode(m.index)) found.push({ at: m.index, spec: m[2]!, statement: true });
  RE_CALL_LOAD.lastIndex = 0;
  while ((m = RE_CALL_LOAD.exec(src))) {
    if (!ctx.isCode(m.index)) continue;
    if (m[2] === '`' && m[3]!.includes('${')) continue;
    found.push({ at: m.index, spec: m[3]!, statement: false });
  }
  // `const req = createRequire(import.meta.url)` — calls to `req(...)` are requires.
  const loaders = new Set<string>();
  for (const c of src.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:module\.|\w+\.)?createRequire\s*\(/g)) if (ctx.isCode(c.index!)) loaders.add(c[1]!);
  for (const name of loaders) {
    for (const c of src.matchAll(new RegExp(String.raw`(?<![.\w$])${name.replace(/\$/g, '\\$')}\s*\(`, 'g'))) {
      if (!ctx.isCode(c.index!)) continue;
      const args = splitArgs(src, ctx.mask, c.index! + c[0].length - 1);
      if (!args || args.args.length !== 1) continue;
      const v = fold(ctx, args.args[0]!, { at: c.index!, pathContext: true });
      const specs = specsOf(v);
      for (const spec of specs) found.push({ at: c.index!, spec, statement: false, folded: true });
      if (!specs.length) unresolved.add(f.path);
    }
  }
  for (const c of src.matchAll(RE_RUNS_FILE)) {
    if (!ctx.isCode(c.index!)) continue;
    const args = splitArgs(src, ctx.mask, c.index! + c[0].length - 1);
    if (!args || !args.args.length) continue;
    const v = fold(ctx, args.args[0]!, { at: c.index!, pathContext: true });
    const specs = specsOf(v).filter((x) => x.startsWith('.') || x.startsWith('/') || x.startsWith('<own>/'));
    for (const spec of specs) found.push({ at: c.index!, spec, statement: false, folded: true });
    if (!specs.length && /\bWorker\b/.test(c[0])) unresolved.add(f.path); // a worker running a file we cannot name
  }
  {
    const opaque = RE_OPAQUE_LOADER.exec(src);
    if (opaque && ctx.isCode(opaque.index) && !/\b(?:typeof\s+require|require\s*&&)/.test(src.slice(Math.max(0, opaque.index - 8), opaque.index + 12))) unresolved.add(f.path);
  }

  RE_DYNAMIC_LOAD.lastIndex = 0;
  while ((m = RE_DYNAMIC_LOAD.exec(src))) {
    if (!ctx.isCode(m.index)) continue;
    // The argument by bracket matching, not by regex: it routinely nests calls
    // (`import(pathToFileURL(path.resolve(__dirname, "../x.mjs")).href)`).
    const open = src.indexOf('(', m.index);
    const args = splitArgs(src, ctx.mask, open);
    if (!args || args.args.length !== 1) continue;
    if (/^`[^`$]*`$/.test(args.args[0]!)) continue; // a literal template, already an edge
    const v = fold(ctx, args.args[0]!, { at: m.index, pathContext: true });
    const specs = specsOf(v);
    for (const spec of specs) found.push({ at: m.index, spec, statement: false, folded: true });
    // A load whose target cannot be reduced could pull in ANY file of the package.
    if (!specs.length) unresolved.add(f.path);
  }
  const depths = braceDepths(src, ctx.mask, found.map((x) => x.at));
  const edges: Edge[] = [];
  for (const x of found) {
    const to = resolve(f.path, x.spec);
    if (to === f.path) continue;
    if (!to) {
      // A spec that should be a file of this package but did not resolve leaves
      // the graph incomplete: an import map, a path alias, a file we did not read.
      if (internalSpec(x.spec) && !/\.(?:json|node|wasm|css|scss|html?|svg|png|jpe?g|gif|txt|md|ya?ml|toml|wav|mp3)$/i.test(x.spec)) unresolved.add(f.path);
      continue;
    }
    edges.push({ to, lazy: !x.statement && (depths.get(x.at) ?? 0) > 0 });
  }
  return edges;
}

function pyEdges(f: SourceFile, resolveModule: (from: string, dotted: string, level: number) => string | undefined, unresolved: Set<string>): Edge[] {
  const edges: Edge[] = [];
  const src = f.content;
  const re = /^([ \t]*)(?:from\s+(\.*)([\w.]*)\s+import\s+(\([^)]*\)|[^\n#]+)|import\s+([^\n#]+))/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    const lazy = m[1]!.length > 0;
    if (m[5] !== undefined) {
      for (const part of m[5].split(',')) {
        const mod = part.trim().split(/\s+as\s+/)[0]!.trim();
        const to = resolveModule(f.path, mod, 0);
        if (to && to !== f.path) edges.push({ to, lazy });
      }
      continue;
    }
    const level = m[2]!.length;
    const base = m[3]!;
    const to = resolveModule(f.path, base, level);
    if (to && to !== f.path) edges.push({ to, lazy });
    else if (level > 0 && !to) unresolved.add(f.path);
    // `from . import x, y` / `from .pkg import (sub,\n other)` — each name may itself be a module.
    for (const part of m[4]!.replace(/[()\n\\]/g, ' ').split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0]!.trim();
      if (!/^\w+$/.test(name)) continue;
      const sub = resolveModule(f.path, base ? `${base}.${name}` : name, level);
      if (sub && sub !== f.path) edges.push({ to: sub, lazy });
    }
  }
  // importlib.import_module("pkg.x") / __import__("pkg.x"): followed when literal, opaque otherwise.
  for (const c of src.matchAll(/\b(?:importlib\.import_module|import_module|__import__)\s*\(\s*([^,)]+)/g)) {
    const lit = /^['"]([\w.]+)['"]$/.exec(c[1]!.trim());
    if (!lit) {
      unresolved.add(f.path);
      continue;
    }
    const rel = /^\./.test(lit[1]!);
    const to = resolveModule(f.path, lit[1]!.replace(/^\.+/, ''), rel ? (/^\.+/.exec(lit[1]!)![0].length) : 0);
    if (to && to !== f.path) edges.push({ to, lazy: true });
  }
  return edges;
}

/** Every module specifier a folded load can name (a ternary of paths names several). */
function specsOf(v: Folded): string[] {
  if (v.kind === 'literal') return v.values;
  if (v.kind === 'own-path') return [`<own>/${v.value}`];
  return [];
}

/** A specifier that names a file of THIS package (or might), as opposed to a dependency. */
function internalSpec(spec: string): boolean {
  return /^(?:\.|\/|#|<own>\/|@\/|~\/|src\/|lib\/|dist\/|app\/)/.test(spec);
}

// --- public entry point -----------------------------------------------------

export function buildReachability(files: SourceFile[], layout?: PackageLayout): ReachInfo {
  const byPath = new Map<string, SourceFile>();
  for (const f of files) if (f && typeof f.path === 'string' && typeof f.content === 'string') byPath.set(normPath(f.path), f);
  if (!byPath.size) return UNKNOWN_REACH;

  const has = (p: string): string | undefined => {
    const n = normPath(p);
    if (/[\\/]$/.test(p)) {
      for (const ext of JS_EXT) if (byPath.has(`${n}/index${ext}`)) return `${n}/index${ext}`;
      return undefined; // './tools/' is the directory, never the sibling tools.js
    }
    if (byPath.has(n)) return n;
    for (const ext of JS_EXT) if (byPath.has(n + ext)) return n + ext;
    for (const ext of JS_EXT) if (byPath.has(`${n}/index${ext}`)) return `${n}/index${ext}`;
    // TypeScript sources import './x.js' that is really './x.ts'.
    const swapped = n.replace(/\.(m|c)?js$/, '.$1ts');
    if (swapped !== n && byPath.has(swapped)) return swapped;
    return undefined;
  };

  let pkgName: string | undefined;
  let pkgJson: Record<string, unknown> = {};
  try {
    const pj = layout?.files['package.json'];
    if (pj) {
      pkgJson = JSON.parse(pj) as Record<string, unknown>;
      pkgName = typeof pkgJson.name === 'string' ? pkgJson.name : undefined;
    }
  } catch {
    /* ignore */
  }
  /** Resolve a key through a package.json map (`imports` or `exports`), conditions and one `*`. */
  const viaMap = (map: unknown, key: string): string | undefined => {
    if (!map || typeof map !== 'object') return typeof map === 'string' && key === '.' ? map : undefined;
    const pick = (v: unknown): string | undefined => {
      if (typeof v === 'string') return v;
      if (v && typeof v === 'object') for (const c of ['node', 'import', 'require', 'default']) { const r = pick((v as Record<string, unknown>)[c]); if (r) return r; }
      return undefined;
    };
    const m = map as Record<string, unknown>;
    if (key in m) return pick(m[key]);
    for (const [k, v] of Object.entries(m)) {
      const star = k.indexOf('*');
      if (star < 0) continue;
      const pre = k.slice(0, star);
      const post = k.slice(star + 1);
      if (key.startsWith(pre) && key.endsWith(post)) {
        const target = pick(v);
        if (target) return target.replace('*', key.slice(pre.length, key.length - post.length));
      }
    }
    return undefined;
  };

  const resolveJs = (from: string, spec: string): string | undefined => {
    if (spec.startsWith('<own>/')) {
      const rel = spec.slice(6);
      return has(joinRel(dirOf(from), rel)) ?? has(rel);
    }
    if (spec.startsWith('.') || spec.startsWith('/')) return has(joinRel(dirOf(from), spec) + (/[\\/]$/.test(spec) ? '/' : ''));
    if (spec.startsWith('#')) {
      const t = viaMap(pkgJson.imports, spec);
      return t && !t.startsWith('#') ? (t.startsWith('.') ? has(t) : undefined) : undefined;
    }
    if (pkgName && (spec === pkgName || spec.startsWith(`${pkgName}/`))) {
      const sub = spec === pkgName ? '.' : `./${spec.slice(pkgName.length + 1)}`;
      const t = viaMap(pkgJson.exports, sub);
      return (t ? has(t) : undefined) ?? has(spec.slice(pkgName.length + 1) || (typeof pkgJson.main === 'string' ? pkgJson.main : 'index'));
    }
    return undefined; // a dependency, not this package
  };
  const resolvePy = (from: string, dotted: string, level: number): string | undefined => {
    const parts = dotted ? dotted.split('.') : [];
    let base: string;
    if (level > 0) {
      let dir = dirOf(from);
      for (let i = 1; i < level; i++) dir = dirOf(dir);
      base = joinRel(dir, parts.join('/'));
    } else {
      base = parts.join('/');
    }
    if (!base) return undefined;
    return byPath.has(`${base}.py`) ? `${base}.py` : byPath.has(`${base}/__init__.py`) ? `${base}/__init__.py` : byPath.has(`src/${base}.py`) ? `src/${base}.py` : byPath.has(`src/${base}/__init__.py`) ? `src/${base}/__init__.py` : undefined;
  };

  const graph = new Map<string, Edge[]>();
  const unresolved = new Set<string>();
  for (const [p, f] of byPath) graph.set(p, /\.py$/i.test(p) ? pyEdges(f, resolvePy, unresolved) : jsEdges(f, resolveJs, unresolved));

  const roots = new Set<string>();
  for (const [p, f] of byPath) if (isServerRoot(f)) roots.add(p);
  const entries = entriesOf(layout, has);
  if (!roots.size || !entries.length) return { ...UNKNOWN_REACH, serverRoots: [...roots] };

  const closure = (start: string): Set<string> => {
    const seen = new Set<string>([start]);
    const queue = [start];
    while (queue.length) {
      const cur = queue.shift()!;
      for (const e of graph.get(cur) ?? []) if (!seen.has(e.to)) { seen.add(e.to); queue.push(e.to); }
    }
    return seen;
  };

  /** Shortest path start → any root, as the list of edges taken. */
  const pathToRoot = (start: string): { node: string; lazy: boolean }[] | null => {
    if (roots.has(start)) return [];
    const parent = new Map<string, { from: string; lazy: boolean }>();
    const seen = new Set([start]);
    const queue = [start];
    while (queue.length) {
      const cur = queue.shift()!;
      // Deterministic order: edges as found, already in source order.
      for (const e of graph.get(cur) ?? []) {
        if (seen.has(e.to)) continue;
        seen.add(e.to);
        parent.set(e.to, { from: cur, lazy: e.lazy });
        if (roots.has(e.to)) {
          const path: { node: string; lazy: boolean }[] = [];
          let n = e.to;
          while (n !== start) {
            const p = parent.get(n)!;
            path.unshift({ node: n, lazy: p.lazy });
            n = p.from;
          }
          return path;
        }
        queue.push(e.to);
      }
    }
    return null;
  };

  const mcpClosure = new Map<string, string>(); // file → entry label
  const startup = new Set<string>();
  const otherReach = new Set<string>();
  const labels: string[] = [];
  const sortedEntries = [...entries].sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
  for (const entry of sortedEntries) {
    const all = closure(entry.file);
    const path = pathToRoot(entry.file);
    if (!path) {
      for (const p of all) otherReach.add(p);
      continue;
    }
    // The server's own code starts at the LAST lazy load on the way to the root:
    // `bin → (lazy) cli/commands/mcp.js → (lazy, "serve") runtime/stdio.js` starts at
    // stdio.js, not at the `mcp` dispatcher that also holds onboarding and setup.
    let lastLazyAt = -1;
    path.forEach((s, i) => { if (s.lazy) lastLazyAt = i; });
    const start = lastLazyAt >= 0 ? path[lastLazyAt]!.node : entry.file;
    // Everything on the way there — the entry and every module loaded before that
    // last hop, with their STATIC imports — runs in the server process at startup.
    if (lastLazyAt >= 0) {
      const heads = [entry.file, ...path.slice(0, lastLazyAt).map((s) => s.node)];
      const seenS = new Set(heads);
      const queue = [...heads];
      while (queue.length) {
        const cur = queue.shift()!;
        startup.add(cur);
        for (const e of graph.get(cur) ?? []) if (!e.lazy && !seenS.has(e.to)) { seenS.add(e.to); queue.push(e.to); }
      }
    }
    const label = lastLazyAt >= 0 ? `${entry.label} → ${start}` : `${entry.label} (${entry.file})`;
    labels.push(label);
    for (const p of closure(start)) if (!mcpClosure.has(p)) mcpClosure.set(p, label);
    for (const p of all) otherReach.add(p);
  }
  if (!mcpClosure.size) return { ...UNKNOWN_REACH, serverRoots: [...roots] };

  // The server's import graph is COMPLETE when none of its files performs a
  // dynamic load we could not reduce. Only then is a file that no entry loads
  // (a launcher another tool spawns, a stray script) provably not server code;
  // otherwise such a file stays `unknown`.
  const complete = ![...mcpClosure.keys()].some((p) => unresolved.has(p));

  return {
    status: 'built',
    reach(path: string): Reach {
      const n = normPath(path);
      if (mcpClosure.has(n)) return true;
      // With an unresolved load inside the server's own graph, ANY file could be
      // what it loads — even one another entry also imports.
      if (!complete) return 'unknown';
      return otherReach.has(n) || byPath.has(n) ? false : 'unknown';
    },
    entryOf: (path: string) => mcpClosure.get(normPath(path)),
    mcpEntries: labels,
    serverRoots: [...roots].sort(),
    loadsAtStartup: (path: string) => startup.has(normPath(path)),
  };
}

// --- paths -----------------------------------------------------------------------

function normPath(p: string): string {
  const out: string[] = [];
  for (const seg of String(p).replace(/\\/g, '/').split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return out.join('/');
}

function dirOf(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

function joinRel(dir: string, rel: string): string {
  return normPath(dir ? `${dir}/${rel}` : rel);
}
