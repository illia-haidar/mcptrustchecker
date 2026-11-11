/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Process-execution call sites and their SHAPE (MTC-SRC-002).
 *
 * The rule used to fire on the first `child_process` token in a file — almost
 * always the import line — and grade every file the same: "high, command
 * injection / RCE". `execFile("tailscale", ["status", "--json"])` and
 * `exec("git log " + req.params.ref)` are not the same thing, and the report
 * has to say which one it saw. This module finds each real call and classifies
 * it by what an attacker would need to control to abuse it:
 *
 *   shell-dynamic              a shell runs a command line built at runtime
 *   dynamic-program            no shell, but the program itself is chosen at runtime
 *   fixed-program-dynamic-args a fixed program, an argv array with runtime elements
 *   shell-fixed                a shell runs a command line that is entirely literal
 *   fixed-program-fixed-args   a fixed program with fixed arguments
 *
 * The first two are code execution. The rest spawn a process whose identity is
 * fixed in the code — a capability worth recording, not a remote-code-execution
 * primitive.
 */

import type { FileCtx } from '../util/fileCtx.js';
import { type Folded, describeFolded, fold, isConst, union } from '../util/constFold.js';
import { type ArgList, splitArgs } from '../util/jsLex.js';
import type { ToolFlow } from './toolFlow.js';

export type CallShape =
  | 'shell-dynamic'
  | 'dynamic-program'
  | 'fixed-program-dynamic-args'
  | 'shell-fixed'
  | 'fixed-program-fixed-args';

/** Higher = more dangerous; used to pick a file's worst call and to order findings. */
export const SHAPE_RANK: Record<CallShape, number> = {
  'shell-dynamic': 5,
  'dynamic-program': 4,
  'fixed-program-dynamic-args': 3,
  'shell-fixed': 2,
  'fixed-program-fixed-args': 1,
};

export interface ProcessCall {
  index: number;
  line: number;
  /** The API called: `execFile`, `spawn`, `subprocess.run`, `os.system`… */
  method: string;
  shape: CallShape;
  /** Human label of the program (or command line) the call runs. */
  program: string;
  /** Normalized call text, for evidence and the finding fingerprint. */
  snippet: string;
  /**
   * Tool input visibly reaches the call (best-effort, same-file): an argv
   * element; for a call that runs code chosen at runtime, the program or the
   * options too (1.18: not a result callback; not over 4 KB of program and
   * options). Always false for a call recorded without its arguments (a
   * function handed on as a value, an API chosen at runtime), as in 1.17.
   */
  toolInput: boolean;
  /** The `shell` option is an explicit key set at runtime (`shell: process.platform === "win32"`). */
  shellAtRuntime?: boolean;
  /**
   * The call keeps the 1.17 words whatever else holds (1.18): its program is
   * not written as a plain name, a member of one or an element of one (`bin`,
   * `this.bin`, `process.env.TOOL`, `argv[0]`) — a literal, a call, an operator,
   * a cast or a comment may hide a program the scanner did not read; or its
   * arguments hold a shell or eval flag as a literal (`-c`, `/c`, `-e`, …: a
   * shell or an interpreter given a command line); or its options ask for a
   * shell or name one (`shell: true`, `shell: isWin`, a `shell` key next to a
   * spread); or, in Python, the program is given by keyword (`args=`,
   * `executable=`).
   */
  keepWords?: boolean;
  /**
   * The shape the call ranks as when a file's worst call is picked, when that
   * differs from `shape`: a call relabelled `shell-dynamic` only by the words
   * (same profile) ranks as the `dynamic-program` 1.17 read, so the finding's
   * evidence and fingerprint stay those of 1.17.
   */
  rankAs?: CallShape;
}

/** The rank of a call when a file's worst one is picked. */
export function callRank(c: ProcessCall): number {
  return SHAPE_RANK[c.rankAs ?? c.shape];
}

/**
 * Does METHOD run a program with an argv array and no shell of its own (1.18)?
 * Not a shell API (`exec`, `os.system`, …), not one string split into a command
 * (`execaCommand`), and not an API the scanner cannot name: one chosen at
 * runtime (`cp[name]`, `getattr(subprocess, name)`) or a module loaded through
 * a binding it cannot read.
 */
export function runsArgv(method: string): boolean {
  if (ARGV_METHODS.has(method)) return true;
  const [mod, fn = ''] = method.split('.');
  return mod === 'subprocess' ? PY_SUBPROCESS.has(fn) && !PY_SHELL.has(fn) : method === 'asyncio.create_subprocess_exec';
}

export interface ProcessScan {
  /** The file imports/requires a process-execution module. */
  importsModule: boolean;
  /** Offset of that import, when there is one. */
  importIndex: number;
  calls: ProcessCall[];
}

const JS_METHODS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
/** execa's string-command API: no shell, but the whole command line is one string. */
const STRING_COMMAND_METHODS = new Set(['execaCommand', 'execaCommandSync']);
/** Third-party process libraries and what each export does. */
const LIB_EXPORTS: Record<string, Record<string, string>> = {
  'cross-spawn': { default: 'spawn', sync: 'spawnSync' },
  execa: { default: 'execFile', execa: 'execFile', execaSync: 'execFileSync', execaNode: 'fork', execaCommand: 'execaCommand', execaCommandSync: 'execaCommandSync' },
};
const JS_SHELL_METHODS = new Set(['exec', 'execSync']);
/** Process APIs that take a program and an argv array. */
const ARGV_METHODS = new Set(['execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
const CP_SPEC = String.raw`['"](?:node:)?child_process['"]`;

/** Programs that are themselves shells, and the flag that hands them a command line. */
const BIN = String.raw`(?:.*[\\/])?`; // any directory prefix: /bin/, /usr/local/bin/, C:\\Windows\\…
const SHELL_PROGRAMS = new RegExp(String.raw`^${BIN}(?:sh|bash|zsh|dash|ksh|mksh|fish|csh|tcsh|ash|busybox|cmd|powershell|pwsh)(?:\.exe)?$`, 'i');
const SHELL_FLAGS = /^(?:-c|-lc|-ic|-ec|-xc|\/c|\/C|\/k|\/K|-Command|-command|-c\s.*|-EncodedCommand|-enc|-e)$/;
/** Interpreters: a fixed interpreter running runtime CODE or a runtime SCRIPT is code execution. */
const INTERPRETERS = new RegExp(String.raw`^(?:${BIN}(?:node|nodejs|deno|bun|tsx|ts-node|python[\d.]*|py|pypy[\d.]*|ruby|perl|php|lua|luajit|Rscript|osascript|tclsh|wscript|cscript|java|groovy|julia)(?:\.exe)?|<node>)$`, 'i');
const EVAL_FLAGS = /^(?:-e|--eval|-p|--print|-c|-r|-E|-x|-m|--exec|eval|-Command|-command|-script|--require)$/;
/** Programs that only run ANOTHER program — look through them to the real one. */
const WRAPPERS = new RegExp(String.raw`^${BIN}(?:env|sudo|doas|nohup|nice|ionice|timeout|gtimeout|time|stdbuf|xargs|exec|setsid|caffeinate|chrt|taskset|unbuffer|runuser|wsl|start|call|cmd-wrapper)(?:\.exe)?$`, 'i');
/** Package runners: the first non-flag argument names a package that gets downloaded and run. */
const PKG_RUNNERS = new RegExp(String.raw`^${BIN}(?:npx|pnpx|bunx|uvx|pipx)(?:\.cmd|\.exe)?$`, 'i');
/** Package managers: a runtime package name after these subcommands is code execution (install scripts, `exec`). */
const PKG_MANAGERS = new RegExp(String.raw`^${BIN}(?:npm|pnpm|yarn|bun|pip[\d.]*|uv|gem|cargo|go|deno|composer)(?:\.cmd|\.exe)?$`, 'i');
const PKG_RUN_SUBCOMMANDS = /^(?:exec|x|dlx|run|run-script|install|i|add|start|create|init|get|tool)$/;

export function scanProcessCalls(ctx: FileCtx, flow?: ToolFlow): ProcessScan {
  return ctx.lang === 'py' ? scanPy(ctx, flow) : scanJs(ctx, flow);
}

// --- JavaScript / TypeScript --------------------------------------------------

interface Bindings {
  /** Bare local name → child_process method it refers to. */
  names: Map<string, string>;
  /** Namespace aliases for the whole module (`cp`, `child_process_1`, `import_child_process`). */
  namespaces: Set<string>;
  /** Third-party library objects whose members spawn (`crossSpawn.sync`). */
  libNamespaces: Map<string, Record<string, string>>;
  /** Text ranges of the binding statements themselves (never call sites). */
  ranges: [number, number][];
  importIndex: number;
  /** `child_process` is loaded through something we cannot follow (an unusual loader, a computed name). */
  unreadable: number;
  /** The file has a require/import of a value that does not fold — any binding could hide behind it. */
  opaqueRequire: boolean;
  /** Computed-member calls on the module (`cp[name](…)`) with a runtime key. */
  computed: number[];
  /** `require(<expr folding to child_process>).method(` calls. */
  inline: { at: number; method: string; open: number }[];
}

function jsBindings(ctx: FileCtx): Bindings {
  const { src } = ctx;
  const b: Bindings = { names: new Map(), namespaces: new Set(), libNamespaces: new Map(), ranges: [], importIndex: -1, unreadable: -1, opaqueRequire: false, computed: [], inline: [] };
  const note = (m: RegExpExecArray): void => {
    b.ranges.push([m.index, m.index + m[0].length]);
    if (b.importIndex < 0 || m.index < b.importIndex) b.importIndex = m.index;
  };
  const addNamed = (list: string, sep: 'as' | ':'): void => {
    for (const raw of list.split(',')) {
      const part = raw.replace(/^\s*type\s+/, '').trim();
      if (!part) continue;
      const [orig, alias] = sep === 'as' ? part.split(/\s+as\s+/) : part.split(/\s*:\s*/);
      const method = (orig ?? '').trim();
      const local = (alias ?? orig ?? '').trim().replace(/\s*=.*$/, '');
      if (JS_METHODS.has(method) && /^[A-Za-z_$][\w$]*$/.test(local)) b.names.set(local, method);
    }
  };
  const run = (re: RegExp, fn: (m: RegExpExecArray) => void): void => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) if (ctx.isCode(m.index)) { note(m); fn(m); }
  };
  // `const req = createRequire(import.meta.url)` — `req` is `require`.
  const loaderNames = ['require'];
  for (const c of src.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:module\.|\w+\.)?createRequire\s*\(/g)) if (ctx.isCode(c.index!)) loaderNames.push(c[1]!);
  const REQ = `(?:${loaderNames.map((n) => n.replace(/\$/g, '\\$')).join('|')})`;
  // A require/import of a computed value: fold it — `require(['child','process'].join('_'))`
  // style names that fold to child_process are bindings; ones that do not fold are opaque.
  for (const c of src.matchAll(new RegExp(String.raw`(?<![.\w$])(?:${REQ}|import)\s*\(\s*(?!['"])`, 'g'))) {
    if (!ctx.isCode(c.index!)) continue;
    const args = splitArgs(src, ctx.mask, src.indexOf('(', c.index!));
    if (!args || args.args.length !== 1 || args.args[0]!.startsWith('`') && !args.args[0]!.includes('${')) continue;
    const v = fold(ctx, args.args[0]!, { at: c.index! });
    if (v.kind === 'literal' && v.values.some((x) => /^(?:node:)?child_process$/.test(x))) {
      // Bind it like a literal require: `X = require(expr)` / `const {..} = require(expr)` / inline `.method(`.
      const before = src.slice(Math.max(0, c.index! - 160), c.index!);
      const ns = /(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?$/.exec(before);
      const de = /\{([^}]*)\}\s*=\s*(?:await\s+)?$/.exec(before);
      if (de) addNamed(de[1]!, ':');
      else if (ns) b.namespaces.add(ns[1]!);
      if (b.importIndex < 0 || c.index! < b.importIndex) b.importIndex = c.index!;
      const after = src.slice(args.end + 1, args.end + 40);
      const inl = /^\s*\.\s*(\w+)\s*\(/.exec(after);
      if (inl && JS_METHODS.has(inl[1]!)) b.inline.push({ at: c.index!, method: inl[1]!, open: args.end + 1 + inl[0].length - 1 });
    } else if (v.kind !== 'literal') b.opaqueRequire = true;
  }
  // `anyLoader('child_process')` through a function we do not recognise.
  for (const c of src.matchAll(/([A-Za-z_$][\w$.]*)\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g)) {
    if (!ctx.isCode(c.index!)) continue;
    if (new RegExp(`^(?:${REQ}|import|.*\\.require)$`).test(c[1]!)) continue;
    if (b.unreadable < 0) b.unreadable = c.index!;
  }

  // import { a, b as c } from 'child_process'   /   import cp, { a } from 'child_process'
  run(new RegExp(String.raw`\bimport\s+(?:([A-Za-z_$][\w$]*)\s*,\s*)?\{([^}]*)\}\s*from\s*${CP_SPEC}`, 'g'), (m) => {
    if (m[1]) b.namespaces.add(m[1]);
    addNamed(m[2]!, 'as');
  });
  // import * as cp from 'child_process'   /   import cp from 'child_process'
  run(new RegExp(String.raw`\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*${CP_SPEC}`, 'g'), (m) => b.namespaces.add(m[1]!));
  // const { a, b: c } = require('child_process')   /   = await import('child_process')
  run(new RegExp(String.raw`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:${REQ}|import)\s*\(\s*${CP_SPEC}\s*\)`, 'g'), (m) => addNamed(m[1]!, ':'));
  // ns = require('child_process'), incl. TS/esbuild/babel interop wrappers.
  run(
    new RegExp(
      String.raw`(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:__toESM|__importStar|__importDefault|_interopRequireWildcard|_interopRequireDefault|tslib\.__importStar)?\s*\(?\s*(?:await\s+)?(?:${REQ}|import)\s*\(\s*${CP_SPEC}\s*\)(?!\s*\.)`,
      'g',
    ),
    (m) => b.namespaces.add(m[1]!),
  );
  // const run = promisify(execFile) / util.promisify(cp.execFile) / (0, import_util.promisify)(execFile)
  run(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:util\.|\(\s*0\s*,\s*[\w$]+\.)?promisify\)?\s*\(\s*([\w$.]+(?:\(\s*['"](?:node:)?child_process['"]\s*\)\.[\w$]+)?)\s*\)/g, (m) => {
    const arg = m[2]!;
    const method = b.names.get(arg) ?? (/\.([\w$]+)$/.exec(arg)?.[1] ?? '');
    const ns = arg.split('.')[0]!;
    if (JS_METHODS.has(method) && (b.names.has(arg) || b.namespaces.has(ns) || /child_process/.test(arg))) b.names.set(m[1]!, method);
  });
  // Third-party process libraries: cross-spawn, execa.
  for (const [lib, exportsMap] of Object.entries(LIB_EXPORTS)) {
    const spec = String.raw`['"]${lib}['"]`;
    run(new RegExp(String.raw`\bimport\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{([^}]*)\})?\s*from\s*${spec}`, 'g'), (m) => {
      if (exportsMap.default) b.names.set(m[1]!, exportsMap.default);
      if (m[2]) for (const part of m[2].split(',')) {
        const [o, al] = part.trim().split(/\s+as\s+/);
        if (o && exportsMap[o.trim()]) b.names.set((al ?? o).trim(), exportsMap[o.trim()]!);
      }
    });
    run(new RegExp(String.raw`\bimport\s*\{([^}]*)\}\s*from\s*${spec}`, 'g'), (m) => {
      for (const part of m[1]!.split(',')) {
        const [o, al] = part.trim().split(/\s+as\s+/);
        if (o && exportsMap[o.trim()]) b.names.set((al ?? o).trim(), exportsMap[o.trim()]!);
      }
    });
    run(new RegExp(String.raw`(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:__toESM\s*\()?\s*require\s*\(\s*${spec}\s*\)(?!\s*\.)`, 'g'), (m) => {
      if (exportsMap.default) b.names.set(m[1]!, exportsMap.default);
      b.libNamespaces.set(m[1]!, exportsMap);
    });
    run(new RegExp(String.raw`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*${spec}\s*\)`, 'g'), (m) => {
      for (const part of m[1]!.split(',')) {
        const [o, al] = part.trim().split(/\s*:\s*/);
        if (o && exportsMap[o.trim()]) b.names.set((al ?? o).trim(), exportsMap[o.trim()]!);
      }
    });
  }
  // `const sp = require('child_process').spawn` — a method pulled off the require.
  run(new RegExp(String.raw`(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:${REQ}|import)\s*\(\s*${CP_SPEC}\s*\)\s*\.\s*(\w+)\b(?!\s*\()`, 'g'), (m) => {
    if (JS_METHODS.has(m[2]!)) b.names.set(m[1]!, m[2]!);
  });
  // `import('child_process').then((cp) => cp.spawn(…))` / `.then(({ spawn }) => …)`.
  run(new RegExp(String.raw`\bimport\s*\(\s*${CP_SPEC}\s*\)\s*\.\s*then\s*\(\s*(?:async\s+)?(?:function\s*\w*\s*)?\(?\s*(\{[^}]*\}|[A-Za-z_$][\w$]*)`, 'g'), (m) => {
    const p = m[1]!;
    if (p.startsWith('{')) addNamed(p.slice(1, -1), ':');
    else b.namespaces.add(p);
  });
  // Second-hand bindings off a namespace: `const run = cp.execFile`, `const { exec: x } = cp`,
  // `cp['exec'](…)`, and `cp[name](…)` with a runtime key.
  for (const ns of [...b.namespaces]) {
    const n = ns.replace(/\$/g, '\\$');
    run(new RegExp(String.raw`(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*${n}(?:\.default)?\.(\w+)\b(?!\s*\()`, 'g'), (m) => {
      if (JS_METHODS.has(m[2]!)) b.names.set(m[1]!, m[2]!);
    });
    run(new RegExp(String.raw`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*${n}(?:\.default)?\s*[;\n,)]`, 'g'), (m) => addNamed(m[1]!, ':'));
    for (const c of src.matchAll(new RegExp(String.raw`(?<![.\w$])${n}(?:\.default)?\[\s*([^\]]+?)\s*\]\s*\(`, 'g'))) {
      if (!ctx.isCode(c.index!)) continue;
      const key = fold(ctx, c[1]!, { at: c.index! });
      if (key.kind === 'literal' && key.values.every((v) => JS_METHODS.has(v))) b.inline.push({ at: c.index!, method: key.values[0]!, open: c.index! + c[0].length - 1 });
      else b.computed.push(c.index!);
    }
  }
  if (b.importIndex < 0 && b.unreadable >= 0) b.importIndex = b.unreadable;
  if (b.importIndex < 0) {
    const j = src.search(new RegExp(String.raw`(?:require|import)\s*\(\s*${CP_SPEC}|from\s*${CP_SPEC}`));
    if (j >= 0) b.importIndex = j;
    else {
      const i = src.search(/\bchild_process\b/);
      if (i >= 0 && ctx.isCode(i)) b.importIndex = i;
    }
  }
  return b;
}

function scanJs(ctx: FileCtx, flow?: ToolFlow): ProcessScan {
  const b = jsBindings(ctx);
  const { src, mask } = ctx;
  const calls: ProcessCall[] = [];
  const inBinding = (i: number): boolean => b.ranges.some(([s, e]) => i >= s && i < e);
  const seen = new Set<number>();
  const push = (index: number, method: string, open: number): void => {
    if (seen.has(index) || !ctx.isCode(index) || inBinding(index)) return;
    const args = splitArgs(src, mask, open);
    if (!args) return;
    seen.add(index);
    calls.push(classifyJs(ctx, method, index, args, flow));
  };

  // Bare bound names: execFile(...), run(...)
  for (const [local, method] of b.names) {
    const re = new RegExp(String.raw`(?<![.\w$])${local.replace(/\$/g, '\\$')}\s*\(`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      if (/\bfunction\s*\*?\s*$/.test(src.slice(Math.max(0, m.index - 12), m.index))) continue;
      push(m.index, method, m.index + m[0].length - 1);
    }
  }
  // Namespace calls: cp.execFile(...), child_process_1.default.spawn(...), (0, ns.execFile)(...)
  for (const ns of b.namespaces) {
    const n = ns.replace(/\$/g, '\\$');
    const direct = new RegExp(String.raw`(?<![.\w$])${n}(?:\.default)?\.(\w+)\s*\(`, 'g');
    let m: RegExpExecArray | null;
    while ((m = direct.exec(src))) if (JS_METHODS.has(m[1]!)) push(m.index, m[1]!, m.index + m[0].length - 1);
    const indirect = new RegExp(String.raw`\(\s*0\s*,\s*${n}(?:\.default)?\.(\w+)\s*\)\s*\(`, 'g');
    while ((m = indirect.exec(src))) if (JS_METHODS.has(m[1]!)) push(m.index, m[1]!, m.index + m[0].length - 1);
  }
  // Inline: require('child_process').exec(...)
  {
    const re = new RegExp(String.raw`\brequire\s*\(\s*${CP_SPEC}\s*\)\.(\w+)\s*\(`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) if (JS_METHODS.has(m[1]!)) push(m.index, m[1]!, m.index + m[0].length - 1);
  }
  // A bound process function handed on as a VALUE (`spawnImpl = spawn`,
  // `run(cmd, spawn)`) is called somewhere we cannot see, with arguments we
  // cannot read. Record it as a dynamic call — exactly as cautious as the old rule.
  for (const [local, method] of b.names) {
    const re = new RegExp(String.raw`(?<![.\w$])${local.replace(/\$/g, '\\$')}(?![\w$])`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      const i = m.index;
      if (!ctx.isCode(i) || inBinding(i) || seen.has(i)) continue;
      let j = i + local.length;
      while (j < src.length && (src[j] === ' ' || src[j] === '\t')) j++;
      if (src[j] === '(' || src[j] === ':' || (src[j] === '=' && src[j + 1] !== '=')) continue; // call, key, assignment target
      const before = src.slice(Math.max(0, i - 24), i);
      if (/promisify\)?\s*\(\s*$/.test(before) || /\bfunction\s*\*?\s*$/.test(before)) continue;
      if (/(?:const|let|var)\s*$/.test(before)) continue;
      seen.add(i);
      // `X.sync(…)` on a cross-spawn binding stays this record, as in 1.17: whether `.sync` is still
      // cross-spawn's own when it runs is not something the scanner can prove from the package's text.
      calls.push({
        index: i,
        line: ctx.line(i),
        method,
        shape: 'dynamic-program',
        program: '<passed on as a value>',
        snippet: normalize(src.slice(Math.max(0, i - 40), i + local.length + 40)),
        toolInput: false,
      });
    }
  }
  // `require(<folds to child_process>).exec(…)` and `cp['exec'](…)`.
  for (const c of b.inline) push(c.at, c.method, c.open);
  // `cp[name](…)` with a runtime key: which API runs is decided at runtime.
  for (const at of b.computed) {
    if (seen.has(at)) continue;
    seen.add(at);
    calls.push({ index: at, line: ctx.line(at), method: '[computed]', shape: 'dynamic-program', program: '<API chosen at runtime>', snippet: normalize(src.slice(at, at + 120)), toolInput: false });
  }

  // Library member calls: crossSpawn.sync(...)
  for (const [ns, exportsMap] of b.libNamespaces) {
    const re = new RegExp(String.raw`(?<![.\w$])${ns.replace(/\$/g, '\\$')}\.(\w+)\s*\(`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) if (exportsMap[m[1]!]) push(m.index, exportsMap[m[1]!]!, m.index + m[0].length - 1);
  }
  // Process APIs called as a MEMBER of something we did not bind — a bundler's
  // numeric module (`__webpack_require__(81).spawn`, `(0, child_process_1.spawn)(…)`
  // after `__nccwpck_require__`), a re-export object. When the file loads
  // child_process at all, such a call is a process call, not "import only".
  if (b.importIndex >= 0) {
    const reMember = /(?:\(\s*0\s*,\s*)?(?<![\w$])([A-Za-z_$][\w$]*)((?:\s*\.\s*[A-Za-z_$][\w$]*)*?)\s*\.\s*(execFileSync|execFile|execSync|spawnSync|spawn|fork|exec)\s*\)?\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = reMember.exec(src))) {
      const recv = m[1]!;
      const method = m[3]!;
      if (b.namespaces.has(recv) || b.libNamespaces.has(recv)) continue;
      if (/^(?:this|self|console|Math|JSON|Object|Array|Promise|String|Number|RegExp|db|sql|stmt)$/.test(recv)) continue;
      // `.exec(` is RegExp/DB everywhere — only a process-looking receiver counts.
      if (method === 'exec' && !/(?:child|proc|process|^cp$|_cp$|shell|^sh$|spawn|exec)/i.test(recv + (m[2] ?? ''))) continue;
      const open = m.index + m[0].length - 1;
      push(m.index, method, open);
    }
  }
  // Bare process-API names with no binding we could read — an obfuscated
  // require, a re-export through another module. The old rule matched these
  // names wherever they appeared; keep that floor so a real call is never
  // silently dropped, unless the file defines a function of that name itself.
  {
    const re = /(?<![.\w$])(execFileSync|execFile|execSync|exec|spawnSync|spawn)\s*\((?!\s*\/)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      const name = m[1]!;
      if (b.names.has(name)) continue;
      // A same-named local function is a decoy only when nothing in the file can
      // smuggle in the real API; behind an opaque require it proves nothing.
      if (!b.opaqueRequire && ctx.functions().some((f) => f.name === name)) continue;
      if (/\bfunction\s*\*?\s*$|\bdef\s+$/.test(src.slice(Math.max(0, m.index - 12), m.index))) continue;
      // `exec(` alone is everywhere (RegExp#exec, DB clients) — require a process import for it.
      if (name === 'exec' && b.importIndex < 0) continue;
      push(m.index, name, m.index + m[0].length - 1);
    }
  }
  // child_process is loaded through something we could not read, and no call
  // was found: the calls exist somewhere we cannot see. Not "import only".
  const bound = b.names.size + b.namespaces.size + b.libNamespaces.size + b.inline.length;
  if (!calls.length && b.importIndex >= 0 && (b.unreadable >= 0 || (!bound && b.opaqueRequire))) {
    const at = b.unreadable >= 0 ? b.unreadable : b.importIndex;
    calls.push({ index: at, line: ctx.line(at), method: 'child_process', shape: 'dynamic-program', program: '<loaded through a binding the scanner cannot read>', snippet: normalize(src.slice(at, at + 120)), toolInput: false });
  }
  calls.sort((x, y) => x.index - y.index);
  return { importsModule: b.importIndex >= 0, importIndex: b.importIndex, calls };
}

/** Does a package-relative path climb out of the package? */
function leavesPackage(file: string, rel: string): boolean {
  const parts: string[] = [];
  for (const seg of `${file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : ''}/${rel}`.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (!parts.length) return true;
      parts.pop();
    } else parts.push(seg);
  }
  return false;
}

const CALLBACK = /^(?:function\b|\(|async\b|[A-Za-z_$][\w$]*\s*=>)/;
/** A program and options longer than this are not read again for tool input (1.18): the reading of 1.17 stays. */
const CODE_INPUT_CAP = 4096;

/**
 * A program written as a plain name, a member of one or an element of one
 * (1.18): `bin`, `this.bin`, `cfg?.paths.bin`, `process.env.TOOL`, `argv[0]`.
 * Nothing else: no literal, no call, no operator, no cast, no comment.
 */
const PLAIN_REFERENCE = /^[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*|\s*\[\s*(?:\d+|[A-Za-z_$][\w$]*)\s*\])*$/;

/**
 * A shell or eval flag as written in an argv: `-c`, `-lc`, `-ic`, `-e`, `-p`, `--eval`, `--command`
 * (case matters: `git -C dir` is no such flag); `/c`, `/k`, `/r`, `-Command`, `-EncodedCommand`,
 * `-enc` in any case.
 */
const CODE_FLAG = /^(?:-[a-z]*c|-e|-p|--eval|--print|--command|--exec)$/;
const CODE_FLAG_ANY_CASE = /^(?:\/[ckr]|-command(?:withargs)?|-encodedcommand|-enc)$/i;

/** The same flags as a quoted string anywhere in the arguments as written: `["-c"].concat(line)`, `f ? ["-c", x] : [x]`. */
const CODE_FLAG_WRITTEN = /['"`](?:-[a-z]*c|-e|-p|--eval|--print|--command|--exec)['"`]/;
const CODE_FLAG_WRITTEN_ANY_CASE = /['"`](?:\/[ckr]|-command(?:withargs)?|-encodedcommand|-enc)['"`]/i;
const flagWritten = (text: string): boolean => CODE_FLAG_WRITTEN.test(text) || CODE_FLAG_WRITTEN_ANY_CASE.test(text);

/** Does a folded argv hold a shell or eval flag as a literal element? */
function holdsCodeFlag(argv: Folded): boolean {
  return argv.kind === 'array' && argv.elements.some((e) => e.kind === 'literal' && e.values.some((v) => CODE_FLAG.test(v.trim()) || CODE_FLAG_ANY_CASE.test(v.trim())));
}

function classifyJs(ctx: FileCtx, method: string, index: number, args: ArgList, flow?: ToolFlow): ProcessCall {
  const a = args.args;
  const snippet = normalize(ctx.src.slice(index, args.end + 1));
  const line = ctx.line(index);
  const base = { index, line, method, snippet };
  // Tool input in `read` (the argv, or the command line), as in 1.17. A call that runs code chosen at
  // runtime also counts its program and its options (1.18): not a result callback, which runs after the
  // process, and not a program and options over the cap, where the reading of 1.17 stays. One walk.
  const toolInputOf = (shape: CallShape, read: string | undefined, program: string | undefined, options: string | undefined): boolean => {
    if (!flow?.hasHandlers) return false;
    const more = shape === 'shell-dynamic' || shape === 'dynamic-program' ? [program, options !== undefined && !CALLBACK.test(options) ? options : undefined] : [];
    // Not a program or options that hold a template literal either: reading them is not linear.
    const parts = more.filter((x): x is string => !!x && !x.includes('`'));
    return flow.carries([read ?? '', ...(parts.reduce((n, x) => n + x.length, 0) <= CODE_INPUT_CAP ? parts : [])], index);
  };
  if (STRING_COMMAND_METHODS.has(method)) {
    // execaCommand('git status'): no shell, the string is split into program + argv.
    const cmd = foldInScope(ctx, a[0] ?? '', index);
    const shape: CallShape = isConst(cmd) ? 'fixed-program-fixed-args' : 'dynamic-program';
    const toolInput = toolInputOf(shape, a[0], undefined, a[1]);
    return { ...base, shape, program: describeFolded(cmd), toolInput };
  }
  if (JS_SHELL_METHODS.has(method)) {
    const cmd = foldInScope(ctx, a[0] ?? '', index);
    const shape: CallShape = isConst(cmd) ? 'shell-fixed' : 'shell-dynamic';
    const toolInput = toolInputOf(shape, a[0], undefined, a[1]);
    return { ...base, shape, program: describeFolded(cmd), toolInput };
  }
  // execFile/spawn/fork(program, [argv], [options], [callback])
  let program = foldInScope(ctx, a[0] ?? '', index);
  // A "file of the package" that climbs out of it is not the package's own program.
  if (program.kind === 'own-path' && leavesPackage(ctx.path, program.value)) program = { kind: 'unknown', why: 'a path outside the package' };
  let argvText: string | undefined;
  let optsText: string | undefined;
  const second = a[1];
  if (second !== undefined && !CALLBACK.test(second)) {
    if (second.startsWith('{')) optsText = second;
    else if (second.startsWith('[')) {
      argvText = second;
      optsText = a[2];
    } else {
      // An identifier/expression: an argv array, or an options object.
      const f = foldInScope(ctx, second, index);
      const decl = /^[A-Za-z_$][\w$]*$/.test(second) ? ctx.constInitAt(second, index) : undefined;
      if (f.kind === 'array') {
        argvText = second;
        optsText = a[2];
      } else if (decl && decl.init.trim().startsWith('{')) optsText = second;
      else {
        argvText = second; // unknown: assume argv (runtime), and look at the next argument for options
        optsText = a[2];
      }
    }
  }
  if (optsText && CALLBACK.test(optsText)) optsText = undefined; // a callback
  const shellRead = method === 'fork' ? false : shellOption(ctx, optsText, index);
  let shell = shellRead;
  // 1.18, the label only: "set at runtime" is said of the value of a `shell` key written at the top
  // level of inline options. A key in a comment, in a nested object or in another value stays the
  // 'unknown' of 1.17.
  if (shell === 'runtime') {
    const value = topLevelShellValue(ctx, args, optsText);
    if (value === null || !setAtRuntime(ctx, value, index)) shell = 'unknown';
  }
  const argv: Folded = argvText !== undefined ? foldInScope(ctx, argvText, index) : { kind: 'array', elements: [], dynamic: false };
  const stdinLiteral = !!optsText && /\binput\s*:\s*(['"])(?:(?!\1)[^\\])*\1\s*[,}]/.test(optsText);
  const shaped = shell === 'runtime' ? shellSetAtRuntime(program, argv, stdinLiteral) : shapeOf(program, argv, shell, stdinLiteral);
  // A fixed program: the argv alone decides it, as in 1.17 (that is all the medium "option injection" rule reads).
  const toolInput = toolInputOf(shaped.shape, argvText, a[0], optsText);
  // 1.18, the words only: a program not written as a plain reference, a shell / eval flag in the
  // arguments, or options that ask for a shell or name one (`shell: true`, `shell: isWin`, a `shell`
  // key next to a spread).
  // The options as written, or the object a constant holds: do they ask for a shell, or name one?
  const optsDecl = optsText !== undefined && /^[A-Za-z_$][\w$]*$/.test(optsText) ? ctx.constInitAt(optsText, index) : undefined;
  const shellSeen = shellRead === true || shellRead === 'runtime' || (shellRead === 'unknown' && /shell/i.test(optsDecl?.init ?? optsText ?? ''));
  const keepWords = !PLAIN_REFERENCE.test(a[0] ?? '') || holdsCodeFlag(argv) || flagWritten(a.slice(1).join(',')) || shellSeen;
  return { ...base, ...shaped, toolInput, ...(keepWords ? { keepWords: true } : {}) };
}

/** The value of the `shell` key written at the top level of these inline options (the last one), or null. */
function topLevelShellValue(ctx: FileCtx, args: ArgList, optsText: string | undefined): string | null {
  const k = optsText === undefined ? -1 : args.args.indexOf(optsText);
  if (k < 0 || !optsText!.startsWith('{')) return null;
  let value: string | null = null;
  for (const e of splitArgs(ctx.src, ctx.mask, args.starts[k]!)?.args ?? []) {
    if (e === 'shell') value = 'shell';
    else {
      const m = /^(?:shell|'shell'|"shell")\s*:\s*([\s\S]+)$/.exec(e);
      if (m) value = m[1]!;
    }
  }
  return value;
}

type Shaped = { shape: CallShape; program: string; shellAtRuntime?: boolean; rankAs?: CallShape };

/**
 * An explicit `shell` option whose value is decided at runtime
 * (`shell: process.platform === "win32"`) is judged exactly as options the
 * scanner cannot read (1.17); only the label says which (1.18). A dynamic
 * program with runtime arguments is then the `shell-dynamic` it is where that
 * value is true — same severity, confidence and capability, and it ranks as
 * the `dynamic-program` it was. A shape 1.17 called fixed is never raised.
 */
function shellSetAtRuntime(program: Folded, argv: Folded, stdinLiteral: boolean): Shaped {
  const s = shapeOf(program, argv, 'unknown', stdinLiteral);
  // A shell only because the options may turn one on (not `bash -c …`): say why.
  if (s.shape === 'shell-dynamic') return shapeOf(program, argv, false, stdinLiteral).shape === 'shell-dynamic' ? s : { ...s, shellAtRuntime: true };
  if (s.shape === 'dynamic-program' && !isConst(argv)) return { ...s, shape: 'shell-dynamic', shellAtRuntime: true, rankAs: 'dynamic-program' };
  return s;
}

/** Shape from a folded program + argv. `shell` is true, false, or 'unknown' (options we cannot see). */
function shapeOf(programIn: Folded, argvIn: Folded, shell: boolean | 'unknown', stdinLiteral = false): { shape: CallShape; program: string } {
  let program = programIn;
  let argv = argvIn;
  const label = (): string => describeFolded(program);
  const lit = (f: Folded | undefined): string[] => (f && f.kind === 'literal' ? f.values.map((v) => v.trim()) : f && f.kind === 'exec-path' ? ['<node>'] : []);
  const isFlag = (f: Folded): boolean => f.kind === 'literal' && f.values.every((v) => /^-/.test(v.trim()));
  const elements = (): Folded[] | null => (argv.kind === 'array' ? argv.elements : null);

  if (shell === true) return { shape: isConst(program) && isConst(argv) ? 'shell-fixed' : 'shell-dynamic', program: label() };
  if (!isConst(program)) return { shape: 'dynamic-program', program: label() };

  // Look through wrappers (`env bash -c …`, `sudo -u x cmd`, `timeout 5 node -e …`).
  for (let hop = 0; hop < 4 && lit(program).some((p) => WRAPPERS.test(p)); hop++) {
    const els = elements();
    if (!els) return { shape: 'dynamic-program', program: label() };
    let i = 0;
    while (i < els.length && (isFlag(els[i]!) || lit(els[i]).every((v) => /^[A-Za-z_][A-Za-z0-9_]*=|^\d+(?:\.\d+)?[smhd]?$/.test(v)) && els[i]!.kind === 'literal')) i++;
    const next = els[i];
    if (!next) break;
    if (!isConst(next)) return { shape: 'dynamic-program', program: label() };
    program = next;
    argv = { kind: 'array', elements: els.slice(i + 1), dynamic: argv.kind === 'array' ? argv.dynamic : true };
  }
  // A program that is a file of the package: judge it by its base name too
  // (`<package>/../../bin/sh` is still a shell).
  const prog = program.kind === 'own-path' ? [program.value.split('/').pop() ?? program.value] : lit(program);
  const els = elements();
  const words = els ? els.filter((e) => !isFlag(e)) : null;
  // A shell or an interpreter given NO command and NO script reads its program
  // from stdin — `spawn('sh')` then `child.stdin.write(cmd)`, `execFileSync('bash',
  // { input })`: a reverse-shell shape. Literal `input` is the only fixed case.
  if (els && words && !words.length && !els.some((e) => e.kind === 'literal' && e.values.some((v) => SHELL_FLAGS.test(v.trim()) || EVAL_FLAGS.test(v.trim()))) &&
      prog.some((p) => SHELL_PROGRAMS.test(p) || INTERPRETERS.test(p)) && !(argv.kind === 'array' && argv.dynamic)) {
    return { shape: stdinLiteral ? 'shell-fixed' : 'shell-dynamic', program: label() };
  }

  // A shell handed a command line.
  if (prog.some((p) => SHELL_PROGRAMS.test(p))) {
    if (!els) return { shape: 'shell-dynamic', program: label() };
    const flagAt = els.findIndex((e) => e.kind === 'literal' && e.values.some((v) => SHELL_FLAGS.test(v.trim())));
    if (flagAt >= 0) {
      const script = els[flagAt + 1];
      const scriptConst = script !== undefined ? isConst(script) : !(argv.kind === 'array' && argv.dynamic);
      return { shape: scriptConst && !(argv.kind === 'array' && argv.dynamic) ? 'shell-fixed' : 'shell-dynamic', program: label() };
    }
    // `bash script.sh` — the script is the program.
    const first = els.find((e) => !isFlag(e));
    if ((first && !isConst(first)) || (argv.kind === 'array' && argv.dynamic && !first)) return { shape: 'shell-dynamic', program: label() };
  }

  // An interpreter running code or a script chosen at runtime.
  if (prog.some((p) => INTERPRETERS.test(p))) {
    if (!els) return { shape: 'dynamic-program', program: label() };
    const evalAt = els.findIndex((e) => e.kind === 'literal' && e.values.some((v) => EVAL_FLAGS.test(v.trim())));
    if (evalAt >= 0) {
      const code = els[evalAt + 1];
      if (!code || !isConst(code)) return { shape: 'dynamic-program', program: label() };
      return { shape: 'shell-fixed', program: label() }; // literal inline code
    }
    const script = els.find((e) => !isFlag(e));
    if ((script && !isConst(script)) || (!script && argv.kind === 'array' && argv.dynamic)) return { shape: 'dynamic-program', program: label() };
  }

  // A package runner fetching and running a package chosen at runtime.
  if (prog.some((p) => PKG_RUNNERS.test(p))) {
    if (!els) return { shape: 'dynamic-program', program: label() };
    const pkg = els.find((e) => !isFlag(e));
    if ((pkg && !isConst(pkg)) || (!pkg && argv.kind === 'array' && argv.dynamic)) return { shape: 'dynamic-program', program: label() };
  }
  if (prog.some((p) => PKG_MANAGERS.test(p))) {
    if (!els) return { shape: 'dynamic-program', program: label() };
    const words = els.filter((e) => !isFlag(e));
    const sub = words[0];
    if (sub && !isConst(sub)) return { shape: 'dynamic-program', program: label() };
    if (sub && lit(sub).some((v) => PKG_RUN_SUBCOMMANDS.test(v)) && (words.slice(1).some((w) => !isConst(w)) || (argv.kind === 'array' && argv.dynamic))) {
      return { shape: 'dynamic-program', program: label() };
    }
  }

  // Options we could not see may turn a shell on: with runtime arguments that is a shell command line.
  if (shell === 'unknown' && !isConst(argv)) return { shape: 'shell-dynamic', program: label() };
  return { shape: isConst(argv) ? 'fixed-program-fixed-args' : 'fixed-program-dynamic-args', program: label() };
}

/**
 * Does a `shell` value that does not fold name a binding, so that it is set at
 * runtime (`process.platform === "win32"`, `isWin`)? A value of literals and
 * operators only (`!1`, `!0`, `void 0`), or a constant initialised to one, does
 * not: it stays the 'unknown' of 1.17.
 */
function setAtRuntime(ctx: FileCtx, value: string, at: number, depth = 0): boolean {
  const v = value.trim();
  // A value this long is no platform test; reading it is not linear either. The 'unknown' of 1.17.
  if (v.length > 200) return false;
  if (depth < 3 && /^[A-Za-z_$][\w$]*$/.test(v)) {
    const decl = ctx.constInitAt(v, at);
    if (decl) return setAtRuntime(ctx, decl.init, decl.at, depth + 1);
  }
  const code = v.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g, '""');
  return /(?<![\w$.])(?!(?:true|false|null|undefined|void|typeof|NaN|Infinity)(?![\w$]))[A-Za-z_$][\w$]*/.test(code);
}

/**
 * Is a shell requested by these options? true / false; 'runtime' when an
 * explicit `shell` key holds a value set at runtime (1.18: judged exactly
 * as 'unknown'); 'unknown' when the options are a parameter, a spread, or
 * anything else we cannot read.
 */
function shellOption(ctx: FileCtx, optsText: string | undefined, at: number, depth = 0): boolean | 'unknown' | 'runtime' {
  if (optsText === undefined) return false;
  const t = optsText.trim();
  if (t.startsWith('{')) {
    if (/\.\.\./.test(t)) {
      // A spread can carry `shell`, unless an explicit `shell:` after it decides.
      const after = t.slice(t.lastIndexOf('...'));
      const explicit = /(?:\bshell|['"`]shell['"`])\s*:\s*([^,}\n]+)/.exec(after);
      if (!explicit) return 'unknown';
    }
    // `{ shell }` shorthand: the value is a variable of that name.
    if (/[{,]\s*shell\s*[,}]/.test(t)) {
      const f = fold(ctx, 'shell', { at });
      if (f.kind === 'literal') return f.values.some((x) => !/^(?:false|undefined|null|0|)$/.test(x));
      return setAtRuntime(ctx, 'shell', at) ? 'runtime' : 'unknown';
    }
    if (/\[\s*[^\]]+\]\s*:/.test(t)) return 'unknown'; // a computed key could be `shell`
    const m = /(?:\bshell|['"`]shell['"`])\s*:\s*([^,}\n]+)/.exec(t);
    if (!m) return false;
    const v = m[1]!.trim();
    if (/^(?:false|undefined|null|0|'')$/.test(v)) return false;
    if (/^(?:true|['"`])/.test(v)) return true;
    const f = fold(ctx, v, { at });
    if (f.kind === 'literal') return f.values.some((x) => !/^(?:false|undefined|null|0|)$/.test(x));
    return setAtRuntime(ctx, v, at) ? 'runtime' : 'unknown';
  }
  if (depth < 3 && /^[A-Za-z_$][\w$]*$/.test(t)) {
    const decl = ctx.constInitAt(t, at);
    if (decl) return shellOption(ctx, decl.init, decl.at, depth + 1);
  }
  return 'unknown';
}

/**
 * Fold `expr` at `at`, resolving the parameters of EVERY enclosing function from
 * its call sites on demand — but only for a LOCAL function whose every caller is
 * in view (not exported, never passed as a value). A parameter reached through
 * a local alias (`const p = entry instanceof URL ? fileURLToPath(entry) : entry`)
 * resolves too, because the resolver is consulted wherever the folder meets a name.
 */
function foldInScope(ctx: FileCtx, expr: string, at: number, depth = 0): Folded {
  const chain = ctx.enclosingChain(at);
  const memo = new Map<string, Folded>();
  const resolve = (name: string): Folded | undefined => {
    if (memo.has(name)) return memo.get(name);
    for (const fn of chain) {
      const p = fn.params.find((x) => x.name === name || [...(x.keys?.values() ?? [])].includes(name));
      if (!p) continue;
      let v: Folded = { kind: 'unknown', why: name };
      if (fn.name && p.name === name && depth < 3 && !ctx.escapes(fn.name)) {
        const sites = ctx.callSitesOf(fn.name);
        let merged: Folded | undefined;
        for (const s of sites) {
          const argText = s.args.args[p.index];
          // An omitted argument takes the parameter's DEFAULT, not `undefined`.
          const one: Folded =
            argText !== undefined
              ? foldInScope(ctx, argText, s.index, depth + 1)
              : p.default !== undefined
                ? foldInScope(ctx, p.default, fn.headerStart, depth + 1)
                : { kind: 'literal', values: ['undefined'] };
          merged = merged ? union(merged, one) : one;
          if (merged.kind === 'unknown') break;
        }
        if (merged) v = merged;
      }
      memo.set(name, v);
      return v;
    }
    return undefined;
  };
  return fold(ctx, expr, { resolve, at });
}

// --- Python -------------------------------------------------------------------

const PY_SHELL = new Set(['system', 'popen', 'getoutput', 'getstatusoutput', 'create_subprocess_shell']);
const PY_SUBPROCESS = new Set(['run', 'call', 'check_call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput']);

function scanPy(ctx: FileCtx, flow?: ToolFlow): ProcessScan {
  const { src, mask } = ctx;
  const calls: ProcessCall[] = [];
  let importIndex = -1;
  const names = new Map<string, string>(); // local → 'subprocess.run' | 'os.system'
  const namespaces = new Map<string, 'subprocess' | 'os'>();
  const noteImport = (i: number): void => {
    if (importIndex < 0 || i < importIndex) importIndex = i;
  };
  let m: RegExpExecArray | null;
  const reImport = /^[ \t]*import\s+([^\n#]+)/gm;
  while ((m = reImport.exec(src))) {
    if (!ctx.isCode(m.index + m[0].indexOf('import'))) continue;
    for (const part of m[1]!.split(',')) {
      const [modRaw, alias] = part.trim().split(/\s+as\s+/);
      const mod = (modRaw ?? '').trim();
      const top = mod.split('.')[0]!;
      // `import os.path` binds `os` too; `import os.path as p` binds p to os.path only.
      if (top === 'subprocess' || top === 'os') {
        const local = alias && mod === top ? alias.trim() : alias ? null : top;
        if (local) namespaces.set(local, top as 'subprocess' | 'os');
        if (top === 'subprocess') noteImport(m.index);
      }
    }
  }
  // `sp = importlib.import_module("subprocess")` / `__import__("os")`.
  for (const im of src.matchAll(/^[ \t]*([A-Za-z_]\w*)\s*=\s*(?:importlib\.)?(?:import_module|__import__)\s*\(\s*['"](subprocess|os)['"]\s*\)/gm)) {
    namespaces.set(im[1]!, im[2] as 'subprocess' | 'os');
    noteImport(im.index!);
  }
  // `from subprocess import (\n run,\n PIPE,\n)` spans lines; `*` binds every API.
  const reFrom = /^[ \t]*from\s+(subprocess|os)\s+import\s+(\([^)]*\)|[^\n#]+)/gm;
  while ((m = reFrom.exec(src))) {
    if (!ctx.isCode(m.index + m[0].indexOf('from'))) continue;
    const list = m[2]!.replace(/[()\\]/g, ' ').trim() === '*'
      ? (m[1] === 'subprocess' ? [...PY_SUBPROCESS] : ['system', 'popen']).join(',')
      : m[2]!.replace(/[()\\\n]/g, ' ');
    for (const part of list.split(',')) {
      const [orig, alias] = part.trim().split(/\s+as\s+/);
      const o = (orig ?? '').trim();
      if ((m[1] === 'subprocess' && PY_SUBPROCESS.has(o)) || (m[1] === 'os' && (o === 'system' || o === 'popen'))) {
        names.set((alias ?? o).trim(), `${m[1]}.${o}`);
        noteImport(m.index);
      }
    }
  }
  const push = (index: number, method: string, open: number): void => {
    if (!ctx.isCode(index)) return;
    const args = splitArgs(src, mask, open);
    if (!args) return;
    calls.push(classifyPy(ctx, method, index, args, flow));
  };
  // Second-hand aliases: `run = sp.run`, `run = getattr(subprocess, "run")`, and
  // `getattr(subprocess, name)(…)` with a runtime name.
  for (const [ns, mod] of namespaces) {
    for (const a of src.matchAll(new RegExp(String.raw`^[ \t]*([A-Za-z_]\w*)\s*=\s*(?:${ns}\.(\w+)|getattr\(\s*${ns}\s*,\s*['"](\w+)['"]\s*\))\s*$`, 'gm'))) {
      const fn = (a[2] ?? a[3])!;
      if (mod === 'subprocess' ? PY_SUBPROCESS.has(fn) : fn === 'system' || fn === 'popen') names.set(a[1]!, `${mod}.${fn}`);
    }
    for (const g of src.matchAll(new RegExp(String.raw`getattr\(\s*${ns}\s*,\s*(?!['"])[^)]+\)\s*\(`, 'g'))) {
      if (!ctx.isCode(g.index!)) continue;
      calls.push({ index: g.index!, line: ctx.line(g.index!), method: `${mod}.[computed]`, shape: 'dynamic-program', program: '<API chosen at runtime>', snippet: normalize(src.slice(g.index!, g.index! + 120)), toolInput: false });
    }
  }
  for (const [ns, mod] of namespaces) {
    const re = new RegExp(String.raw`(?<![.\w])${ns}\.(\w+)\s*\(`, 'g');
    while ((m = re.exec(src))) {
      const fn = m[1]!;
      if (mod === 'subprocess' ? PY_SUBPROCESS.has(fn) : fn === 'system' || fn === 'popen') {
        if (mod === 'os') noteImport(m.index);
        push(m.index, `${mod}.${fn}`, m.index + m[0].length - 1);
      }
    }
  }
  for (const [local, method] of names) {
    const re = new RegExp(String.raw`(?<![.\w])${local}\s*\(`, 'g');
    while ((m = re.exec(src))) push(m.index, method, m.index + m[0].length - 1);
  }
  const reAsync = /\b(?:asyncio\.)?(create_subprocess_exec|create_subprocess_shell)\s*\(/g;
  while ((m = reAsync.exec(src))) {
    noteImport(m.index);
    push(m.index, `asyncio.${m[1]}`, m.index + m[0].length - 1);
  }
  // A process API that slipped past every binding form above (a re-export, a
  // helper module object): never let the file read as having no call at all.
  if (!calls.length) {
    for (const raw of src.matchAll(/\b(?:[\w.]*\.)?(system|popen|run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(/g)) {
      const i = raw.index!;
      if (!ctx.isCode(i)) continue;
      const qual = raw[0];
      const looksProcess = /\b(?:os|subprocess|sp|commands)\b\s*\./.test(qual) || /^(?:Popen|check_output|check_call|getoutput|getstatusoutput)$/.test(raw[1]!);
      if (!looksProcess) continue;
      const fn = raw[1]!;
      push(i, fn === 'system' || fn === 'popen' ? `os.${fn}` : `subprocess.${fn}`, i + qual.length - 1);
      noteImport(i);
    }
  }
  calls.sort((x, y) => x.index - y.index);
  return { importsModule: importIndex >= 0, importIndex, calls };
}

function classifyPy(ctx: FileCtx, method: string, index: number, args: ArgList, flow?: ToolFlow): ProcessCall {
  const positional = args.args.filter((x) => !/^[A-Za-z_]\w*\s*=(?!=)/.test(x));
  const kwargs = args.args.filter((x) => /^[A-Za-z_]\w*\s*=(?!=)/.test(x));
  const shellKw = kwargs.some((k) => /^shell\s*=\s*(?!False\b|None\b|0\b)/.test(k));
  const short = method.split('.').pop()!;
  const snippet = normalize(ctx.src.slice(index, args.end + 1));
  const base = { index, line: ctx.line(index), method, snippet };
  const first = positional[0] ?? '';
  const toolInput = !!flow?.carries(args.args.join(','), index);
  if (PY_SHELL.has(short) || shellKw) {
    const cmd = foldInScope(ctx, first, index);
    return { ...base, shape: isConst(cmd) ? 'shell-fixed' : 'shell-dynamic', program: describeFolded(cmd), toolInput };
  }
  // 1.18, the words only. The program as written: the first element of one inline list, else the whole
  // first argument (`*argv` is its first element). It must be a plain reference; a program given by
  // keyword (`args=`, `executable=`) is not where the scanner reads it.
  const programText = (): string => {
    const firstAt = args.starts[args.args.indexOf(first)] ?? -1;
    if (firstAt < 0) return '';
    const list = first.startsWith('[') ? splitArgs(ctx.src, ctx.mask, firstAt) : null;
    const text = list && list.end + 1 === firstAt + first.length ? (list.args[0] ?? '') : first;
    return text.replace(/^\*\s*/, '');
  };
  const byKeyword = kwargs.some((k) => /^(?:args|executable)\s*=/.test(k));
  const flagInArgs = flagWritten(args.args.join(','));
  const words = (argv: Folded): { keepWords?: true } => (byKeyword || flagInArgs || !PLAIN_REFERENCE.test(programText()) || holdsCodeFlag(argv) ? { keepWords: true } : {});
  if (short === 'create_subprocess_exec') {
    const program = foldInScope(ctx, first, index);
    const rest = positional.slice(1).map((x) => foldInScope(ctx, x, index));
    const argv: Folded = { kind: 'array', elements: rest, dynamic: positional.slice(1).some((x) => x.startsWith('*')) };
    return { ...base, ...shapeOf(program, argv, false), toolInput, ...words(argv) };
  }
  const cmd = foldInScope(ctx, first, index);
  if (cmd.kind === 'array') {
    const program = cmd.elements[0] ?? { kind: 'unknown' };
    const argv: Folded = { kind: 'array', elements: cmd.elements.slice(1), dynamic: cmd.dynamic };
    return { ...base, ...shapeOf(cmd.dynamic && !cmd.elements.length ? { kind: 'unknown' } : program, argv, false), toolInput, ...words(argv) };
  }
  // A plain string without shell=True is the program name itself.
  const none: Folded = { kind: 'array', elements: [], dynamic: false };
  return { ...base, ...shapeOf(cmd, none, false), toolInput, ...words(none) };
}

function normalize(s: string): string {
  return s.replace(/\s+/g, ' ').trim().slice(0, 160);
}
