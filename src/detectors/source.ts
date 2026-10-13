/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 4b — Implementation-level analysis.
 *
 * Metadata detectors read what a server *claims*. This one reads what its code
 * *does*: when the server's source is available (a local package directory or an
 * extracted tarball), it scans for dangerous sinks — arbitrary execution, shell
 * spawning, hardcoded egress, obfuscated payloads, credential reads. Fully
 * deterministic; no LLM, no execution of the code.
 */

import { createHash } from 'node:crypto';
import type { CapabilityTag, Confidence, Detector, DetectorContext, Finding, Severity, SourceFile } from '../types.js';
import { SOURCE_PATTERNS, isNonRuntimePath, type SourcePattern } from '../data/sourcePatterns.js';
import { SECRET_PATTERNS } from '../data/injectionPatterns.js';
import { buildReachability, type Reach } from '../analysis/reachability.js';
import { scanProcessCalls, SHAPE_RANK, type CallShape, type ProcessCall } from '../analysis/callSites.js';
import { toolFlowOf } from '../analysis/toolFlow.js';
import { fileCtxOf, type FileCtx, type FnInfo } from '../util/fileCtx.js';
import { fold, isConst } from '../util/constFold.js';
import { CAPABILITY_NOTE } from '../scoring/model.js';
import { CODE, identOffsets, lineAt, lineStarts, splitArgs } from '../util/jsLex.js';
import {
  inlineSourceMap,
  isGeneratedScript,
  originalOffset,
  originalTextAt,
  parseSourceMap,
  resolvePositions,
  sourceInfoOf,
  sourceMapRefOf,
  type OriginalPosition,
  type SourceMapData,
} from '../util/sourceMap.js';
import {
  CODE_EXECUTION_LIBRARIES,
  STATIC_CODEGEN_PACKAGES,
  corroborated,
  matchVendoredSignature,
  vendoredNoteFor,
  type SignatureFile,
} from '../data/vendoredSignatures.js';

const MAX_FINDINGS_PER_RULE = 10; // don't drown the report on a big codebase

/** Threat rules assert something about the SERVER's runtime behaviour, so they
 *  are not raised from test/benchmark/example/release-tooling files. The
 *  capability rules still fire there — that code really is in the package.
 *  MTC-SRC-004 (obfuscated payload) is here too: a decode+exec blob in a test
 *  fixture or a vendored bundle is not the server's runtime behaviour. */
const RUNTIME_ONLY_RULES = new Set(['MTC-SRC-004', 'MTC-SRC-007', 'MTC-SRC-009', 'MTC-SRC-010']);

/** Capability-sink rules (arbitrary exec / shell / dynamic module load). The code
 *  really ships, so they fire even in packaging/dev/install tooling — but THERE
 *  they are downgraded: it is not the server's request-handling runtime, and an
 *  install-time shell is already surfaced by MTC-SUP-010 (`runs install scripts`).
 *  Firing them HIGH on a build/install script overstates them as a runtime threat. */
const CAPABILITY_SINK_RULES = new Set(['MTC-SRC-001', 'MTC-SRC-002', 'MTC-SRC-003', 'MTC-SRC-005', 'MTC-SRC-006']);

/** Rules whose match is suppressed when it sits INSIDE a string literal — the shape
 *  is DATA (a scanner's detection pattern / example / red-team fixture), not code.
 *  SRC-009 (assembled command), SRC-010 (dynamic eval), SRC-004 (obfuscated payload)
 *  and SRC-007 (unsafe deserialization) are all catalogued verbatim by security
 *  tooling, so a string-literal occurrence must not self-accuse. */
const STRING_GUARD_RULES = new Set(['MTC-SRC-004', 'MTC-SRC-007', 'MTC-SRC-009', 'MTC-SRC-010']);

/** `Function("m","return import(m)")` is the standard optional-dependency loader —
 *  it wraps a dynamic `import()` to bypass a bundler's static resolution, not to
 *  eval arbitrary code. Recognise it so MTC-SRC-001 does not raise a HIGH "dynamic
 *  code execution" on it; the dynamic import it contains is still reported by
 *  MTC-SRC-005 at medium/heuristic, so the signal is not lost, only right-sized. */
function isOptionalImportLoader(content: string, index: number): boolean {
  const win = content.slice(index, index + 120);
  const back = content.slice(Math.max(0, index - 200), index);
  // `eval(...)` branch (SRC-010): the only benign vendored eval idiom is the
  // WebAssembly/emscripten runtime's `eval(func)`, guarded by an ASM_CONSTS /
  // wasm-bindgen context. A genuine `eval(script)` in server code has none.
  if (/^eval\s*\(/.test(win)) return /\b(?:ASM_CONSTS|emscripten|wasm_bindgen|WebAssembly)\b/.test(back);
  if (!/^(?:new\s+)?Function\s*\(/.test(win)) return false;
  // The optional-dependency loader, `Function("m","return import(m)")`.
  if (/\breturn\s+import\s*\(/.test(win)) return true;
  // Benign, ubiquitous vendored idioms that are NOT arbitrary eval: the global-this
  // polyfill `Function("return this")()` (lodash/core-js), the empty `Function("")`
  // eval feature-probe (zod's `allowsEval`), and the `function-bind` polyfill
  // `Function("binder","return function(){…}")` (transitive via call-bind/es-abstract,
  // inlined into countless bundled `dist` files).
  if (/^(?:new\s+)?Function\s*\(\s*(['"`])\s*return\s+this\s*\1\s*\)/.test(win)) return true;
  if (/^(?:new\s+)?Function\s*\(\s*(['"`])\1\s*\)/.test(win)) return true;
  if (/^(?:new\s+)?Function\s*\(\s*(['"`])binder\1\s*,/.test(win)) return true;
  // Zod's `allowsEval` probe embedded in a GENERATED bundle as an ESCAPED empty
  // string — `new Function(\"\")` — where the backslash defeats the quote lookahead.
  if (/^(?:new\s+)?Function\s*\(\s*\\+(['"])\s*\\+\1\s*\)/.test(win)) return true;
  // wasm-bindgen generated glue: `new Function(getStringFromWasm0(ptr,len))`, and
  // any `new Function(...)` sitting inside a WebAssembly/emscripten runtime blob —
  // generated method-caller glue copied into `dist`, not the server's own eval.
  if (/^(?:new\s+)?Function\s*\(\s*getStringFromWasm0\b/.test(win)) return true;
  if (/\b(?:wasm_bindgen|WebAssembly|emscripten|getStringFromWasm|ASM_CONSTS)\b/.test(back)) return true;
  return false;
}

/** The dynamic-code rules whose sites can be attributed to a bundled dependency. */
const ATTRIBUTED_RULES = ['MTC-SRC-001', 'MTC-SRC-010'] as const;
/** Sites per file resolved through its source map (one pass over `mappings` for all of them). */
const MAX_ATTRIBUTED_SITES = 512;
/** Distinct dependencies reported per file and rule. */
const MAX_VENDORED_PER_FILE = 5;
/**
 * How far a site may sit after the start of the map segment that covers it:
 * indentation (esbuild starts a statement's segment at column 0) plus at most
 * this many other characters (the `$` of `$Function`).
 */
const SEGMENT_SLACK = 2;
/** Source-map text parsed per scan, all maps together. */
const MAX_MAP_BYTES_PER_SCAN = 64 * 1024 * 1024;

/** Where a dynamic-code site in a bundle came from, when it is a dependency's code. */
interface VendoredOrigin {
  package: string;
  version?: string;
  via: 'source-map' | 'signature';
  /** `<original path>:<line>` from the source map. */
  source?: string;
  /** The id of the `VENDORED_SIGNATURES` entry that matched. */
  signature?: string;
  /** The site is named but counts in full (not a vetted code generator). */
  discounted?: false;
  /** The dependency exists to run code it is handed. */
  codeExecutionLibrary?: true;
}

/**
 * The source maps of one scan, parsed at most once each. A sidecar map that more
 * than one generated file claims describes none of them (a map is the map of ONE
 * file) and is never read; parsing stops at a per-scan byte budget.
 */
class ScanMaps {
  private readonly parsed = new Map<string, SourceMapData | null>();
  private readonly claims = new Map<string, number>();
  private budget = MAX_MAP_BYTES_PER_SCAN;

  constructor(
    private readonly texts: ReadonlyMap<string, string>,
    files: readonly SourceFile[],
  ) {
    if (!texts.size) return;
    for (const f of files) {
      const ref = sourceMapRefOf(f.path, f.content, texts);
      if (ref && 'path' in ref) this.claims.set(ref.path, (this.claims.get(ref.path) ?? 0) + 1);
    }
  }

  mapFor(path: string, content: string): SourceMapData | null {
    const ref = sourceMapRefOf(path, content, this.texts);
    if (!ref) return null;
    if ('inline' in ref) return this.parse(`inline:${path}`, () => inlineSourceMap(ref.inline));
    if ((this.claims.get(ref.path) ?? 0) !== 1) return null;
    return this.parse(ref.path, () => this.texts.get(ref.path) ?? null);
  }

  private parse(key: string, text: () => string | null): SourceMapData | null {
    if (this.parsed.has(key)) return this.parsed.get(key)!;
    const t = text();
    let map: SourceMapData | null = null;
    if (t && t.length <= this.budget) {
      this.budget -= t.length;
      map = parseSourceMap(t);
    }
    this.parsed.set(key, map);
    return map;
  }
}

/** True when `pkg` is the server's own package, or another package of its own npm scope (its workspace). */
function isOwnPackage(pkg: string, ownName: string | undefined): boolean {
  if (!ownName) return false;
  if (pkg === ownName) return true;
  const scope = /^(@[^/]+)\//.exec(ownName)?.[1];
  return !!scope && pkg.startsWith(`${scope}/`);
}

/** Parameter names of a function (destructured locals included). */
function paramNames(fn: FnInfo | null): string[] {
  if (!fn) return [];
  return fn.params.flatMap((p) => [p.name, ...(p.keys ? [...p.keys.values()] : [])]).filter(Boolean);
}

/** Text with all whitespace removed, for comparing a call's head across formatting. */
const squash = (t: string): string => t.replace(/\s+/g, '');

/**
 * Dependency attribution for one file's MTC-SRC-001/010 sites (1.16). A single-
 * file `dist` bundle inlines its dependencies — Ajv's schema compiler arrives with
 * the MCP SDK — so a `new Function` in the bundle is often not the server's code.
 * Only generated JavaScript (`.js`/`.mjs`/`.cjs`) is ever attributed, and never a
 * site a decode-and-execute dropper (MTC-SRC-004) covers.
 *
 *   1. Source map. A site counts as mapped only when a segment STARTS at it (the
 *      map fits the file: no more lines than it has, segments inside the lines).
 *      Then the MAP DECIDES: a path that, normalized, is under `node_modules/` is
 *      that package's code (the store's real name wins over an npm alias); any
 *      other path — `src/…`, a pnpm `file+`/`link+` workspace store, a package of
 *      the server's own scope — is the server's, and no signature overrides it.
 *      When the map embeds `sourcesContent`, the original must show the same call
 *      at that position (and not be a copy of the bundle), else the map is stale
 *      and ignored. Only a vetted code generator ({@link STATIC_CODEGEN_PACKAGES})
 *      is DISCOUNTED — and when it has a call signature, that very call must
 *      show: in the embedded original, or, without one, at the generated site.
 *      Any other dependency is NAMED but counts in full; a code-execution
 *      library ({@link CODE_EXECUTION_LIBRARIES}) says so.
 *   2. No map that covers the site: a vetted code-generator signature
 *      ({@link matchVendoredSignature}), corroborated by the file being a bundle
 *      that carries the dependency's own identifying text.
 *
 * Lazy: nothing is parsed until a site needs it, and then every SRC-001/010 site
 * in the file is resolved in one linear pass.
 */
function vendorAttribution(
  f: SourceFile,
  path: string,
  fctx: FileCtx,
  maps: ScanMaps,
  ownName: string | undefined,
): (rule: string, index: number) => VendoredOrigin | null {
  if (!isGeneratedScript(path)) return () => null;
  const src = f.content;
  let starts: number[] | undefined;
  const lineStartOf = (i: number): number => {
    starts ??= lineStarts(src);
    return starts[lineAt(starts, i) - 1]!;
  };
  let sites: Map<number, OriginalPosition | null> | null | undefined;
  const resolve = (): Map<number, OriginalPosition | null> | null => {
    if (sites !== undefined) return sites;
    sites = null;
    const map = maps.mapFor(path, src);
    if (!map) return null;
    const at = new Set<number>();
    for (const id of ATTRIBUTED_RULES) {
      const p = SOURCE_PATTERNS.find((x) => x.id === id);
      if (!p) continue;
      for (const m of allMatches(src, p.pattern)) {
        if (at.size >= MAX_ATTRIBUTED_SITES) break;
        at.add(m.index);
      }
    }
    const idx = [...at].sort((a, b) => a - b);
    starts ??= lineStarts(src);
    const ls = starts;
    const file = {
      lineCount: ls.length,
      lineLength: (l: number): number => (l < 0 || l >= ls.length ? -1 : (l + 1 < ls.length ? ls[l + 1]! - 1 : src.length) - ls[l]!),
    };
    const res = resolvePositions(
      map,
      idx.map((i) => {
        const line = lineAt(ls, i) - 1;
        return { line, column: i - ls[line]! };
      }),
      file,
    );
    sites = new Map(idx.map((i, k) => [i, res[k] ?? null]));
    return sites;
  };
  let droppers: [number, number][] | undefined;
  const sig: SignatureFile = {
    src,
    mask: fctx.mask,
    paramsAt: (i) => paramNames(fctx.enclosingFn(i)),
    fnAt: (i) => fnRange(fctx.enclosingFn(i)),
    memo: new Map(),
  };
  // Signature evaluations per rule are capped; past the cap a site is not
  // attributed (fail closed), so the first such site is reported in full.
  const evaluations = new Map<string, number>();
  const budget = (rule: string): boolean => {
    const n = (evaluations.get(rule) ?? 0) + 1;
    evaluations.set(rule, n);
    return n <= MAX_ATTRIBUTED_SITES;
  };
  const signature = (rule: string, index: number): VendoredOrigin | null => {
    const s = matchVendoredSignature(sig, index, rule);
    return s && corroborated(s, sig) ? { package: s.package, via: 'signature', signature: s.id } : null;
  };

  return (rule, index) => {
    // A site a decode-and-execute dropper (MTC-SRC-004) covers is never attributed.
    if (!droppers) {
      droppers = [];
      const p004 = SOURCE_PATTERNS.find((x) => x.id === 'MTC-SRC-004');
      if (p004) for (const m of allMatches(src, p004.pattern)) if (droppers.push([m.index, m.index + m[0].length]) >= 64) break;
    }
    if (droppers.some(([a, b]) => index >= a && index < b)) return null;
    if (!budget(rule)) return null;

    const pos = resolve()?.get(index);
    const lineStart = lineStartOf(index);
    const segStart = lineStart + (pos?.generatedColumn ?? 0);
    if (pos && segStart <= index && index - segStart <= 256 && src.slice(segStart, index).trimStart().length <= SEGMENT_SLACK) {
      // The call as generated, from the segment to its `(`, must be the call the original shows.
      const paren = src.indexOf('(', index);
      const head = paren >= 0 && paren - index < 64 ? squash(src.slice(lineStart + pos.generatedColumn, paren + 1)) : '';
      const original = originalTextAt(pos);
      // An "original" that is the generated file itself describes nothing (checked once per source).
      if (head && (original === null || squash(original).startsWith(head)) && !isCopiedOriginal(pos, src)) {
        const info = sourceInfoOf(pos.map, pos.sourceIndex);
        const dep = info.dependency;
        if (!dep || isOwnPackage(dep.package, ownName)) return null; // the server's own code: the map decides
        const base = { package: dep.package, ...(dep.version ? { version: dep.version } : {}), via: 'source-map' as const, source: `${info.label}:${pos.line}` };
        if (CODE_EXECUTION_LIBRARIES.has(dep.package)) return { ...base, discounted: false, codeExecutionLibrary: true };
        if (!STATIC_CODEGEN_PACKAGES.has(dep.package)) return { ...base, discounted: false };
        // A vetted generator: its call signature must hold at the GENERATED site,
        // whatever the map says; an embedded original must show that call too.
        if (matchVendoredSignature(sig, index, rule, dep.package) && (original === null || originalShows(pos, rule, dep.package))) return base;
      }
      // A map that cannot vouch for this site (stale, copied, not the generator's
      // call): read the code instead.
    }
    return signature(rule, index);
  };
}

function fnRange(fn: FnInfo | null): { start: number; end: number } | null {
  return fn ? { start: fn.bodyStart, end: fn.bodyEnd } : null;
}

/** Whether a map's `sourcesContent` entry is the generated file itself — compared once per (map, source). */
const COPIED = new WeakMap<SourceMapData, Map<number, boolean>>();
function isCopiedOriginal(pos: OriginalPosition, src: string): boolean {
  let byIndex = COPIED.get(pos.map);
  if (!byIndex) COPIED.set(pos.map, (byIndex = new Map()));
  let hit = byIndex.get(pos.sourceIndex);
  if (hit === undefined) {
    hit = pos.map.sourcesContent[pos.sourceIndex] === src;
    byIndex.set(pos.sourceIndex, hit);
  }
  return hit;
}

/** A map's original source as a signature file, built once per (map, source). */
const ORIGINALS = new WeakMap<SourceMapData, Map<number, SignatureFile>>();
function originalFile(map: SourceMapData, index: number): SignatureFile | null {
  const content = map.sourcesContent[index];
  if (typeof content !== 'string') return null;
  let byIndex = ORIGINALS.get(map);
  if (!byIndex) ORIGINALS.set(map, (byIndex = new Map()));
  let file = byIndex.get(index);
  if (!file) {
    const ctx = fileCtxOf({ path: `original-${index}.js`, content });
    file = { src: content, mask: ctx.mask, paramsAt: (i) => paramNames(ctx.enclosingFn(i)), fnAt: (i) => fnRange(ctx.enclosingFn(i)), memo: new Map() };
    byIndex.set(index, file);
  }
  return file;
}

/** True when the ORIGINAL source a map traces the site to shows the generator's own call there. */
function originalShows(pos: OriginalPosition, rule: string, pkg: string): boolean {
  const file = originalFile(pos.map, pos.sourceIndex);
  let at = originalOffset(pos);
  if (!file || at === null) return false;
  while (at < file.src.length && /\s/.test(file.src[at]!)) at++;
  // Only the call's own shape: the one original module does not define the whole generator.
  for (let k = 0; k <= SEGMENT_SLACK; k++) if (matchVendoredSignature(file, at + k, rule, pkg, { local: true })) return true;
  return false;
}

/** True when the match sits INSIDE a quoted/backtick string literal on its line —
 *  an `eval(`/`exec(` that is string DATA (a security scanner's detection pattern,
 *  a remediation example, a red-team payload fixture), not executed code. Uses a
 *  detection-rule key hint plus the standard odd-unescaped-quotes test. */
function isInsideStringLiteral(content: string, index: number, file?: SourceFile): boolean {
  // Fast, high-precision hint: a `pattern:`/`example:`/`payload:` … key immediately
  // before a quote on the match's OWN line marks the value as detection/example DATA.
  let ls = index;
  while (ls > 0 && content[ls - 1] !== '\n') ls--;
  if (/\b(?:pattern|patterns|before|after|fix|example|examples|payload|sample|description|desc|label|rule|rules|title|message|msg|test|input|snippet|code|regex|match)s?\s*[:=]\s*['"`]/i.test(content.slice(ls, index)))
    return true;
  return stringStateAt(content, file)[index] === 1;
}

/**
 * The multi-line string-state lexer, run ONCE per file: a small lexer that tracks
 * '/"/backtick strings (with escapes), Python triple-quotes and JS template literals
 * ACROSS lines, skipping `//` and `/* *\/` comments so a quote inside a comment
 * cannot throw off the parity. `state[i] === 1` when offset i is inside a string.
 * (It used to re-scan from offset 0 for every candidate match — quadratic on a
 * large bundle, and the reason a 6 MB file could not be read at all.)
 */
const STRING_STATE = new WeakMap<object, Uint8Array>();
function stringStateAt(content: string, file?: SourceFile): Uint8Array {
  const key = file ?? null;
  if (key) {
    const hit = STRING_STATE.get(key);
    if (hit) return hit;
  }
  const n = content.length;
  const state = new Uint8Array(n + 1);
  let st: string | null = null; // '"' | "'" | '`' | '"""' | "'''"
  for (let i = 0; i < n; ) {
    state[i] = st === null ? 0 : 1;
    const c = content[i]!;
    if (st === null) {
      if ((c === '"' || c === "'") && content[i + 1] === c && content[i + 2] === c) { st = c + c + c; state[i + 1] = 1; state[i + 2] = 1; i += 3; continue; }
      if (c === '"' || c === "'" || c === '`') { st = c; i += 1; continue; }
      if (c === '/' && content[i + 1] === '/') { while (i < n && content[i] !== '\n') { state[i] = 0; i++; } continue; }
      if (c === '/' && content[i + 1] === '*') { state[i + 1] = 0; i += 2; while (i < n && !(content[i] === '*' && content[i + 1] === '/')) { state[i] = 0; i++; } if (i < n) state[i] = 0; if (i + 1 < n) state[i + 1] = 0; i += 2; continue; }
      i += 1;
    } else if (st.length === 3) {
      if (c === st[0] && content[i + 1] === st[0] && content[i + 2] === st[0]) { st = null; state[i + 1] = 1; state[i + 2] = 1; i += 3; continue; }
      i += 1;
    } else {
      if (c === '\\') { if (i + 1 < n) state[i + 1] = 1; i += 2; continue; }
      if (c === st) { st = null; i += 1; continue; }
      i += 1;
    }
  }
  state[n] = st === null ? 0 : 1;
  if (key) STRING_STATE.set(key, state);
  return state;
}

/** True when the match sits on a comment line (`//`, `*`, `/*`, `#`) — a lexical
 *  pattern that fires on a JSDoc/comment ("spawn (e.g. `'npx'`)") is documentation,
 *  not code, and must not raise a finding. */
function isCommentLine(content: string, index: number): boolean {
  let s = index;
  while (s > 0 && content[s - 1] !== '\n') s--;
  const prefix = content.slice(s, index).trimStart();
  return prefix.startsWith('//') || prefix.startsWith('*') || prefix.startsWith('/*') || prefix.startsWith('#');
}

/** `.exec(`/`.spawn(` on a NON-process receiver whose argument is a SQL statement
 *  is a database call (`db.exec(\`SELECT …\`)`), not command execution. Leading
 *  literal `\n`/`\r`/`\t` escapes (common in minified bundles) are tolerated so
 *  `db.exec(\`\nPRAGMA journal_mode=WAL\`)` is still recognised as SQL. */
// A SQL / GraphQL / Cypher statement as the first arg is a database/query call,
// not a shell command. Leading literal `\n`/`\r`/`\t` escapes (minified bundles)
// are tolerated so `db.exec(\`\nPRAGMA journal_mode=WAL\`)` still reads as SQL.
const SQL_ARG = /^(?:\\[nrt]|\s)*[(`'"]*(?:\\[nrt]|\s)*(?:--[^\n]*\n\s*)?(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|PRAGMA|BEGIN|COMMIT|ROLLBACK|WITH|REPLACE|VACUUM|ATTACH|DETACH|SAVEPOINT|RELEASE|ANALYZE|REINDEX|EXPLAIN|MUTATION|QUERY|SUBSCRIPTION|FRAGMENT|MATCH|MERGE|UNWIND)\b/i;
/** Receiver tokens whose `.exec()` runs SQL (a DB handle), never a shell. */
// Deliberately NOT conn/connection/session/client — ssh2's `conn.exec('rm -rf ~')`
// / `session.exec(cmd)` IS a real shell exec; the GraphQL/Cypher cases are covered
// by the query-keyword ARG test, not by receiver name.
const DB_RECEIVER = /(?:^|[.#])(?:sql|db|database|sqlite|stmt|statement|prepared?|pragma|d1|prisma|knex|drizzle)$/i;
/** A receiver whose `.exec()` is RegExp.prototype.exec (a match), not a shell. */
const REGEXP_RECEIVER = /(?:^|[.#])(?:[A-Z0-9_]{2,}|(?:re|rx|regexp?|pattern|matcher|expr)\w*)$/;
/** child_process aliases whose `.exec()` IS a shell — never skipped by the above. */
const CP_RECEIVER = /(?:^|[._])(?:child_?process|childprocess|cp|execa|shelljs|sh|proc|subprocess)$/i;
function isSqlExec(content: string, index: number): boolean {
  // (1) A regex-LITERAL receiver — `/pat/.exec(x)` — is a RegExp match, not a shell.
  if (content[index - 1] === '.' && content[index - 2] === '/') return true;
  // (2) Named receiver: a DB handle / query client (`sql.exec`, `this.#o.exec`,
  //     `session.exec`) or a RegExp-named const (`EMAIL_RE.exec`, `pattern.exec`)
  //     is not a shell — UNLESS the receiver is a child_process alias, which always
  //     wins so `cp.exec(...)` / `child_process_1.exec(...)` still fires.
  if (content[index - 1] === '.') {
    let j = index - 2;
    while (j >= 0 && /[\w$#]/.test(content[j]!)) j--;
    const recv = content.slice(j + 1, index - 1);
    if (CP_RECEIVER.test(recv)) return false;
    if (recv.startsWith('#') || DB_RECEIVER.test(recv) || REGEXP_RECEIVER.test(recv)) return true;
  }
  // (3) Argument: `db.exec(\`SELECT …\`)` is a SQL statement, not a shell command.
  const paren = content.indexOf('(', index);
  if (paren < 0) return false;
  return SQL_ARG.test(content.slice(paren + 1, paren + 90));
}

/** Iterate every match of a (possibly non-global) pattern so a benign first hit
 *  (a comment, a SQL string) cannot mask a real later one. */
function* allMatches(content: string, pattern: RegExp): Generator<RegExpExecArray> {
  const g = pattern.global ? pattern : new RegExp(pattern.source, pattern.flags + 'g');
  g.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = g.exec(content))) {
    yield m;
    if (m.index === g.lastIndex) g.lastIndex++;
  }
}

/** Declaration files (`*.d.ts`) carry TYPES only — no runtime code, so an
 *  `import { IOType } from 'node:child_process'` in a `.d.ts` is not execution. */
const DECLARATION_FILE = /\.d\.[cm]?ts$/i;

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line += 1;
  return line;
}

/** Secret patterns whose match is a genuine PRIVATE credential — a leak worth a
 *  confirmed high finding (and the confirmed-high grade gate). Google API keys
 *  (public-by-design client keys) and JWTs (routed by decoded role) are handled
 *  separately below and never default to `confirmed`. */
const CONFIRMED_SECRET_IDS = new Set(['aws-access-key', 'github-token', 'slack-token', 'stripe-secret', 'openai-key', 'private-key']);

/** Documentation/placeholder credential values — AWS's own canonical example keys,
 *  the jwt.io John-Doe token body, `xoxb-test-token`, sequential/all-x dummies. A
 *  match here is NOT a leaked secret. */
// AWS's documented example keys are matched by their ROOT (not the full ...EXAMPLE
// suffix) so bait variants like `AKIAIOSFODNN7FAKEXMP` (defense-mcp honeypot) are
// recognised as placeholders, not a live leak. These roots are the literal AWS
// docs prefixes — a real random key containing them is astronomically unlikely.
const KNOWN_PLACEHOLDER = /AKIAIOSFODNN7|AKIAI44QH8DHB|wJalrXUtnFEMI|bPxRfiCYEXAMPLEKEY|xoxb-test-token/i;
const PLACEHOLDER_BODY =
  /example|xxxx+|placeholder|dummy|redacted|changeme|deadbeef|notreal|your[-_]?(?:key|token|secret|api|id)|fake[-_]?(?:key|token|secret)|test[-_]?(?:token|key|secret)|1234567890|0123456789|abcdefghij|(?:[a-z]\d){6,}|[-_]here\b|\byour[-_][a-z0-9_-]*(?:token|key|secret|id)\b/i;

function looksLikePlaceholder(value: string): boolean {
  if (KNOWN_PLACEHOLDER.test(value)) return true;
  if (PLACEHOLDER_BODY.test(value)) return true;
  // A body that is a single repeated character is filler, never a real secret.
  const body = value.replace(/^[A-Za-z_-]+[-_]/, '');
  return /^(.)\1{7,}$/.test(body);
}

/** A file whose secret hits are CORROBORATED as test/fixture data, not a live leak:
 *  it assembles MULTIPLE distinct secret/PII shapes (a scanner's own vector corpus)
 *  OR carries an explicit fixture marker in the path / surrounding window. Used to
 *  downgrade SRC-008 to low/heuristic ONLY with such corroboration — never on a
 *  plain single embedded credential. */
const FIXTURE_MARKER = /\b(?:leak|demo|synthetic|fixture|writeCases|secretlint|gitleaks|detect-secrets|redact|sanitiz)\w*|Hardcoded secret|(^|\/)(?:test|tests|fixtures|__tests__|examples?|samples?)\//i;
function isCorroboratedFixture(path: string, content: string, index: number): boolean {
  const win = content.slice(Math.max(0, index - 200), index + 200);
  if (FIXTURE_MARKER.test(path) || FIXTURE_MARKER.test(win)) return true;
  // Multiple DISTINCT live-secret shapes clustered in one file = a vector corpus.
  let shapes = 0;
  for (const re of [/\bAKIA[0-9A-Z]{16}\b/, /\bgh[posru]_[0-9A-Za-z]{20,}/, /\bsk_live_[0-9A-Za-z]{16,}/, /\bxox[baprs]-[0-9A-Za-z-]{10,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./]) {
    if (re.test(content)) shapes++;
  }
  return shapes >= 3;
}

/** Base64URL-decode a JWT payload and JSON-parse it; null if not a decodable JWT. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split('.')[1];
  if (!part) return null;
  try {
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj: unknown = JSON.parse(json);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Classify a hardcoded-secret match into (severity, confidence, note), or null to
 *  suppress it (a placeholder / sample token that is not a real credential).
 *  Only genuine private credentials in runtime code get `confirmed` — the confidence
 *  the grade gate keys on — so example keys, public keys and test fixtures can no
 *  longer cap a reputable package at C/D. */
function classifySecret(
  id: string,
  value: string,
  win: string,
): { severity: Finding['severity']; confidence: Finding['confidence']; note: string } | null {
  if (looksLikePlaceholder(value)) return null;
  if (id === 'jwt') {
    const payload = decodeJwtPayload(value);
    const role = payload ? String(payload.role ?? '').toLowerCase() : '';
    const iss = payload ? String(payload.iss ?? '').toLowerCase() : '';
    if (payload && (String(payload.name) === 'John Doe' || String(payload.sub) === '1234567890')) return null; // sample token
    if (role === 'service_role')
      return { severity: 'high', confidence: 'confirmed', note: 'a Supabase service_role key (full-access credential)' };
    if (role === 'anon' || role === 'public' || role === 'authenticated' || iss === 'supabase')
      return { severity: 'low', confidence: 'heuristic', note: 'a public-by-design (anon/publishable) key — RLS, not secrecy, protects it' };
    return { severity: 'medium', confidence: 'heuristic', note: 'an embedded JSON Web Token (often an example or expired token)' };
  }
  if (id === 'google-api-key') {
    // Google API keys are designed to ship in clients (Firebase/Maps/CrUX),
    // restricted by referrer/quota — a leaked one is a hygiene note, not a gating leak.
    const firebase = /firebase|authDomain|VITE_[A-Z_]*FIREBASE|googleapis\.com/i.test(win);
    return {
      severity: 'low',
      confidence: 'heuristic',
      note: firebase ? 'a public Firebase/web API key' : 'a client API key (restricted by referrer/quota, not a private secret)',
    };
  }
  if (CONFIRMED_SECRET_IDS.has(id))
    return { severity: 'high', confidence: 'confirmed', note: 'a live-looking credential hardcoded in shipped code' };
  return { severity: 'high', confidence: 'strong', note: 'a hardcoded credential in shipped code' };
}

/** One candidate finding, collected before the per-rule cap is applied. */
interface Candidate {
  rule: string;
  file: string;
  index: number;
  reach: Reach;
  nonRuntime: boolean;
  /** Danger, for ordering: the call shape for SRC-002, the severity otherwise. */
  danger: number;
  /** A dependency's code bundled into the file (ordered after the server's own sites). */
  vendored?: boolean;
  finding: Finding;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const REACH_RANK = (r: Reach): number => (r === true ? 0 : r === 'unknown' ? 1 : 2);


/** Shape → severity, confidence, capability tag and the plain-language description of what the call does. */
const SHAPE_PROFILE: Record<CallShape | 'import-only', { severity: Severity; confidence: Confidence; tag: CapabilityTag | null }> = {
  'shell-dynamic': { severity: 'high', confidence: 'strong', tag: 'code-exec' },
  'dynamic-program': { severity: 'high', confidence: 'strong', tag: 'code-exec' },
  'fixed-program-dynamic-args': { severity: 'low', confidence: 'heuristic', tag: 'process-spawn' },
  'shell-fixed': { severity: 'low', confidence: 'strong', tag: 'process-spawn' },
  'fixed-program-fixed-args': { severity: 'info', confidence: 'strong', tag: null },
  'import-only': { severity: 'info', confidence: 'strong', tag: null },
};

function minSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b;
}

/** A stable identity for one location: rule + file + the normalized code at it (never the line number). */
export function findingFingerprint(rule: string, file: string, fragment: string): string {
  const norm = fragment.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${rule}|${file}|${norm}`).digest('hex');
}

/** Where a file sits, in words, for titles and descriptions. */
function placeOf(nonRuntime: boolean, reach: Reach): { where: string; suffix: string } {
  if (nonRuntime) return { where: 'a packaging/dev/install script (shipped, but not the server runtime)', suffix: 'in packaging/dev tooling' };
  if (reach === false) return { where: 'a non-server entry point (shipped in the package, but the MCP server does not import it — CLI / daemon / library code)', suffix: 'in a non-server entry point' };
  if (reach === true) return { where: "the MCP server's implementation", suffix: 'in server code' };
  return { where: "the package's implementation", suffix: 'in package code' };
}

const SHAPE_WORDS: Record<CallShape, string> = {
  'shell-dynamic': 'a shell runs a command line built at runtime',
  'dynamic-program': 'the program to run is chosen at runtime',
  'fixed-program-dynamic-args': 'a fixed program with runtime arguments, no shell',
  'shell-fixed': 'a shell runs a command line that is entirely literal',
  'fixed-program-fixed-args': 'a fixed program with fixed arguments',
};

function src002Title(worst: ProcessCall | null, path: string, suffix: string): string {
  if (!worst) return `Imports child_process; no call site found (${path})`;
  const prog = worst.program.length > 48 ? `${worst.program.slice(0, 45)}…` : worst.program;
  switch (worst.shape) {
    case 'shell-dynamic':
    case 'dynamic-program':
      return `Shell/command execution ${suffix} (${path})`;
    case 'fixed-program-dynamic-args':
      return `Spawns \`${prog}\` with runtime arguments, no shell, ${suffix} (${path})`;
    case 'shell-fixed':
      return `Runs a fixed shell command \`${prog}\` ${suffix} (${path})`;
    case 'fixed-program-fixed-args':
      return `Spawns \`${prog}\` with fixed arguments ${suffix} (${path})`;
  }
}

/** MTC-SRC-006: is this credential-file literal an element of a deny-list that is only ever membership-tested? */
function isProtectiveDenyList(ctx: FileCtx, index: number): boolean {
  const { src, mask } = ctx;
  // The string literal that holds the match.
  let i = index;
  while (i < src.length && mask[i] !== 1 && i < index + 4) i++;
  if (mask[i] !== 1) return false;
  let start = i;
  while (start > 0 && mask[start - 1] === 1) start--;
  // Nearest unmatched opening bracket before the literal.
  let depth = 0;
  let open = -1;
  for (let k = start - 1; k >= 0 && k > start - 20_000; k--) {
    if (mask[k] !== CODE) continue;
    const c = src[k]!;
    if (c === ')' || c === ']' || c === '}') depth++;
    else if (c === '(' || c === '[' || c === '{') {
      if (depth === 0) { open = k; break; }
      depth--;
    }
  }
  if (open < 0) return false;
  const before = src.slice(Math.max(0, open - 120), open);
  const decl =
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]{1,60})?=\s*(?:new\s+(?:Set|ReadonlySet)\s*(?:<[^>]*>)?\s*\(\s*|Object\.freeze\s*\(\s*)?$/.exec(before) ??
    /(?:^|\n)[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]{1,60})?=\s*(?:frozenset\s*\(\s*|set\s*\(\s*|tuple\s*\(\s*)?$/.exec(before);
  if (!decl) return false;
  const name = decl[1]!;
  const declAt = open - (before.length - decl.index) ;
  const uses = identOffsets(src, mask, name).filter((u) => u < declAt || u > open);
  if (!uses.length) return false;
  return uses.every((u) => {
    const after = src.slice(u + name.length, u + name.length + 24);
    const back = src.slice(Math.max(0, u - 12), u);
    const line = src.slice(src.lastIndexOf('\n', u) + 1, u);
    if (/\bfor\b[^;:]*\bin\s+$/.test(line) || /\bfor\s*\([^;)]*\bin\s+$/.test(line)) return false; // iteration, not a membership test
    return /^\s*\.\s*(?:has|includes|indexOf|__contains__)\s*\(/.test(after) || /\bin\s+$/.test(back) || /\bnot\s+in\s+$/.test(back);
  });
}

/** MTC-SRC-005: does this `require(x)` / `import(x)` load a constant — usually a file of the package itself? */
function loadsConstantModule(ctx: FileCtx, index: number): boolean {
  const open = ctx.src.indexOf('(', index);
  if (open < 0 || open > index + 20) return false;
  const args = splitArgs(ctx.src, ctx.mask, open);
  if (!args || args.args.length !== 1) return false;
  const v = fold(ctx, args.args[0]!, { at: index, pathContext: true });
  if (v.kind === 'own-path') {
    const parts: string[] = [];
    for (const seg of `${ctx.path.includes('/') ? ctx.path.slice(0, ctx.path.lastIndexOf('/')) : ''}/${v.value}`.split('/')) {
      if (!seg || seg === '.') continue;
      if (seg === '..') {
        if (!parts.length) return false; // climbs out of the package: not its own module
        parts.pop();
      } else parts.push(seg);
    }
    return true;
  }
  return v.kind === 'literal' && isConst(v) && !v.values.some((x) => /^(?:\/|[A-Za-z]:[\\/]|~)/.test(x));
}

/** Report order of the rules (pattern order, then secrets) — keeps output stable. */
function ruleIndex(rule: string): number {
  const i = SOURCE_PATTERNS.findIndex((p) => p.id === rule);
  return i >= 0 ? i : rule === 'MTC-SRC-008' ? SOURCE_PATTERNS.length : SOURCE_PATTERNS.length + 1;
}

/** A finding for a lexical pattern rule (everything but SRC-002 and SRC-008). */
function patternCandidate(
  p: SourcePattern,
  f: SourceFile,
  path: string,
  m: RegExpExecArray,
  nonRuntime: boolean,
  reach: Reach,
  entry: string | undefined,
): Candidate {
  const fctx = fileCtxOf(f);
  const line = fctx.line(m.index);
  const capabilityRule = CAPABILITY_SINK_RULES.has(p.id);
  // A capability sink in packaging/dev tooling, or in a file the MCP server does
  // not import, ships — but it is not the server's request-handling surface. It
  // is right-sized and flagged `nonRuntime` so the capability score skips it.
  // Reachability is evidence; a path name is a guess. A file the MCP server is
  // proven to load is server code even under `vendor/` or `scripts/`.
  const outside = capabilityRule && reach !== true && (nonRuntime || reach === false);
  const severity: Severity = outside ? minSeverity(p.severity, 'low') : p.severity;
  const confidence: Confidence = outside ? 'heuristic' : p.confidence;
  const place = placeOf(nonRuntime && capabilityRule && reach !== true, reach);
  const base = p.title.replace(/ in server code$/, '');
  const title = place.suffix === 'in server code' && p.title === base ? `${p.title} (${path})` : `${base} ${place.suffix} (${path})`;
  const evidence = f.content.slice(Math.max(0, m.index - 24), m.index + 96).replace(/\s+/g, ' ').trim().slice(0, 160);
  return {
    rule: p.id,
    file: path,
    index: m.index,
    reach,
    nonRuntime: outside || nonRuntime,
    danger: SEVERITY_RANK[severity],
    finding: {
      ruleId: p.id,
      title,
      category: p.category,
      severity,
      confidence,
      description:
        `In ${place.where} (\`${path}:${line}\`): ${p.why} ` +
        (reach === true && entry ? `Reachable from the MCP server via ${entry}. ` : '') +
        'This is read from the code itself — not from the tool description — so a poisoned server cannot hide it behind honest-looking metadata.' +
        (capabilityRule ? ` ${CAPABILITY_NOTE}` : ''),
      remediation:
        'Review this call path: confirm it never receives unsanitized tool input, constrain it, or remove it. ' +
        'Treat a server whose code reaches these sinks as high-capability regardless of what its tools claim.',
      location: { kind: 'server', name: path },
      // Evidence carries a little surrounding source, not the bare token, so the
      // claim is auditable ("why is this HIGH?") rather than an opaque `exec(`.
      evidence,
      owasp: p.category === 'exfiltration' ? 'LLM02:2025 Sensitive Information Disclosure' : 'LLM05:2025 Improper Output Handling',
      // `nonRuntime` lets the capability scorer skip tooling/unreachable findings so
      // the low/heuristic downgrade actually stops the -6/-10, not just relabels.
      data: {
        rule: p.id,
        file: path,
        line,
        nonRuntime: outside,
        reachable: reach,
        ...(reach === true && entry ? { entry } : {}),
        fingerprint: findingFingerprint(p.id, path, m[0] + f.content.slice(m.index + m[0].length, m.index + m[0].length + 60)),
      },
    },
  };
}

/**
 * MTC-SRC-001/010 at a site attributed to a bundled dependency: kept, so the
 * report says what is there, but `info`, with `capabilityTag: null` so it raises
 * no capability — the dependency's code generator is not the server evaluating
 * its input. The fingerprint is the one the same site always had.
 */
function vendoredCandidate(
  p: SourcePattern,
  f: SourceFile,
  path: string,
  m: RegExpExecArray,
  nonRuntime: boolean,
  reach: Reach,
  entry: string | undefined,
  origin: VendoredOrigin,
): Candidate {
  const c = patternCandidate(p, f, path, m, nonRuntime, reach, entry);
  const dep = origin.version ? `${origin.package}@${origin.version}` : origin.package;
  const line = fileCtxOf(f).line(m.index);
  const base = p.title.replace(/ in server code$/, '');
  const how =
    origin.via === 'source-map'
      ? `the package's source map traces this position to \`${origin.source}\`, inside the dependency`
      : `no source map covers this position, and the call matches ${origin.package}'s generated-code signature \`${origin.signature}\``;
  const note = vendoredNoteFor(origin.package);
  return {
    ...c,
    vendored: true,
    danger: SEVERITY_RANK.info,
    finding: {
      ...c.finding,
      title: `${base} in bundled dependency ${dep} (${path})`,
      severity: 'info',
      confidence: origin.via === 'source-map' ? 'strong' : 'heuristic',
      description:
        `In \`${path}:${line}\`, code bundled from the dependency ${dep}: ${how}. ` +
        (note ? `${note} ` : '') +
        "It is the dependency's code, not the server's implementation: it does not lower the trust grade, is not counted as the server's dynamic code execution, and does not raise the capability level. " +
        'Dynamic code the server itself contains is still reported at full severity.',
      remediation: 'Nothing to fix in the server. Keep the dependency current; ship the source map with the bundle so the attribution can be checked.',
      data: {
        ...c.finding.data,
        vendored: {
          package: origin.package,
          ...(origin.version ? { version: origin.version } : {}),
          via: origin.via,
          ...(origin.source ? { source: origin.source } : {}),
          ...(origin.signature ? { signature: origin.signature } : {}),
        },
        capabilityTag: null,
      },
    },
  };
}

/**
 * MTC-SRC-001/010 at a site a source map traces into a bundled dependency that is
 * NOT a vetted code generator: the dependency is named, but the finding keeps its
 * severity and capability — dependency code runs in the server process, and what
 * reaches it is the server's choice. A code-execution library (vm2, safe-eval, a
 * template engine…) says so.
 */
function namedCandidate(c: Candidate, p: SourcePattern, path: string, origin: VendoredOrigin): Candidate {
  const dep = origin.version ? `${origin.package}@${origin.version}` : origin.package;
  const base = p.title.replace(/ in server code$/, '');
  const library = origin.codeExecutionLibrary === true;
  return {
    ...c,
    finding: {
      ...c.finding,
      title: library ? `${base} in bundled code-execution library ${dep} (${path})` : `${base} in bundled dependency ${dep}, counted in full (${path})`,
      description:
        (library
          ? `The server bundles ${dep}, a library whose job is to run code it is handed at runtime; the package's source map traces this site to \`${origin.source}\`. `
          : `The package's source map traces this site to \`${origin.source}\`, in the bundled dependency ${dep}. Only vetted code generators that compile static definitions are discounted, so `) +
        (library ? 'It counts' : 'it counts') +
        " as the server's own dynamic code execution: dependency code runs in the server process, and what reaches it is decided by the server. " +
        c.finding.description,
      data: {
        ...c.finding.data,
        vendored: {
          package: origin.package,
          ...(origin.version ? { version: origin.version } : {}),
          via: 'source-map',
          ...(origin.source ? { source: origin.source } : {}),
          discounted: false,
          ...(library ? { codeExecutionLibrary: true } : {}),
        },
      },
    },
  };
}

/** MTC-SRC-002 for one file: the worst process call (or the bare import) and the reason. */
function processCandidate(
  fctx: FileCtx,
  f: SourceFile,
  path: string,
  nonRuntime: boolean,
  fileReach: Reach,
  entry: string | undefined,
  effReach: (index: number) => Reach = () => fileReach,
): Candidate | null {
  const scan = scanProcessCalls(fctx, toolFlowOf(fctx));
  if (!scan.calls.length && !scan.importsModule) return null;
  // Calls the server can run come first; then the most dangerous.
  const worst = [...scan.calls].sort((a, b) => REACH_RANK(effReach(a.index)) - REACH_RANK(effReach(b.index)) || SHAPE_RANK[b.shape] - SHAPE_RANK[a.shape] || a.index - b.index)[0] ?? null;
  const reach: Reach = worst ? effReach(worst.index) : fileReach;
  const shape: CallShape | 'import-only' = worst ? worst.shape : 'import-only';
  const profile = SHAPE_PROFILE[shape];
  let severity = profile.severity;
  let confidence = profile.confidence;
  // A fixed program whose argv visibly carries a tool's input: the model can
  // steer the arguments (an option-injection surface), still not the program.
  if (shape === 'fixed-program-dynamic-args' && worst?.toolInput) severity = 'medium';
  const outside = reach !== true && (nonRuntime || reach === false);
  if (outside) {
    severity = minSeverity(severity, 'low');
    if (severity !== 'info') confidence = 'heuristic';
  }
  const place = placeOf(nonRuntime && reach !== true, reach);
  const at = worst ? worst.index : Math.max(0, scan.importIndex);
  const line = fctx.line(at);
  const codeExec = shape === 'shell-dynamic' || shape === 'dynamic-program';

  let what: string;
  if (!worst) {
    what = `the file imports child_process, but no call to it was found (it may be unused, or re-exported).`;
  } else if (codeExec) {
    what =
      `\`${worst.method}(…)\` — ${SHAPE_WORDS[worst.shape]}. Spawning a process whose command line or program is decided at runtime ` +
      'is code execution: with unsanitized tool input it is command injection / RCE.';
  } else {
    what =
      `\`${worst.method}(…)\` spawns \`${worst.program}\` — ${SHAPE_WORDS[worst.shape]}. The program is fixed in the code, ` +
      'so this is a process-spawning capability, not arbitrary code execution.' +
      (worst.toolInput
        ? ` An argument visibly comes from a tool's input, so check it cannot smuggle options into \`${worst.program}\`.`
        : '');
  }
  const others = scan.calls.length > 1
    ? ` ${scan.calls.length} process calls in this file: ` +
      scan.calls
        .slice(0, 6)
        .map((c) => `:${c.line} ${c.shape} (${c.program.length > 32 ? `${c.program.slice(0, 29)}…` : c.program})`)
        .join('; ') +
      (scan.calls.length > 6 ? `; …${scan.calls.length - 6} more` : '') +
      '.'
    : '';
  const remediation = codeExec
    ? 'Pass a fixed program and an argv array instead of a shell string; never let tool input choose the program or the command line. ' +
      'If a shell is genuinely required, validate every value that reaches it.'
    : worst
      ? 'Nothing to fix by itself: the program is fixed. Keep the argv array (no shell), and validate any argument that comes from tool input so it cannot start with `-`.'
      : 'If the import is unused, drop it.';
  const evidence = worst
    ? worst.snippet
    : f.content.slice(at, at + 120).replace(/\s+/g, ' ').trim().slice(0, 160);
  return {
    rule: 'MTC-SRC-002',
    file: path,
    index: at,
    reach,
    nonRuntime: outside,
    danger: worst ? SHAPE_RANK[worst.shape] : 0,
    finding: {
      ruleId: 'MTC-SRC-002',
      title: src002Title(worst, path, place.suffix),
      category: 'permissions',
      severity,
      confidence,
      description:
        `In ${place.where} (\`${path}:${line}\`): ${what}${others} ` +
        (reach === true && entry ? `Reachable from the MCP server via ${entry}. ` : '') +
        `This is read from the code itself, not from the tool description. ${CAPABILITY_NOTE}`,
      remediation,
      location: { kind: 'server', name: path },
      evidence,
      owasp: 'LLM05:2025 Improper Output Handling',
      data: {
        rule: 'MTC-SRC-002',
        file: path,
        line,
        nonRuntime: outside,
        callShape: shape,
        reachable: reach,
        ...(reach === true && entry ? { entry } : {}),
        capabilityTag: profile.tag,
        toolInput: !!worst?.toolInput,
        calls: scan.calls.map((c) => ({ line: c.line, method: c.method, shape: c.shape, program: c.program, toolInput: c.toolInput })),
        fingerprint: findingFingerprint('MTC-SRC-002', path, evidence),
      },
    },
  };
}

export const sourceDetector: Detector = {
  id: 'source',
  stage: 4,
  title: 'Implementation-level source analysis',
  run(ctx: DetectorContext): Finding[] {
    const raw: SourceFile[] = Array.isArray(ctx.surface.sourceFiles) ? ctx.surface.sourceFiles : [];
    if (!raw.length) return [];
    // Process in a stable path order (code-unit, never locale) so the per-rule
    // finding cap keeps the SAME findings regardless of how the caller ordered
    // the files — the "same input ⇒ byte-identical report" promise must not
    // depend on filesystem or archive iteration order.
    const files = [...raw].sort((a, b) => {
      const x = typeof a?.path === 'string' ? a.path : '';
      const y = typeof b?.path === 'string' ? b.path : '';
      return x < y ? -1 : x > y ? 1 : 0;
    });
    const valid = files.filter((f): f is SourceFile => !!f && typeof f.content === 'string');
    // Which files the MCP server can actually reach (`unknown` when that cannot be decided).
    const reach = buildReachability(valid, ctx.surface.packageLayout);
    const candidates: Candidate[] = [];
    // Source maps the acquirer kept beside the generated files (attribution only).
    const maps = new Map<string, string>();
    for (const sm of Array.isArray(ctx.surface.sourceMaps) ? ctx.surface.sourceMaps : []) {
      if (sm && typeof sm.path === 'string' && typeof sm.content === 'string') maps.set(sm.path, sm.content);
    }
    const scanMaps = new ScanMaps(maps, valid);
    const ownName = typeof ctx.surface.packageMeta?.name === 'string' ? ctx.surface.packageMeta.name : undefined;

    for (const f of valid) {
      const path = typeof f.path === 'string' ? f.path : 'source';
      // Declaration files are types only — never runtime code. Skip them entirely.
      if (DECLARATION_FILE.test(path)) continue;
      const nonRuntime = isNonRuntimePath(path);
      const r: Reach = reach.reach(path);
      const fctx = fileCtxOf(f);
      // A file the server's entry loads statically at startup: its TOP-LEVEL code
      // runs in the server process, its functions only when something calls them.
      const startup = r === false && reach.loadsAtStartup(path);
      // A function defined there can still be handed to the server (a global, an
      // injected dependency), so a call inside one is `unknown`, never "unreachable".
      const effReach = (index: number): Reach => (startup ? (fctx.enclosingFn(index) === null ? true : 'unknown') : r);
      let vendorOf: ReturnType<typeof vendorAttribution> | undefined;

      for (const p of SOURCE_PATTERNS) {
        if (nonRuntime && RUNTIME_ONLY_RULES.has(p.id)) continue;
        if (p.id === 'MTC-SRC-002') continue; // decided per call site, below

        // Take the first REAL match — skipping comments/JSDoc, the optional-import
        // loader (SRC-001), SQL passed to a DB `.exec()` (SRC-009), an own-package
        // module path (SRC-005) and a protective deny-list (SRC-006) — so a benign
        // lexical hit can neither raise a finding nor mask a genuine later one.
        // A SRC-001/010 site in a bundled dependency is set aside the same way (and
        // reported separately, as the dependency's), so it cannot hide the server's own.
        let m: RegExpExecArray | undefined;
        let library: VendoredOrigin | undefined;
        const attributed = p.id === 'MTC-SRC-001' || p.id === 'MTC-SRC-010';
        const vendored = new Map<string, { m: RegExpExecArray; origin: VendoredOrigin }>();
        for (const cand of allMatches(f.content, p.pattern)) {
          if (cand.index === undefined) continue;
          if (isCommentLine(f.content, cand.index)) continue;
          if ((p.id === 'MTC-SRC-001' || p.id === 'MTC-SRC-010') && isOptionalImportLoader(f.content, cand.index)) continue;
          if (p.id === 'MTC-SRC-009' && isSqlExec(f.content, cand.index)) continue;
          if (STRING_GUARD_RULES.has(p.id) && isInsideStringLiteral(f.content, cand.index, f)) continue;
          if (p.id === 'MTC-SRC-005' && loadsConstantModule(fctx, cand.index)) continue;
          if (p.id === 'MTC-SRC-006' && isProtectiveDenyList(fctx, cand.index)) continue;
          if (attributed) {
            vendorOf ??= vendorAttribution(f, path, fctx, scanMaps, ownName);
            const origin = vendorOf(p.id, cand.index);
            // A dependency that is not a vetted code generator is named, but its site counts in full.
            if (origin?.discounted === false) library = origin;
            else if (origin) {
              if (!vendored.has(origin.package) && vendored.size < MAX_VENDORED_PER_FILE) vendored.set(origin.package, { m: cand, origin });
              continue;
            }
          }
          m = cand;
          break;
        }
        for (const v of vendored.values()) {
          candidates.push(vendoredCandidate(p, f, path, v.m, nonRuntime, effReach(v.m.index), reach.entryOf(path), v.origin));
        }
        if (!m || m.index === undefined) continue;
        const own = patternCandidate(p, f, path, m, nonRuntime, effReach(m.index), reach.entryOf(path));
        candidates.push(library ? namedCandidate(own, p, path, library) : own);
      }

      // MTC-SRC-002 — per call site, with the call's shape.
      if (/child_process|subprocess|\bos\.(?:system|popen)|create_subprocess|cross-spawn|['"]execa['"]|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/.test(f.content)) {
        const c = processCandidate(fctx, f, path, nonRuntime, r, reach.entryOf(path), effReach);
        if (c) candidates.push(c);
      }

      // Embedded credential VALUE hardcoded in source (not just referenced).
      for (const sp of SECRET_PATTERNS) {
        let hit: { m: RegExpExecArray; sev: Finding['severity']; conf: Finding['confidence']; note: string } | undefined;
        for (const cand of allMatches(f.content, sp.pattern)) {
          if (cand.index === undefined) continue;
          // A secret on a comment line, or a placeholder/sample/public-by-design
          // value, is not a leaked credential — skip and keep looking.
          if (isCommentLine(f.content, cand.index)) continue;
          const win = f.content.slice(Math.max(0, cand.index - 80), cand.index + 120);
          const cls = classifySecret(sp.id, cand[0]!, win);
          if (!cls) continue;
          let { severity, confidence } = cls;
          // A "secret" in test/benchmark/example/vendor/build code is a fixture,
          // not a runtime credential leak: cap it at low/heuristic so it can
          // neither trip the confirmed-high gate nor demote a band, and attribute
          // it honestly ("in test/example/packaging").
          if (nonRuntime) {
            severity = 'low';
            confidence = 'heuristic';
          } else if (confidence === 'confirmed' && isCorroboratedFixture(path, f.content, cand.index)) {
            // A confirmed live-secret shape sitting in a CORROBORATED fixture — a
            // scanner's own vector corpus, or a file marked leak/demo/fixture — is
            // test data, not a runtime leak. Downgrade so it cannot trip the gate.
            // (Requires corroboration; a plain single embedded credential stays confirmed.)
            severity = 'low';
            confidence = 'heuristic';
          }
          hit = { m: cand, sev: severity, conf: confidence, note: cls.note };
          break;
        }
        if (!hit) continue;
        const line = fctx.line(hit.m.index!);
        candidates.push({
          rule: 'MTC-SRC-008',
          file: path,
          index: hit.m.index!,
          reach: r,
          nonRuntime,
          danger: SEVERITY_RANK[hit.sev],
          finding: {
            ruleId: 'MTC-SRC-008',
            title: nonRuntime
              ? `Hardcoded ${sp.label} in test/example/packaging (${path})`
              : `Hardcoded ${sp.label} in server code (${path})`,
            category: 'exfiltration',
            severity: hit.sev,
            confidence: hit.conf,
            description:
              `A hardcoded ${sp.label} (${hit.note}) appears in \`${path}:${line}\`. ` +
              (hit.conf === 'confirmed'
                ? 'Secrets in source ship to everyone who installs the package and are a direct credential leak.'
                : 'Verify whether this is a real credential; if so, remove and rotate it.'),
            remediation: 'Remove the secret, rotate it, and load credentials from the environment or a secret store.',
            location: { kind: 'server', name: path },
            evidence: `${sp.label}: ${hit.m[0]!.slice(0, 4)}…(redacted)`,
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
            data: { secretType: sp.id, file: path, line, fingerprint: findingFingerprint('MTC-SRC-008', path, sp.id + hit.m[0]!.slice(0, 8)) },
          },
        });
        break; // one secret finding per file is enough
      }
    }

    // Apply the per-rule cap AFTER ordering: reachable from the MCP server first,
    // then the most dangerous, runtime before tooling, then path — so a capped
    // report shows what makes the server what it is, not the first ten files in
    // alphabetical order (which used to be CLI scraps, hiding the one call that
    // earned the capability level).
    const findings: Finding[] = [];
    const byRule = new Map<string, Candidate[]>();
    for (const c of candidates) {
      const list = byRule.get(c.rule) ?? [];
      list.push(c);
      byRule.set(c.rule, list);
    }
    const ruleOrder = [...byRule.keys()].sort((a, b) => ruleIndex(a) - ruleIndex(b) || (a < b ? -1 : a > b ? 1 : 0));
    for (const rule of ruleOrder) {
      const list = byRule.get(rule)!;
      list.sort(
        (a, b) =>
          Number(!!a.vendored) - Number(!!b.vendored) ||
          REACH_RANK(a.reach) - REACH_RANK(b.reach) ||
          b.danger - a.danger ||
          Number(a.nonRuntime) - Number(b.nonRuntime) ||
          (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
          a.index - b.index,
      );
      const kept = list.slice(0, MAX_FINDINGS_PER_RULE);
      const omitted = list.length - kept.length;
      for (const c of kept) findings.push(c.finding);
      if (omitted > 0) {
        const last = kept[kept.length - 1]!.finding;
        last.data = { ...(last.data ?? {}), omitted };
        last.description += ` …and ${omitted} more location${omitted === 1 ? '' : 's'} for this rule (the report keeps the ${MAX_FINDINGS_PER_RULE} most significant).`;
      }
    }

    // Compound: the server both ASSEMBLES shell commands from runtime values and
    // EVALUATES runtime values as code. Either alone is a precondition that
    // legitimate CLI wrappers and template engines routinely trip; together, in
    // runtime code, they are the dropper shape — an attacker who influences one
    // has a second primitive waiting. Scored on top of its parts, because the
    // combination carries information neither part does.
    const cmdFinding = findings.find((f) => f.ruleId === 'MTC-SRC-009');
    const evalFinding = findings.find((f) => f.ruleId === 'MTC-SRC-010');
    if (cmdFinding && evalFinding) {
      const cmdFile = (cmdFinding.data?.file as string | undefined) ?? undefined;
      const evalFile = (evalFinding.data?.file as string | undefined) ?? undefined;
      const sameFile = !!cmdFile && cmdFile === evalFile;
      findings.push({
        ruleId: 'MTC-SRC-011',
        title: 'Assembled command execution and dynamic evaluation in the same server',
        category: 'injection',
        severity: 'high',
        confidence: 'strong',
        description:
          `The implementation both builds shell commands out of runtime values (\`${cmdFile ?? 'command sink'}\`) ` +
          `and evaluates runtime values as code (\`${evalFile ?? 'eval sink'}\`). ` +
          'Each is a separate arbitrary-execution primitive; a server exposing both gives anything that reaches ' +
          'either one a direct path to running attacker-chosen code.' +
          (sameFile
            ? ''
            : ' These two sinks are in different files — confirm whether they are actually connected, or are unrelated code paths (e.g. a vendored bundle plus a CLI wrapper).'),
        remediation:
          'Remove the dynamic eval, and pass command arguments as an argv array instead of building a shell string. ' +
          'If both are genuinely required, constrain and validate every value that can reach them.',
        location: { kind: 'server', name: sameFile ? (cmdFile as string) : 'implementation' },
        owasp: 'LLM05:2025 Improper Output Handling',
        data: { rules: ['MTC-SRC-009', 'MTC-SRC-010'], commandFile: cmdFile, evalFile, sameFile },
      });
    }
    return findings;
  },
};
