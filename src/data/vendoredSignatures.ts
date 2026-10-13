/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Bundled third-party code that compiles code at runtime, as data:
 *
 *   - {@link STATIC_CODEGEN_PACKAGES}: dependencies whose dynamic code is a code
 *     GENERATOR fed by the program's own static definitions (schemas, wrappers).
 *   - {@link CODE_EXECUTION_LIBRARIES}: dependencies whose JOB is to run code
 *     handed to them at runtime. A site inside one of them is never discounted.
 *   - {@link VENDORED_SIGNATURES}: the exact call shapes of the generators, for a
 *     bundle with no usable source map — and, when a map embeds the original
 *     source, the shape that original must show for the map to be believed.
 *
 * Every name and shape is taken from the package's own published source (the
 * `origin` field names the file), never guessed. A signature pins the WHOLE call
 * and where each runtime value in it comes from: the argument shapes, the
 * invocation, and the provenance of every identifier that reaches the code or
 * the parameter list — an assignment chain, a helper's definition, or a caller
 * that only passes literals. A value that is a parameter of the enclosing
 * function, or comes from anywhere else, does not match. Provenance is read from
 * CODE only (comments are blanked, a match inside a string does not count), on
 * bounded windows; no pattern has nested or overlapping unbounded quantifiers.
 * Without a map a signature is CORROBORATED before it counts: the file must be a
 * bundle and carry the dependency's own identifying text elsewhere — a look-alike
 * in an author's small `src/*.js` is the author's code.
 *
 * Extend by adding an entry (and a fixture test taken from the real package).
 */

import { CODE, COMMENT, STRING, identOffsets, matchBracket, splitArgs } from '../util/jsLex.js';

/**
 * The code generators a site can be discounted for: exactly the packages with a
 * verified SITE signature below (ajv, depd, get-intrinsic). A source map alone
 * never discounts — the call at the generated site must be the generator's own.
 *
 * Checked and deliberately not listed: zod (its v4 JIT and `allowsEval` probe
 * call `new F(…)` through `const F = Function`, which MTC-SRC-001/010 never match;
 * a literal `Function("")` is already exempt), @sinclair/typebox
 * (`new globalThis.Function(...args)`, never matched), protobufjs and
 * @protobufjs/codegen (`Function(source)` / `Function.apply`, never matched),
 * function-bind (its `Function('binder', …)` wrapper is exempt before attribution),
 * fast-json-stringify (compiles whatever schema it is handed, which can be the
 * caller's — not a static definition), ajv-formats (no dynamic code).
 */
export const STATIC_CODEGEN_PACKAGES: ReadonlySet<string> = new Set(['ajv', 'depd', 'get-intrinsic']);

/**
 * Libraries that exist to run code they are handed at runtime (sandboxes,
 * evaluators, template engines that compile templates to functions, a DOM that
 * runs page scripts). A site a source map traces into one of these keeps its
 * full severity and capability: the server bundles a code-execution engine, and
 * what reaches it is the server's choice. Each was confirmed to contain dynamic
 * code in its published source (vm2 bridge/nodevm, safe-eval and eval/node-eval
 * vm.runIn*, ses FERAL_EVAL/FERAL_FUNCTION, @nyariv/sandboxjs's interpreter,
 * require-from-string Module._compile, static-eval / expr-eval / lodash template
 * / underscore template / doT / art-template / nunjucks / ejs / pug `Function`,
 * handlebars `Function.apply`, jsdom `vm.runInContext`). isolated-vm,
 * quickjs-emscripten and mathjs were checked and ship no JavaScript-level dynamic
 * code, so no site can ever be traced into them.
 */
export const CODE_EXECUTION_LIBRARIES: ReadonlySet<string> = new Set([
  'vm2',
  'safe-eval',
  'ses',
  '@nyariv/sandboxjs',
  'eval',
  'node-eval',
  'require-from-string',
  'static-eval',
  'expr-eval',
  'lodash',
  'lodash.template',
  'underscore',
  'handlebars',
  'ejs',
  'pug',
  'nunjucks',
  'dot',
  'art-template',
  'jsdom',
]);

/**
 * One argument: `re` is a regex SOURCE matched against the whole argument (code
 * only), where `{NAME}` is replaced by an already-bound identifier and a named
 * group `(?<NAME>…)` binds a new one; `concat` is a `+`-concatenation (or
 * template literal) of exactly these string pieces and bound identifiers.
 */
export type ArgSpec = { re: string } | { concat: ReadonlyArray<string | { bind: string }> };

/** Where a bound identifier must come from. Templates use the same `{NAME}` / `(?<NAME>…)` convention. */
export type Provenance =
  /**
   * The last assignment to NAME before the call is `NAME = <from>`; with `declared`
   * it is a `var`/`let`/`const` declaration (a local no outer closure can reach);
   * with `unique` it is the ONLY assignment to NAME in the enclosing function,
   * nested closures included.
   */
  | { assigned: string; from: string; within: number; declared?: boolean; unique?: boolean }
  /** Every `function NAME(…)` in the file matches one of `body` (anchored at `function`), and there is one. */
  | { definedAs: string; body: readonly string[] }
  /** The code right before the call matches this template (anchored at the call). */
  | { precededBy: string; within: number }
  /** Every use of NAME is its own definition or a call with one quoted literal matching `literal`. */
  | { literalCallsOnly: string; literal: RegExp }
  /**
   * The FILE is the generator's: each `defines` template matches in code, and
   * every code definition of `method` matches one of `bodies` — no other class
   * in the file implements it. Skipped when only an embedded original is read
   * (that one module does not define the whole generator).
   */
  | { fileDefines: readonly string[]; method: string; bodies: readonly string[] }
  /**
   * The constructor bound at the site (CTOR: `CodeGen` or `ns.CodeGen`) resolves,
   * in the same file, only to classes that define every `classHas` method body
   * themselves; none of `sealed` is overridden on them (prototype assignment,
   * class field, `this.<name> =`), and `sealedEverywhere` is not redefined
   * anywhere in the file by any means other than a method definition.
   */
  | { constructs: string; property: string; classHas: readonly string[]; sealed: readonly string[]; sealedEverywhere: readonly string[] };

export interface VendoredSignature {
  /** Stable id, reported in `data.vendored.signature`. */
  id: string;
  /** The npm package the code belongs to. */
  package: string;
  /** Where the shape comes from in the package's own source (for audit). */
  origin: string;
  /** Rules whose candidate this can attribute. */
  rules: readonly string[];
  /** Cheap pre-filter on the 400 characters at the finding's offset. */
  hint: RegExp;
  /** The callee at the finding's offset, up to and including its `(`. */
  callee: RegExp;
  args: readonly ArgSpec[];
  /** The compiled function's invocation: right after the call, or through the variable it is assigned to. */
  invoke: readonly ArgSpec[];
  provenance: readonly Provenance[];
  /** Bound names that must not be parameters of the enclosing function. */
  notParams: readonly string[];
  /** Text of the dependency's own that a bundle inlining it carries elsewhere (all of it), for corroboration. */
  identity: readonly string[];
  /** One sentence for the finding: why this generated code is not the server evaluating its input. */
  note: string;
}

const IDENT = String.raw`[A-Za-z_$][\w$]*`;
// Ajv's `names` import as a bundler spells it: `names_1.default`, `xn.default`, `names_default`.
const AJV_NAMES = String.raw`(?<N>[A-Za-z_$][\w$]*(?:\.default)?)`;
// The chain Ajv's compilers run right before `new Function`, contiguous — no call
// in between that could change the code (comments are blanked first):
//   const Z = gen.toString()
//   SRC = `${gen.scopeRefs(N.scope)}return ${Z}`
//   [ if (this.opts.code.process) SRC = this.opts.code.process(SRC, sch) ]
//   [ const makeValidate = ] new Function(…, SRC)
// and gen is the fresh `new CodeGen(this.scope, …)` of that same function.
const AJV_PROCESS = String.raw`(?:this\.opts\.code\.process\s*&&\s*\(\s*{SRC}\s*=\s*this\.opts\.code\.process\(\s*{SRC}\s*,\s*${IDENT}\s*\)\s*\)|if\s*\(\s*this\.opts\.code\.process\s*\)\s*{SRC}\s*=\s*this\.opts\.code\.process\(\s*{SRC}\s*,\s*${IDENT}\s*\))`;
const AJV_CHAIN: readonly Provenance[] = [
  {
    precededBy:
      String.raw`(?<![\w$.])(?:const|let|var)\s+(?<Z>${IDENT})\s*=\s*(?<G>${IDENT})\.toString\(\s*\)\s*(?:;\s*)?` +
      String.raw`(?<![\w$.]){SRC}\s*=\s*\x60\$\{\s*\k<G>\.scopeRefs\(\s*{N}\.scope\s*\)\s*\}return \$\{\s*\k<Z>\s*\}\x60\s*(?:[,;]\s*)?` +
      String.raw`(?:${AJV_PROCESS}\s*(?:;\s*)?)?(?:(?:const|let|var)\s+${IDENT}\s*=\s*)?$`,
    within: 1500,
  },
  { assigned: 'G', from: String.raw`new\s+(?<CTOR>(?:${IDENT}\.)?CodeGen)\s*\(\s*this\.scope\b`, within: 6000, unique: true },
  // …and that CodeGen is Ajv's: the file defines CodeGen.toString (renders its
  // tree) and CodeGen.scopeRefs (delegates to the external scope), and every
  // `scopeRefs` method in it is one of Ajv's two (CodeGen's, ValueScope's).
  {
    fileDefines: [
      String.raw`(?<![\w$.])toString\s*\(\s*\)\s*\{\s*return\s+this\._root\.render\(\s*this\.opts\s*\)`,
      String.raw`(?<![\w$.])scopeRefs\s*\(\s*(?<A>${IDENT})\s*\)\s*\{\s*return\s+this\._extScope\.scopeRefs\(\s*\k<A>\s*,\s*this\._values\s*\)`,
    ],
    method: 'scopeRefs',
    bodies: [
      String.raw`scopeRefs\s*\(\s*(?<A>${IDENT})\s*\)\s*\{\s*return\s+this\._extScope\.scopeRefs\(\s*\k<A>\s*,\s*this\._values\s*\)`,
      String.raw`scopeRefs\s*\(\s*${IDENT}\s*,\s*(?<V>${IDENT})\s*=\s*this\._values\s*\)\s*\{\s*return\s+this\._reduceValues\(\s*\k<V>\s*,`,
    ],
  },
  // …and the `new CodeGen(…)` at the site IS that class: every class the file binds
  // to the name (`class CodeGen`, `CodeGen = class`, `exports.CodeGen = Vg`,
  // `CodeGen: () => X`) defines Ajv's toString and scopeRefs itself, and nothing
  // replaces them afterwards (`X.prototype.scopeRefs = …`, a `scopeRefs = () => …` field).
  {
    constructs: 'CTOR',
    property: 'CodeGen',
    classHas: [
      String.raw`(?<![\w$.])toString\s*\(\s*\)\s*\{\s*return\s+this\._root\.render\(\s*this\.opts\s*\)`,
      String.raw`(?<![\w$.])scopeRefs\s*\(\s*(?<A>${IDENT})\s*\)\s*\{\s*return\s+this\._extScope\.scopeRefs\(\s*\k<A>\s*,\s*this\._values\s*\)`,
    ],
    sealed: ['scopeRefs', 'toString', 'render'],
    sealedEverywhere: ['scopeRefs'],
  },
];
// Strings every Ajv build carries (CodeGen's scopeRefs, two fixed error messages).
const AJV_IDENTITY = ['this._extScope.scopeRefs(', 'schema with key or id ', 'strict mode: '];

const DEPD_LOOP = String.raw`for\s*\(\s*var\s+(?<I>${IDENT})\s*=\s*0\s*;\s*\k<I>\s*<\s*\k<P>\s*;\s*\k<I>\s*\+\+\s*\)`;
const DEPD_ADD = String.raw`\k<S>\s*\+=\s*(?<R>['"]), arg\k<R>\s*\+\s*\k<I>`;
const DEPD_ARGS_HELPER: readonly string[] = [
  // depd's source and an unminified bundle.
  String.raw`function\s+{F}\s*\(\s*(?<P>${IDENT})\s*\)\s*\{\s*var\s+(?<S>${IDENT})\s*=\s*(?<Q>['"])\k<Q>\s*(?:;\s*)?${DEPD_LOOP}\s*\{\s*${DEPD_ADD}\s*(?:;\s*)?\}\s*return\s+\k<S>\.substr\(\s*2\s*\)\s*(?:;\s*)?\}`,
  // Minified: function hve(t){for(var e="",r=0;r<t;r++)e+=", arg"+r;return e.substr(2)}
  String.raw`function\s+{F}\s*\(\s*(?<P>${IDENT})\s*\)\s*\{\s*for\s*\(\s*var\s+(?<S>${IDENT})\s*=\s*(?<Q>['"])\k<Q>\s*,\s*(?<I>${IDENT})\s*=\s*0\s*;\s*\k<I>\s*<\s*\k<P>\s*;\s*\k<I>\s*\+\+\s*\)\s*${DEPD_ADD}\s*;\s*return\s+\k<S>\.substr\(\s*2\s*\)\s*(?:;\s*)?\}`,
];

export const VENDORED_SIGNATURES: readonly VendoredSignature[] = [
  {
    id: 'ajv-compile',
    package: 'ajv',
    origin:
      'ajv/lib/compile/index.ts (compileSchema): gen = new CodeGen(this.scope, …); validateCode = gen.toString(); sourceCode = `${gen.scopeRefs(N.scope)}return ${validateCode}`; new Function(`${N.self}`, `${N.scope}`, sourceCode) → makeValidate(this, this.scope.get())',
    rules: ['MTC-SRC-001', 'MTC-SRC-010'],
    hint: /\.self\s*\}`/,
    callee: /^new\s+Function\s*\(/,
    args: [{ re: String.raw`\x60\$\{\s*${AJV_NAMES}\.self\s*\}\x60` }, { re: String.raw`\x60\$\{\s*{N}\.scope\s*\}\x60` }, { re: `(?<SRC>${IDENT})` }],
    invoke: [{ re: 'this' }, { re: String.raw`this\.scope\.get\(\s*\)` }],
    provenance: AJV_CHAIN,
    notParams: ['N', 'SRC', 'Z', 'G'],
    identity: AJV_IDENTITY,
    note: "Ajv compiles JSON-schema validators from the server's own static schemas (the MCP SDK validates tool input and output with it); a tool call's arguments are validated as data and never become code.",
  },
  {
    id: 'ajv-jtd-compile',
    package: 'ajv',
    origin:
      'ajv/lib/compile/jtd/serialize.ts and parse.ts: the same chain, then new Function(`${N.scope}`, sourceCode) → makeSerialize/makeParse(this.scope.get())',
    rules: ['MTC-SRC-001', 'MTC-SRC-010'],
    hint: /\.scope\s*\}`\s*,/,
    callee: /^new\s+Function\s*\(/,
    args: [{ re: String.raw`\x60\$\{\s*${AJV_NAMES}\.scope\s*\}\x60` }, { re: `(?<SRC>${IDENT})` }],
    invoke: [{ re: String.raw`this\.scope\.get\(\s*\)` }],
    provenance: AJV_CHAIN,
    notParams: ['N', 'SRC', 'Z', 'G'],
    identity: AJV_IDENTITY,
    note: "Ajv's JTD compiler builds serializers/parsers from the server's own static schemas; the data it later processes is never compiled.",
  },
  {
    // Arrives through express/body-parser (the SDK's HTTP transport). The body is
    // fixed text — minified to a template literal, or string concatenation — with
    // ONE dynamic part, the parameter list, built from the wrapped function's arity.
    id: 'depd-wrapfunction',
    package: 'depd',
    origin:
      "depd/index.js (wrapfunction): var args = createArgumentsString(fn.length) … new Function('fn', 'log', 'deprecate', 'message', 'site', '\"use strict\"\\n' + 'return function (' + args + ') {' + 'log.call(deprecate, message, site)\\n' + 'return fn.apply(this, arguments)\\n' + '}')(fn, log, this, message, site)",
    rules: ['MTC-SRC-001', 'MTC-SRC-010'],
    hint: /['"]deprecate['"]/,
    callee: /^new\s+Function\s*\(/,
    args: [
      { concat: ['fn'] },
      { concat: ['log'] },
      { concat: ['deprecate'] },
      { concat: ['message'] },
      { concat: ['site'] },
      {
        concat: [
          '"use strict"\nreturn function (',
          { bind: 'ARGS' },
          ') {log.call(deprecate, message, site)\nreturn fn.apply(this, arguments)\n}',
        ],
      },
    ],
    invoke: [{ re: `(?<FN>${IDENT})` }, { re: IDENT }, { re: 'this' }, { re: IDENT }, { re: IDENT }],
    provenance: [
      // var args = createArgumentsString(fn.length) — a local, assigned once.
      { assigned: 'ARGS', from: String.raw`(?<F>${IDENT})\(\s*{FN}\.length\s*\)`, within: 400, declared: true, unique: true },
      // function createArgumentsString(arity) { var str = ''; for (var i = 0; i < arity; i++) str += ', arg' + i; return str.substr(2) }
      // — exactly that loop, so the list is `arg0, arg1, …` whatever `fn.length` holds.
      { definedAs: 'F', body: DEPD_ARGS_HELPER },
    ],
    notParams: ['ARGS'],
    identity: ['argument fn must be a function', 'argument namespace is required'],
    note: "depd wraps a deprecated function in a generated pass-through whose only dynamic part is its parameter list, built from the wrapped function's arity (`arg0, arg1, …`); no input reaches it.",
  },
  {
    // Also via express (side-channel → call-bound → get-intrinsic). The finding sits
    // on `Function` of `$Function(…)`; a minifier that renames `$Function` leaves no
    // `Function` token at all, so only the unminified spelling occurs.
    id: 'get-intrinsic-evalled-constructor',
    package: 'get-intrinsic',
    origin:
      "get-intrinsic/index.js: var getEvalledConstructor = function (expressionSyntax) { try { return $Function('\"use strict\"; return (' + expressionSyntax + ').constructor;')(); } catch (e) {} }, called only as getEvalledConstructor('async function () {}') and the like",
    rules: ['MTC-SRC-001'],
    hint: /use strict"; return \(/,
    callee: /^Function\s*\(/,
    args: [{ concat: ['"use strict"; return (', { bind: 'EXPR' }, ').constructor;'] }],
    invoke: [],
    provenance: [
      // EXPR is the sole parameter of the function the call sits in, right at its top…
      {
        precededBy: String.raw`(?<![\w$.])(?<NAME>${IDENT})\s*=\s*function\s*(?:${IDENT}\s*)?\(\s*{EXPR}\s*\)\s*\{\s*try\s*\{\s*return\s+\$$`,
        within: 200,
      },
      // …and that function is only ever called with a quoted function expression.
      { literalCallsOnly: 'NAME', literal: /^(?:async\s+)?function\s*\*?\s*\(\s*\)\s*\{\s*\}$/ },
    ],
    notParams: [],
    identity: ['intrinsic name must be a non-empty string', '%AsyncFunction%'],
    note: "get-intrinsic probes for the async/generator function constructors by compiling a fixed function expression (`async function () {}` and the like, literals at its only call sites); no input reaches it.",
  },
];

// --- matcher -------------------------------------------------------------------

/** How far after the call a separately invoked compiled function may be called. */
const INVOKE_WITHIN = 400;
/** Uses of a `literalCallsOnly` function examined before giving up. */
const MAX_USES = 64;

type Bindings = Map<string, string>;

/** A per-file view: the source and its lexical mask (CODE / STRING / COMMENT / REGEX). */
export interface SignatureFile {
  src: string;
  mask: Uint8Array;
  /** Names of the parameters of the function enclosing `index` (empty at top level). */
  paramsAt: (index: number) => readonly string[];
  /** The body range of the function enclosing `index`, or null at top level. */
  fnAt: (index: number) => { start: number; end: number } | null;
  /** Per-file results (helper definitions, call sites, assignment counts, file pins), computed once. */
  memo: Map<string, unknown>;
}

function memo<T>(f: SignatureFile, key: string, compute: () => T): T {
  if (f.memo.has(key)) return f.memo.get(key) as T;
  const v = compute();
  f.memo.set(key, v);
  return v;
}

/** Distinct whole-file scans (a helper's definitions, a function's call sites) per file. */
const MAX_FILE_SCANS = 16;

/**
 * A memoised check that reads the whole file. Each distinct one runs once; past
 * {@link MAX_FILE_SCANS} distinct ones the answer is "no" (fail closed) — a real
 * bundle carries a handful of generator copies, never thousands.
 */
function fileScan(f: SignatureFile, key: string, compute: () => boolean): boolean {
  if (f.memo.has(key)) return f.memo.get(key) as boolean;
  const n = ((f.memo.get('\u0000scans') as number | undefined) ?? 0) + 1;
  f.memo.set('\u0000scans', n);
  const v = n <= MAX_FILE_SCANS && compute();
  f.memo.set(key, v);
  return v;
}

/** `src[from, to)` with comments blanked to spaces, offsets preserved. */
function codeView(f: SignatureFile, from: number, to: number): string {
  const a = Math.max(0, from);
  const b = Math.min(f.src.length, to);
  let out = '';
  let run = a;
  for (let i = a; i < b; ) {
    if (f.mask[i] !== COMMENT) {
      i++;
      continue;
    }
    let j = i;
    while (j < b && f.mask[j] === COMMENT) j++;
    out += f.src.slice(run, i) + ' '.repeat(j - i);
    run = i = j;
  }
  return out + f.src.slice(run, b);
}

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Compile a template: `{NAME}` → the bound value; an unbound placeholder fails. */
function compile(template: string, b: Bindings, flags = ''): RegExp | null {
  let missing = false;
  const source = template.replace(/\{([A-Z][A-Z0-9]*)\}/g, (_, name: string) => {
    const v = b.get(name);
    if (v === undefined) missing = true;
    return v === undefined ? '' : esc(v);
  });
  if (missing) return null;
  try {
    return new RegExp(source, flags);
  } catch {
    return null;
  }
}

/** Bind a match's named groups; an already-bound name must agree. */
function bind(m: RegExpExecArray, b: Bindings): boolean {
  for (const [k, v] of Object.entries(m.groups ?? {})) {
    if (v === undefined) continue;
    const had = b.get(k);
    if (had !== undefined && had !== v) return false;
    b.set(k, v);
  }
  return true;
}

/**
 * A `+`-concatenation of string/template literals and bare identifiers, as its
 * pieces (literals unescaped). Null for anything else: a call, a member access,
 * an interpolation that is not a bare identifier, an escape it does not know.
 */
export function concatPieces(text: string): (string | { id: string })[] | null {
  const out: (string | { id: string })[] = [];
  let i = 0;
  const n = text.length;
  const ws = (): void => {
    while (i < n && /\s/.test(text[i]!)) i++;
  };
  const unescape = (c: string): string | null =>
    c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c === '\\' || c === "'" || c === '"' || c === '`' ? c : c === '\n' ? '' : null;
  for (;;) {
    ws();
    const q = text[i];
    if (q === "'" || q === '"' || q === '`') {
      let s = '';
      i++;
      for (;;) {
        if (i >= n) return null;
        const c = text[i]!;
        if (c === q) {
          i++;
          break;
        }
        if (c === '\\') {
          const u = unescape(text[i + 1] ?? '');
          if (u === null) return null;
          s += u;
          i += 2;
          continue;
        }
        if (q === '`' && c === '$' && text[i + 1] === '{') {
          const close = text.indexOf('}', i + 2);
          if (close < 0) return null;
          const id = text.slice(i + 2, close).trim();
          if (!new RegExp(`^${IDENT}$`).test(id)) return null;
          if (s) out.push(s);
          out.push({ id });
          s = '';
          i = close + 1;
          continue;
        }
        if (q !== '`' && c === '\n') return null;
        s += c;
        i++;
      }
      if (s || q !== '`') out.push(s);
    } else {
      const m = new RegExp(`^${IDENT}`).exec(text.slice(i, i + 256));
      if (!m) return null;
      out.push({ id: m[0] });
      i += m[0].length;
    }
    ws();
    if (i >= n) break;
    if (text[i] !== '+') return null;
    i++;
  }
  // Adjacent literals read as one.
  const merged: (string | { id: string })[] = [];
  for (const p of out) {
    const last = merged[merged.length - 1];
    if (typeof p === 'string' && typeof last === 'string') merged[merged.length - 1] = last + p;
    else merged.push(p);
  }
  return merged.filter((p) => p !== '');
}

function argMatches(spec: ArgSpec, text: string, b: Bindings): boolean {
  if ('re' in spec) {
    const re = compile(`^(?:${spec.re})$`, b);
    const m = re?.exec(text.trim());
    return !!m && bind(m, b);
  }
  const pieces = concatPieces(text);
  if (!pieces || pieces.length !== spec.concat.length) return false;
  return spec.concat.every((want, k) => {
    const got = pieces[k]!;
    if (typeof want === 'string') return typeof got === 'string' && got === want;
    if (typeof got === 'string') return false;
    const had = b.get(want.bind);
    if (had !== undefined) return had === got.id;
    b.set(want.bind, got.id);
    return true;
  });
}

/** The argument texts of the call whose `(` is at `open`, comments blanked. */
function argsAt(f: SignatureFile, open: number): { args: string[]; end: number } | null {
  const list = splitArgs(f.src, f.mask, open);
  if (!list) return null;
  const view = codeView(f, open, list.end + 1);
  return { args: list.args.map((t, k) => view.slice(list.starts[k]! - open, list.starts[k]! - open + t.length).trim()), end: list.end };
}

function argsMatch(specs: readonly ArgSpec[], args: string[], b: Bindings): boolean {
  return specs.length === args.length && specs.every((s, k) => argMatches(s, args[k]!, b));
}

/** Code assignments to `name` in `[from, to)`: `name = …`, `name += …`, `name++` and the like. */
function assignments(f: SignatureFile, name: string, from: number, to: number): { op: string; at: number; rhs: number }[] {
  const view = codeView(f, from, to);
  const re = new RegExp(String.raw`(?<![\w$.])${esc(name)}\s*(?:((?:\*\*|<<|>>>?|&&|\|\||\?\?|[-+*/%&|^])?)=(?![=>])|(\+\+|--))`, 'g');
  const out: { op: string; at: number; rhs: number }[] = [];
  for (let m = re.exec(view); m; m = re.exec(view)) {
    const at = Math.max(0, from) + m.index;
    if (f.mask[at] === CODE) out.push({ op: m[1] ?? m[2] ?? '', at, rhs: at + m[0].length });
  }
  return out;
}

function rhsMatches(f: SignatureFile, rhs: number, template: string, b: Bindings): boolean {
  const re = compile(String.raw`^\s*(?:${template})`, b);
  const m = re?.exec(codeView(f, rhs, rhs + 600));
  return !!m && bind(m, b);
}

function provenanceHolds(f: SignatureFile, p: Provenance, index: number, b: Bindings): boolean {
  if ('assigned' in p) {
    const name = b.get(p.assigned);
    if (!name) return false;
    const list = assignments(f, name, index - p.within, index);
    const last = list[list.length - 1];
    if (!last || last.op || !rhsMatches(f, last.rhs, p.from, b)) return false;
    if (p.declared && !/(?:^|[^\w$.])(?:var|let|const)\s+$/.test(codeView(f, last.at - 16, last.at))) return false;
    if (p.unique) {
      // No other write to NAME anywhere in the enclosing function — before or after
      // the call, in a nested closure included. One index per function, built once.
      const fn = f.fnAt(index);
      if (!fn || (assignmentCounts(f, fn).get(name) ?? 0) !== 1) return false;
    }
    return true;
  }
  if ('definedAs' in p) {
    const name = b.get(p.definedAs);
    if (!name) return false;
    return fileScan(f, `def\u0000${name}\u0000${p.body.join('\u0000')}`, () => {
      const bodies = p.body.map((t) => compile(`^(?:${t})`, b));
      if (bodies.some((re) => !re)) return false;
      const head = new RegExp(String.raw`(?<![\w$.])function\s+${esc(name)}\s*\(`, 'g');
      let seen = 0;
      for (let m = head.exec(f.src); m; m = head.exec(f.src)) {
        if (f.mask[m.index] !== CODE) continue;
        if (++seen > MAX_USES) return false;
        const view = codeView(f, m.index, m.index + 400);
        if (!bodies.some((re) => re!.test(view))) return false;
      }
      return seen > 0;
    });
  }
  if ('fileDefines' in p) return memo(f, `file\u0000${p.fileDefines.join('\u0000')}`, () => fileDefines(f, p));
  if ('constructs' in p) {
    const ctor = b.get(p.constructs);
    if (!ctor) return false;
    // A namespaced constructor resolves the same everywhere in the file; a bare one where it is used.
    const scope = ctor.includes('.') ? '' : `${f.fnAt(index)?.start ?? -1}`;
    return fileScan(f, `ctor\u0000${ctor}\u0000${p.property}\u0000${scope}`, () => constructsGenuine(f, ctor, index, p));
  }
  if ('precededBy' in p) {
    const from = Math.max(0, index - p.within);
    const re = compile(p.precededBy, b);
    const m = re?.exec(codeView(f, from, index));
    return !!m && f.mask[from + m.index] === CODE && bind(m, b);
  }
  const name = b.get(p.literalCallsOnly);
  if (!name) return false;
  return fileScan(f, `lit\u0000${name}\u0000${p.literal.source}`, () => {
    const uses = identOffsets(f.src, f.mask, name);
    if (!uses.length || uses.length > MAX_USES) return false;
    return uses.every((u) => {
      const after = codeView(f, u + name.length, u + name.length + 200);
      if (/^\s*=\s*function\b/.test(after)) return true; // its definition
      const call = /^\s*\(\s*(['"])([^'"\\\n]{0,80})\1\s*\)/.exec(after);
      return !!call && p.literal.test(call[2]!);
    });
  });
}

/** How many times each identifier is written in a function body (`=`, `op=`, `++`/`--`), one pass per function. */
function assignmentCounts(f: SignatureFile, fn: { start: number; end: number }): Map<string, number> {
  return memo(f, `asg\u0000${fn.start}\u0000${fn.end}`, () => {
    const view = codeView(f, fn.start, fn.end);
    const re = new RegExp(String.raw`(?<![\w$.])(${IDENT})\s*(?:(?:\*\*|<<|>>>?|&&|\|\||\?\?|[-+*/%&|^])?=(?![=>])|\+\+|--)|(?:\+\+|--)\s*(${IDENT})`, 'g');
    const counts = new Map<string, number>();
    for (let m = re.exec(view); m; m = re.exec(view)) {
      const name = m[1] ?? m[2]!;
      const at = fn.start + m.index + (m[1] ? 0 : m[0].length - name.length);
      if (f.mask[at] === CODE) counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    return counts;
  });
}

/** The file-level pin of a generator: its own definitions are present, and no other implementation of `method` is. */
function fileDefines(f: SignatureFile, p: { fileDefines: readonly string[]; method: string; bodies: readonly string[] }): boolean {
  for (const t of p.fileDefines) {
    const re = new RegExp(t, 'g');
    let found = false;
    for (let m = re.exec(f.src); m && !found; m = re.exec(f.src)) found = f.mask[m.index] === CODE;
    if (!found) return false;
  }
  const bodies = p.bodies.map((t) => new RegExp(`^(?:${t})`));
  const def = new RegExp(String.raw`(?<![\w$.])${esc(p.method)}\s*\(`, 'g');
  let seen = 0;
  for (let m = def.exec(f.src); m; m = def.exec(f.src)) {
    if (f.mask[m.index] !== CODE) continue;
    const close = f.src.indexOf(')', m.index);
    // A definition is `method(params) {`; anything else is a call.
    if (close < 0 || close - m.index > 200 || !/^\s*\{/.test(f.src.slice(close + 1, close + 40))) continue;
    if (++seen > MAX_USES) return false;
    const view = codeView(f, m.index, m.index + 300);
    if (!bodies.some((re) => re.test(view))) return false;
  }
  return true;
}

/** Every code match start of `re` (global) in the file. */
function codeMatches(f: SignatureFile, re: RegExp, limit = MAX_USES + 1): RegExpExecArray[] {
  const out: RegExpExecArray[] = [];
  re.lastIndex = 0;
  for (let m = re.exec(f.src); m && out.length < limit; m = re.exec(f.src)) if (f.mask[m.index] === CODE) out.push(m);
  return out;
}

/**
 * The class a site's constructor really builds, checked as {@link Provenance}
 * `constructs` describes. Bundles reuse short names across scopes (`U` is a class
 * in one module and a number in the next), so every name is resolved to the
 * definition VISIBLE where it is used — the innermost function that defines it —
 * and that definition's scope is what is audited. Fails closed: no binding, an
 * unresolved one, a binding to anything but a class literal, or any override.
 */
function constructsGenuine(
  f: SignatureFile,
  ctor: string,
  site: number,
  p: { property: string; classHas: readonly string[]; sealed: readonly string[]; sealedEverywhere: readonly string[] },
): boolean {
  const prop = esc(p.property);
  // Redefinitions of a sealed-everywhere name: a prototype or instance assignment, a
  // class field or variable, an object property, or the name as a string (`defineProperty`).
  const sealedOk = memo(f, `sealed\u0000${p.sealedEverywhere.join('\u0000')}`, () => {
    for (const name of p.sealedEverywhere) {
      const n = esc(name);
      if (codeMatches(f, new RegExp(String.raw`(?:\.|(?<![\w$.]))${n}\s*(?:=(?![=>])|:)`, 'g'), 1).length) return false;
      for (let at = f.src.indexOf(name); at >= 0; at = f.src.indexOf(name, at + 1)) {
        if (f.mask[at] === STRING && /['"\x60]/.test(f.src[at - 1] ?? '') && f.src[at + name.length] === f.src[at - 1]) return false;
      }
    }
    return true;
  });
  if (!sealedOk) return false;
  // Where the constructor name is bound to a class: the site itself for a bare name,
  // else every `x.CodeGen = X`, `CodeGen: X` / `CodeGen: () => X`, `defineProperty(…, "CodeGen", { value: X })`.
  // `x.CodeGen = class {…}` binds the class literal itself (name `class`, at the keyword).
  const binds = memo(f, `binds\u0000${p.property}`, () => {
    const out: { name: string; at: number; literal?: number }[] = [];
    const push = (m: RegExpExecArray): void => {
      const name = m[1]!;
      out.push(name === 'class' ? { name, at: m.index, literal: m.index + m[0].length - 5 } : { name, at: m.index });
    };
    for (const m of codeMatches(f, new RegExp(String.raw`\.${prop}\s*=\s*(${IDENT})\b(?!\s*[.=\w$])`, 'g'))) push(m);
    for (const m of codeMatches(f, new RegExp(String.raw`(?<![\w$.])${prop}\s*:\s*(?:\(\s*\)\s*=>\s*)?(${IDENT})\b(?!\s*[.(\w$])`, 'g'))) push(m);
    const def = new RegExp(String.raw`['"]${prop}['"]\s*,\s*\{[^;]{0,160}?(?:value\s*:\s*|return\s+)(${IDENT})\b(?!\s*\.)`, 'g');
    for (let m = def.exec(f.src); m && out.length <= MAX_USES; m = def.exec(f.src)) if (f.mask[m.index + 1] === STRING) out.push({ name: m[1]!, at: m.index });
    return out;
  });
  const uses: { name: string; at: number; literal?: number }[] = ctor.includes('.') ? binds : [{ name: ctor, at: site }];
  if (!uses.length || uses.length > MAX_USES) return false;
  // The bound property's prototype touched anywhere (`ns.CodeGen.prototype.toString = …`).
  if (codeMatches(f, new RegExp(String.raw`\.${prop}\s*\.\s*prototype\b`, 'g'), 1).length) return false;
  const has = p.classHas.map((t) => new RegExp(t));
  const whole = { start: 0, end: f.src.length };
  for (const use of uses) {
    if (use.literal !== undefined) {
      const at = use.literal;
      if (!memo(f, `class\u0000${at}`, () => classBodyGenuine(f, at + 5, has, p.sealed))) return false;
      continue;
    }
    const n = esc(use.name);
    // The class definitions of the name, each with the scope it lives in.
    const defs = memo(f, `defs\u0000${use.name}`, () =>
      codeMatches(f, new RegExp(String.raw`(?<![\w$.])(?:class\s+${n}\b|${n}\s*=\s*class\b)`, 'g')).map((m) => ({
        at: m.index,
        end: m.index + m[0].length,
        scope: f.fnAt(m.index) ?? whole,
      })),
    );
    if (defs.length > MAX_USES) return false;
    const visible = defs.filter((d) => use.at >= d.scope.start && use.at < d.scope.end);
    if (!visible.length) return false;
    const inner = Math.min(...visible.map((d) => d.scope.end - d.scope.start));
    for (const d of visible.filter((x) => x.scope.end - x.scope.start === inner)) {
      const ok = memo(f, `class\u0000${d.at}`, () => {
        if (!classBodyGenuine(f, d.end, has, p.sealed)) return false;
        // In the scope the class lives in: the name reassigned (an alias — not resolved,
        // fail closed) in that same function, or its prototype touched anywhere in it.
        const view = codeView(f, d.scope.start, d.scope.end);
        const fnOf = (i: number) => f.fnAt(i) ?? whole;
        const same = (i: number) => fnOf(i).start === d.scope.start && fnOf(i).end === d.scope.end;
        const alias = new RegExp(String.raw`(?<![\w$.])${n}\s*=(?![=>])(?!\s*class\b)`, 'g');
        for (let m = alias.exec(view); m; m = alias.exec(view)) {
          const at = d.scope.start + m.index;
          if (f.mask[at] === CODE && same(at)) return false;
        }
        const proto = new RegExp(String.raw`(?<![\w$.])${n}\s*\.\s*prototype\b`, 'g');
        for (let m = proto.exec(view); m; m = proto.exec(view)) if (f.mask[d.scope.start + m.index] === CODE) return false;
        return true;
      });
      if (!ok) return false;
    }
  }
  return true;
}

/** The class body that starts after `from` defines every `has` method and replaces no `sealed` one (a field, `this.<name> =`). */
function classBodyGenuine(f: SignatureFile, from: number, has: readonly RegExp[], sealed: readonly string[]): boolean {
  let open = from;
  while (open < f.src.length && (f.src[open] !== '{' || f.mask[open] !== CODE)) open++;
  const close = matchBracket(f.src, f.mask, open);
  if (close < 0) return false;
  const body = codeView(f, open, close + 1);
  if (!has.every((re) => re.test(body))) return false;
  for (const name of sealed) {
    if (new RegExp(String.raw`(?:this\s*\.\s*|[{;}\n]\s*(?:static\s+)?)${esc(name)}\s*=(?![=>])`).test(body)) return false;
  }
  return true;
}

/** The invocation of the compiled function: `)(…)` right after the call, or `V(…)` for `V = <call>`. */
function invocationArgs(f: SignatureFile, index: number, end: number): string[] | null {
  let k = end + 1;
  while (k < f.src.length && /\s/.test(f.src[k]!)) k++;
  if (f.src[k] === '(' && f.mask[k] === CODE) return argsAt(f, k)?.args ?? null;
  const assigned = new RegExp(String.raw`(?<![\w$.])(${IDENT})\s*=\s*$`).exec(codeView(f, index - 80, index));
  if (!assigned) return null;
  const view = codeView(f, end + 1, end + 1 + INVOKE_WITHIN);
  const use = new RegExp(String.raw`(?<![\w$.])${esc(assigned[1]!)}\s*\(`).exec(view);
  if (!use) return null;
  const open = end + 1 + use.index + use[0].length - 1;
  return f.mask[open] === CODE ? (argsAt(f, open)?.args ?? null) : null;
}

/**
 * The signature the dynamic-code call at `index` matches, or null. Matching is
 * all-or-nothing: the callee, every argument, the invocation, the provenance of
 * every bound identifier, and none of them a parameter of the enclosing function.
 * `pkg` restricts the search to one package's signatures.
 */
export function matchVendoredSignature(
  f: SignatureFile,
  index: number,
  rule: string,
  pkg?: string,
  opts: { local?: boolean } = {},
): VendoredSignature | null {
  const win = f.src.slice(index, index + 400);
  for (const s of VENDORED_SIGNATURES) {
    if ((pkg !== undefined && s.package !== pkg) || !s.rules.includes(rule) || !s.hint.test(win)) continue;
    const callee = s.callee.exec(win);
    if (!callee) continue;
    const open = index + callee[0].length - 1;
    if (f.src[open] !== '(' || f.mask[open] !== CODE) continue;
    const call = argsAt(f, open);
    const b: Bindings = new Map();
    if (!call || !argsMatch(s.args, call.args, b)) continue;
    const inv = invocationArgs(f, index, call.end);
    if (!inv || !argsMatch(s.invoke, inv, b)) continue;
    // A lone original module does not define the whole generator: file-level pins apply to the bundle only.
    if (!s.provenance.every((p) => (opts.local && ('fileDefines' in p || 'constructs' in p)) || provenanceHolds(f, p, index, b))) continue;
    const params = f.paramsAt(index);
    if (s.notParams.some((n) => params.includes((b.get(n) ?? '').split('.')[0]!))) continue;
    return s;
  }
  return null;
}

/** True when the package has a call signature here (then a map's original text must show it). */
export function hasSignature(pkg: string): boolean {
  return VENDORED_SIGNATURES.some((s) => s.package === pkg);
}

/** A bundler's module wrapper CALLED in code: esbuild `__commonJS(…)`/`__toESM(…)`/`__require(…)`, webpack `__webpack_require__(…)`. */
const BUNDLE_WRAPPER = /(?<![\w$.])(?:__commonJS|__toESM|__require|__webpack_require__|__esm)\s*\(/g;
const BUNDLE_MIN_BYTES = 64 * 1024;

/**
 * Corroboration for a signature matched WITHOUT a source map: the file is a
 * bundle (it calls a module wrapper in code, or is too large to be one
 * hand-written module), and it carries the dependency's own identifying text —
 * its fixed error messages, its implementation — in code or string positions,
 * never in a comment. A look-alike in an author's own small module has neither.
 */
export function corroborated(s: VendoredSignature, f: SignatureFile): boolean {
  return memo(f, `corr\u0000${s.id}`, () => {
    const inCode = (re: RegExp): boolean => {
      re.lastIndex = 0;
      for (let m = re.exec(f.src); m; m = re.exec(f.src)) if (f.mask[m.index] === CODE) return true;
      return false;
    };
    if (f.src.length < BUNDLE_MIN_BYTES && !inCode(BUNDLE_WRAPPER)) return false;
    return s.identity.every((t) => {
      for (let at = f.src.indexOf(t); at >= 0; at = f.src.indexOf(t, at + 1)) if (f.mask[at] !== COMMENT) return true;
      return false;
    });
  });
}

/** The signature note for a package, used when a source map (not a signature) attributed the code. */
export function vendoredNoteFor(pkg: string): string | undefined {
  return VENDORED_SIGNATURES.find((s) => s.package === pkg)?.note;
}
