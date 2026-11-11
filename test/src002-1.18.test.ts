/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test } from 'node:test';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { FileCtx } from '../src/util/fileCtx.js';
import { toolFlowOf } from '../src/analysis/toolFlow.js';
import type { ServerSurface } from '../src/types.js';

// MCP Trust Checker 1.18 — MTC-SRC-002 precision: the words for a program
// resolved at runtime (S2). They are observations of the scanner and conditionals,
// never a reassurance. A finding is reworded only when every call of the file that
// runs code chosen at runtime is run by an API that takes a program and an argv
// array, writes its program as a plain reference, writes no shell or eval flag in
// its arguments, has options that neither ask for a shell nor name one, and shows no
// tool input; the "saw no tool input" sentence only in a file with no sign of MCP or
// tools. Tool input in the program and the options of such a call (S3), the label for
// a `shell` option set at runtime (S4), memoised reassignment lookups (S5); `.sync(…)`
// on the cross-spawn module and every function handed on as a value keep their 1.17
// record and words. Severity, confidence, capability and score never move because
// tool input is not visible; a finding whose only change is text keeps the evidence
// and the fingerprint of 1.17.0 (hard-coded below, computed with the 1.17.0 engine).

type F = { path: string; content: string };

async function scan(files: F[]) {
  const surface = { id: 'pkg', source: { kind: 'package', origin: 'pkg' }, server: {}, tools: [], prompts: [], resources: [], sourceFiles: files } as unknown as ServerSurface;
  return scanSurface(surface);
}
const src002 = async (files: F[], file?: string): Promise<any> => {
  const r = await scan(files);
  const all = r.findings.filter((f: any) => f.ruleId === 'MTC-SRC-002');
  const f = file ? all.find((x: any) => x.data.file === file) : all[0];
  assert.ok(f, 'an MTC-SRC-002 finding');
  return f;
};
const one = (content: string, path = 'src/x.js') => src002([{ path, content }]);
const calls = (f: any) => f.data.calls.map((c: any) => [c.method, c.shape, c.program]);
const PLACEHOLDER = [['spawn', 'dynamic-program', '<passed on as a value>']];

const OLD_TITLE = /^Shell\/command execution in /;
const NEW_TITLE = /^Runs a program resolved at runtime in /;
const CAPABILITY = "if it is the package's own binary or a known tool run with fixed arguments, it is a process-spawning capability.";
const RUNS = 'runs a program resolved at runtime (a variable, configuration or a lookup). ';
const SAW_NO_INPUT =
  RUNS + 'In this file the scanner saw no tool input reach the program or its arguments. ' +
  `If tool input can reach it from elsewhere, this is command injection / RCE; ${CAPABILITY}`;
const CANNOT_TELL = `The scanner cannot tell whether tool input reaches the program or its arguments in this file. If tool input can reach it, this is command injection / RCE; ${CAPABILITY}`;
const NEUTRAL = RUNS + CANNOT_TELL;
const NEW_REMEDIATION =
  'If the program comes only from your own configuration or a fixed install path, keep it that way: pass an argv array (no shell), ' +
  'never let tool input choose the program or a command line it runs, and validate any argument that comes from tool input.';
const OLD_WORDS = 'the program to run is chosen at runtime. Spawning a process whose command line or program is decided at runtime is code execution: with unsanitized tool input it is command injection / RCE.';
const OLD_REMEDIATION =
  'Pass a fixed program and an argv array instead of a shell string; never let tool input choose the program or the command line. If a shell is genuinely required, validate every value that reaches it.';
const RUNTIME_SHELL_WORDS = 'a shell may run a command line built at runtime (the shell option is set at runtime)';

/** Code execution, as 1.17 rated it: only the words may differ. */
function assertCodeExec(f: any): void {
  assert.equal(f.severity, 'high');
  assert.equal(f.confidence, 'strong');
  assert.equal(f.data.capabilityTag, 'code-exec');
}

/** The finding carries the 1.17.0 evidence and fingerprint. */
function assertSame117(f: any, evidence: string, fingerprint: string): void {
  assert.equal(f.evidence, evidence);
  assert.equal(f.data.fingerprint, fingerprint);
}

// --- Spec item 1: `.sync(…)` on the cross-spawn module stays as in 1.17 --------
//
// Reading `X.sync(…)` as spawnSync trusts that `.sync` is still cross-spawn's own
// when the call runs. Verify round 2 rewrote it at runtime in ways no check of
// the package's text rules out (a module written and loaded by the file, the
// module cache reached under other names, a sibling loading cross-spawn through
// a computed specifier, runtime code fed to `bash /dev/stdin`), so 1.18.0 keeps
// the 1.17 record for every such call: severity, words, evidence, fingerprint.

for (const [name, path, content, evidence, fingerprint] of [
  [
    'firebase extensionsEmulator: spawn.sync("npm", ["install"], …)',
    'lib/emulator/extensionsEmulator.js',
    'const spawn = require("cross-spawn");\nfunction install(dir) {\n  return spawn.sync("npm", ["install"], { encoding: "utf8", cwd: dir });\n}\nmodule.exports = { install };\n',
    'awn"); function install(dir) { return spawn.sync("npm", ["install"], { encoding: "u',
    '13a1b03767f84040a44a1b9da5a88f29078bbcaa946e6539adffaf869487267a',
  ],
  [
    'a default import: spawn.sync("docker", ["push", ...args], …)',
    'src/x.js',
    'import spawn from "cross-spawn";\nexport function push(args) {\n  return spawn.sync("docker", ["push", ...args], { stdio: ["pipe", "inherit", "inherit"] });\n}\n',
    '; export function push(args) { return spawn.sync("docker", ["push", ...args], { std',
    '4d8f5aa747ecf8a71e8ea2699775f5dde551cb0ad52f7187e3e6138a0fc71e32',
  ],
  [
    'tsc output: spawn.sync("npm", ["show", …], …)',
    'src/x.js',
    '"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\nconst spawn = require("cross-spawn");\nfunction getLatestSDKVersion() {\n    return spawn.sync("npm", ["show", "firebase-functions", "--json=true"], { encoding: "utf8", timeout: 10000 });\n}\nexports.getLatestSDKVersion = getLatestSDKVersion;\n',
    'tion getLatestSDKVersion() { return spawn.sync("npm", ["show", "firebase-function',
    '98908bc0e95a95e1b832639b31f56642946cbecf1deed176f15352bd83f974d8',
  ],
  [
    'firebase buildToolsJarHelper: spawn.sync("java", fullArgs, …)',
    'lib/crashlytics/buildToolsJarHelper.js',
    'const spawn = require("cross-spawn");\nfunction runBuildtoolsCommand(jarFile, args, debug) {\n    const fullArgs = ["-jar", jarFile, ...args, "-clientName", "firebase-cli;crashlytics-buildtools"];\n    const outputs = spawn.sync("java", fullArgs, {\n        stdio: debug ? "inherit" : "pipe",\n    });\n    return outputs;\n}\nexports.runBuildtoolsCommand = runBuildtoolsCommand;\n',
    'ytics-buildtools"]; const outputs = spawn.sync("java", fullArgs, { stdio:',
    '2a28678d438d96f0c0f7fccb52760ff23c1651a32109d6747460ea23cb9fcb51',
  ],
  [
    'a plain fixed call: spawn.sync("git", ["status"])',
    'src/server.js',
    'const spawn = require("cross-spawn");\nfunction run() { return spawn.sync("git", ["status"]); }\nmodule.exports = { run };\n',
    '"cross-spawn"); function run() { return spawn.sync("git", ["status"]); } module.expor',
    '5a6542050ad5aa9de1e7726adfbbbe27fd00eabd3a3bf1bf5b696a81b015c607',
  ],
  [
    'a shell with a runtime argument: spawn.sync("ls", [dir], { shell: true })',
    'src/x.js',
    'const spawn = require("cross-spawn");\nexports.list = (dir) => spawn.sync("ls", [dir], { shell: true });\n',
    '"cross-spawn"); exports.list = (dir) => spawn.sync("ls", [dir], { shell: true });',
    '32b88c1f85a839b9020716b285d44393cd50eda807a8da3a687d3d4e7bc52154',
  ],
] as const) {
  test(`cross-spawn .sync keeps the 1.17 record, words, evidence and fingerprint — ${name}`, async () => {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'dynamic-program');
    assert.deepEqual(calls(f), PLACEHOLDER);
    // The arguments are in the code, only not read: neither "cannot see" nor "saw no tool input".
    assert.match(f.title, OLD_TITLE);
    assert.ok(f.description.includes(`\`spawn(…)\` — ${OLD_WORDS}`), f.description);
    assert.equal(f.remediation, OLD_REMEDIATION);
    assertSame117(f, evidence, fingerprint);
  });
}

test('cross-spawn .sync: a module the package can rewrite at runtime keeps the call high (verify round 2: R2-01, R2-02, rr-01, rr-02)', async () => {
  const server = 'const spawn = require("cross-spawn");\nrequire("./patch");\nfunction run() { return spawn.sync("git", ["status"]); }\nmodule.exports = { run };\n';
  const evil = 'const o = cs.sync;\ncs.sync = (p, a, x) => o(process.env.EVIL_BIN || p, a, x);\n';
  const viaCache = (head: string, list: string) =>
    `${head}\nfor (const m of ${list}) {\n  if (m.exports && typeof m.exports.sync === "function") {\n    const o = m.exports.sync;\n    m.exports.sync = (p, a, x) => o(process.env.EVIL_BIN || p, a, x);\n  }\n}\n`;
  for (const [name, files] of [
    ['require["cache"]', [{ path: 'src/server.js', content: server }, { path: 'src/patch.js', content: viaCache('const c = require["cache"];', 'Object.values(c)') }]],
    ['const { cache } = require', [{ path: 'src/server.js', content: server }, { path: 'src/patch.js', content: viaCache('const { cache } = require;', 'Object.values(cache)') }]],
    ['module.parent.children', [{ path: 'src/server.js', content: server }, { path: 'src/patch.js', content: viaCache('', 'module.parent.children') }]],
    ['a computed specifier', [{ path: 'src/server.js', content: server }, { path: 'src/patch.js', content: `const cs = require(["cross", "spawn"].join("-"));\n${evil}` }]],
    ['an escaped specifier', [{ path: 'src/server.js', content: server }, { path: 'src/patch.js', content: `const cs = require("cross-spa\\x77n");\n${evil}` }]],
    ['a concatenated specifier', [{ path: 'src/server.js', content: server }, { path: 'src/patch.js', content: `const cs = require("cross-" + "spawn");\n${evil}` }]],
    ['a module the file writes and loads', [{ path: 'src/server.js', content: 'const fs = require("fs");\nconst spawn = require("cross-spawn");\nfs.writeFileSync(__dirname + "/gen.js", "const c = require(\'cross-\' + \'spawn\'); const o = c.sync; c.sync = (p, a, x) => o(process.env.EVIL_BIN || p, a, x);");\nrequire("./gen");\nfunction run() { return spawn.sync("git", ["status"]); }\nmodule.exports = { run };\n' }]],
    ['the installed module rewritten before it loads', [{ path: 'src/server.js', content: 'const fs = require("fs");\nconst path = require("path");\nconst dir = path.join(__dirname, "..", "node_modules", "cross-" + "spawn");\nfs.writeFileSync(path.join(dir, "index.js"), "module.exports = function () {}; module.exports.sync = () => null;");\nconst spawn = require("cross-spawn");\nfunction run() { return spawn.sync("git", ["status"]); }\nmodule.exports = { run };\n' }]],
    ['runtime code fed to bash /dev/stdin', [{ path: 'src/server.js', content: 'const spawn = require("cross-spawn");\nlet script = "echo ok";\nexports.configure = (s) => { script = s; };\nexports.run = () => spawn.sync("bash", ["/dev/stdin"], { input: script });\n' }]],
  ] as const) {
    const f = await src002(files as unknown as F[], 'src/server.js');
    assertCodeExec(f);
    assert.deepEqual(calls(f), PLACEHOLDER, name);
  }
});

// The conditions the spec names (shadowed, reassigned, `.sync` written) and the other members: as 1.17.
for (const [name, content] of [
  ['shadowed by a parameter', 'const spawn = require("cross-spawn");\nfunction f(spawn) {\n  return spawn.sync("npm", ["install"]);\n}\nexports.f = f;\n'],
  ['reassigned elsewhere in the file', 'let spawn = require("cross-spawn");\nexports.use = (s) => { spawn = s; };\nexports.f = () => spawn.sync("npm", ["install"]);\n'],
  ['.sync overwritten in the file', 'const spawn = require("cross-spawn");\nspawn.sync = (p, a) => run.run(p, a);\nexports.f = () => spawn.sync("npm", ["install"]);\n'],
  ['.call', 'const spawn = require("cross-spawn");\nexports.f = () => spawn.sync.call(null, "npm", ["install"]);\n'],
  ['.apply', 'const spawn = require("cross-spawn");\nexports.f = () => spawn.sync.apply(null, ["npm", ["install"]]);\n'],
  ['.bind', 'const spawn = require("cross-spawn");\nexports.f = spawn.sync.bind(null, "npm");\n'],
  ['handed on as a value', 'const spawn = require("cross-spawn");\nexports.f = (run) => run(spawn.sync);\n'],
  ['a child_process spawn', 'const { spawn } = require("child_process");\nexports.f = () => spawn.sync("npm", ["install"]);\n'],
] as const) {
  test(`cross-spawn .sync: ${name} stays "<passed on as a value>" (as 1.17)`, async () => {
    const f = await one(content);
    assertCodeExec(f);
    // A parameter or an assignment target of the same name is a placeholder of its own, as in 1.17.
    const found = calls(f);
    assert.ok(found.length >= 1);
    for (const c of found) assert.deepEqual(c, PLACEHOLDER[0], content);
  });
}

// The spec's hostile probes: tool input chooses the program.
test('spec hostile: spawn.sync(args.program, …) and spawn.sync(req.params.cmd, []) stay high', async () => {
  const a = await one('const spawn = require("cross-spawn");\nserver.tool("run", {}, async (args) => spawn.sync(args.program, ["--version"]));\n');
  assertCodeExec(a);
  assert.equal(a.data.callShape, 'dynamic-program');
  // A call recorded without its arguments: toolInput false, as in 1.17; a member call keeps the 1.17 words.
  assert.equal(a.data.toolInput, false);
  assert.match(a.title, OLD_TITLE);
  assert.equal(a.remediation, OLD_REMEDIATION);
  const b = await one('const spawn = require("cross-spawn");\napp.get("/run/:cmd", (req, res) => res.json(spawn.sync(req.params.cmd, [])));\n');
  assertCodeExec(b);
  assert.equal(b.data.callShape, 'dynamic-program');
});

test('spec hostile: shell: true with tool-input arguments stays high (shell-dynamic through child_process)', async () => {
  const f = await one('const spawn = require("cross-spawn");\nserver.tool("ls", {}, async (a) => spawn.sync("ls", [a.dir], { shell: true }));\n');
  assertCodeExec(f);
  assert.deepEqual(calls(f), PLACEHOLDER);
  assert.equal(f.data.toolInput, false, 'a call recorded without its arguments, as in 1.17');
  assertSame117(f, 'n"); server.tool("ls", {}, async (a) => spawn.sync("ls", [a.dir], { shell: true }));', 'd72b3b52bc4b48641983c833e6bdcede66f550264afeb886be0059940c647a42');
  const g = await one('const { spawn } = require("child_process");\nserver.tool("ls", {}, async (a) => spawn("ls", [a.dir], { shell: true }));\n');
  assertCodeExec(g);
  assert.equal(g.data.callShape, 'shell-dynamic');
  assert.equal(g.data.toolInput, true);
});

test('spec hostile: { file: input.path, args: [] } stays dynamic-program high', async () => {
  const f = await one('const { execFile } = require("child_process");\nserver.tool("run", {}, async (input) => {\n  const command = { file: input.path, args: [] };\n  return execFile(command.file, command.args);\n});\n');
  assertCodeExec(f);
  assert.equal(f.data.callShape, 'dynamic-program');
});

test('spec hostile: a Python wrapper returning tool input stays high', async () => {
  const f = await one(
    'import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("x")\n\n\ndef cmd(x):\n    return [x, "--v"]\n\n\n@mcp.tool()\ndef run(arguments: dict) -> str:\n    return subprocess.run(cmd(arguments["program"]), capture_output=True, text=True).stdout\n',
    'srv/server.py',
  );
  assertCodeExec(f);
  assert.equal(f.data.callShape, 'dynamic-program');
  assert.equal(f.data.toolInput, true);
  assert.match(f.title, OLD_TITLE);
});

test('spec hostile: a wrapper with one fixed return and one from its parameter stays dynamic-program high', async () => {
  const js = await one('const { execFile } = require("child_process");\nfunction mk(p) {\n  if (globalThis.safe) return { file: "git", args: ["status"] };\n  return { file: p, args: [] };\n}\nserver.tool("run", {}, async (a) => {\n  const c = mk(a.program);\n  return execFile(c.file, c.args);\n});\n');
  assertCodeExec(js);
  assert.equal(js.data.callShape, 'dynamic-program');
  const py = await one(
    'import subprocess\n\n\ndef cmd(x, fixed):\n    if fixed:\n        return ["git", "status"]\n    return [x, "--v"]\n\n\ndef run(program):\n    return subprocess.run(cmd(program, False), capture_output=True)\n',
    'pkg/run.py',
  );
  assertCodeExec(py);
  assert.equal(py.data.callShape, 'dynamic-program');
});

// --- S2. Words for a program resolved at runtime ------------------------------

test('S2: a dynamic program no visible tool input reaches — new words, 1.17 evidence and fingerprint', async () => {
  const f = await one('const { execFile } = require("child_process");\nfunction version(bin) {\n  return execFile(bin, ["--version"]);\n}\nmodule.exports = { version };\n');
  assertCodeExec(f);
  assert.equal(f.data.callShape, 'dynamic-program');
  assert.equal(f.data.toolInput, false);
  assert.equal(f.title, 'Runs a program resolved at runtime in package code (src/x.js)');
  assert.ok(f.description.includes(`\`execFile(…)\` ${SAW_NO_INPUT}`), f.description);
  assert.ok(!f.description.includes('no tool input reaches'));
  assert.equal(f.remediation, NEW_REMEDIATION);
  assertSame117(f, 'execFile(bin, ["--version"])', '6eef544596ba8ec6e953783886c4abdb1cff363e1f57c93c217cc4d87bc8b5f6');
});

test('S2: every API that takes a program and an argv array is reworded (final round 2)', async () => {
  for (const [path, content, method, evidence, fingerprint] of [
    ['src/a.js', 'const { execFileSync } = require("child_process");\nexports.run = (bin) => execFileSync(bin, ["--version"]);\n', 'execFileSync', 'execFileSync(bin, ["--version"])', '088336f1c9540f5865465bc67decb81f84185ff3a44e3d83129e425d7c126d79'],
    ['src/b.js', 'const { spawnSync } = require("child_process");\nexports.run = (bin) => spawnSync(bin, ["--version"]);\n', 'spawnSync', 'spawnSync(bin, ["--version"])', '95a25e5a5895a7b884234f928fc72e443c7be98224578377b5ea7f27c24ae9ba'],
    ['src/c.js', 'const { fork } = require("child_process");\nexports.run = (mod) => fork(mod, ["--port", "1"]);\n', 'fork', 'fork(mod, ["--port", "1"])', 'b231189efac829482384ad0b49dc66f99c5f2b15bf1ac0987eae248fa24be3d4'],
    ['src/d.js', 'const { execa } = require("execa");\nexports.run = (bin) => execa(bin, ["--version"]);\n', 'execFile', 'execa(bin, ["--version"])', 'de808e944ec180ac9d58c9e0551f7301eaf4b2e979c55b17189ff27171d5247f'],
    ['src/e.js', 'const spawn = require("cross-spawn");\nexports.run = (bin) => spawn(bin, ["--version"]);\n', 'spawn', 'spawn(bin, ["--version"])', '164eab8604722b4497c8b2e380fadbfb57a84af255232554de2c5ba6cf9317ef'],
    ['pkg/f.py', 'import subprocess\n\n\ndef run(binary):\n    return subprocess.Popen([binary, "--version"])\n', 'subprocess.Popen', 'subprocess.Popen([binary, "--version"])', 'd692821a14c9331b0df36ef1d54c4fd88ee99befa1c1080555056d38c2dcfd72'],
    ['pkg/g.py', 'import asyncio\n\n\nasync def run(binary):\n    return await asyncio.create_subprocess_exec(binary, "--version")\n', 'asyncio.create_subprocess_exec', 'asyncio.create_subprocess_exec(binary, "--version")', 'ae72e4395a14aff417b4983735c4ee2e3982e996e71ffbeb88d646cb87d0a238'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'dynamic-program', path);
    assert.match(f.title, NEW_TITLE, path);
    assert.ok(f.description.includes(`\`${method}(…)\` ${SAW_NO_INPUT}`), `${path}: ${f.description}`);
    assert.equal(f.remediation, NEW_REMEDIATION, path);
    assertSame117(f, evidence, fingerprint);
  }
});

test('S2: tool input reaching the call keeps the 1.17 words', async () => {
  const f = await one('const { execFile } = require("child_process");\nserver.tool("log", {}, async (a) => execFile(globalThis.bin, ["log", a.ref]));\n');
  assertCodeExec(f);
  assert.equal(f.data.toolInput, true);
  assert.match(f.title, OLD_TITLE);
  assert.ok(f.description.includes(`\`execFile(…)\` — ${OLD_WORDS}`), f.description);
  assert.equal(f.remediation, OLD_REMEDIATION);
});

test('S2: tool input in ANY runtime-program call of the file keeps the 1.17 words', async () => {
  const f = await one('const { execFile, spawn } = require("child_process");\nexports.version = (bin) => execFile(bin, ["--version"]);\nserver.tool("run", {}, async (a) => spawn(a.program, []));\n');
  assertCodeExec(f);
  assert.equal(f.data.calls[0].toolInput, false);
  assert.equal(f.data.calls[1].toolInput, true);
  assert.match(f.title, OLD_TITLE);
  assert.equal(f.remediation, OLD_REMEDIATION);
});

test('S2: a function handed on as a value keeps the 1.17 words (the record does not say how it is used)', async () => {
  const passed = await one('const { spawn } = require("child_process");\nmodule.exports = { run: (impl) => impl(spawn) };\n');
  assertCodeExec(passed);
  assert.match(passed.title, OLD_TITLE);
  assert.ok(passed.description.includes(`\`spawn(…)\` — ${OLD_WORDS}`), passed.description);
  assert.equal(passed.remediation, OLD_REMEDIATION);
  assertSame117(passed, 'module.exports = { run: (impl) => impl(spawn) };', '2b44355a8a34a49f1362133c69ef70c0f8e32b48563c496fc6002661b07c276d');
});

test('S2: a shell API, a command string or an API the scanner cannot name keeps the 1.17 words (final round 2: FR1-01, FR1-02)', async () => {
  // Only an API that takes a program and an argv array is reworded: "Keep an argv array (no shell)"
  // would be false for `exec`, and the arguments of an API chosen at runtime are not read.
  for (const [name, path, content, method, evidence, fingerprint] of [
    ['exec handed on as a value', 'src/runner.js', 'const { exec } = require("child_process");\nmodule.exports = function makeQueue(queue) {\n  return queue.withRunner(exec);\n};\n', 'exec', 'ueue(queue) { return queue.withRunner(exec); };', 'fd8a31f117bbcad94ce235072e9092a22c1021b3aa8a91bda123896500de04ea'],
    ['execSync re-exported', 'src/sh.js', 'const { execSync } = require("child_process");\nmodule.exports = { sh: execSync };\n', 'execSync', 'child_process"); module.exports = { sh: execSync };', 'e2ae077ccc1bce4da41f5c262b9704b47c8eb8636b449ed79a48e0f4b53cc06e'],
    ['execaCommand with a runtime line', 'src/cmd.js', 'const { execaCommand } = require("execa");\nexports.run = (line) => execaCommand(line);\n', 'execaCommand', 'execaCommand(line)', '2817e156cb93030cf385220045ba2f4fe29557eec46dbb15f4fded6c90ee9085'],
    ['cp[MODE](line, { shell: true })', 'src/runLine.js', 'const cp = require("child_process");\nconst MODE = process.env.RUNNER_MODE || "execSync";\nmodule.exports = function runLine(line) {\n  return cp[MODE](line, { shell: true, stdio: "inherit" });\n};\n', '[computed]', 'cp[MODE](line, { shell: true, stdio: "inherit" }); };', '9f197f3fabf733bde88b07c5a093c6524cb8f67fdcf46f0a150a5cc2eddf307a'],
    ['cp[api](file, [])', 'src/x.js', 'const cp = require("child_process");\nexports.run = (api, file) => cp[api](file, []);\n', '[computed]', 'cp[api](file, []);', 'f1f812d3f03bac6d21480c0d054038ff2ec86113c7690550b25bf104f106a333'],
    ['getattr(subprocess, RUNNER)(line, shell=True)', 'pkg/run_line.py', 'import os\nimport subprocess\n\nRUNNER = os.environ.get("RUNNER", "run")\n\n\ndef run_line(line):\n    return getattr(subprocess, RUNNER)(line, shell=True, check=True)\n', 'subprocess.[computed]', 'getattr(subprocess, RUNNER)(line, shell=True, check=True)', '8bc98f8a1970f018e118f4721ef3959706152bf417f2fafdd14d0755b83f5834'],
    ['a binding the scanner cannot read', 'src/x.js', 'const cp = loader("child_process");\nexports.cp = cp;\n', 'child_process', 'loader("child_process"); exports.cp = cp;', '0a976a34afab95c1300cf3d5b9a2a1b441cc2d76180766cba299cf03dce11de8'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'dynamic-program', name);
    assert.match(f.title, OLD_TITLE, name);
    assert.ok(f.description.includes(`\`${method}(…)\` — ${OLD_WORDS}`), `${name}: ${f.description}`);
    assert.equal(f.remediation, OLD_REMEDIATION, name);
    assertSame117(f, evidence, fingerprint);
  }
});

test('S2: the spec item-2 examples stay dynamic-program high, with the 1.17 evidence; a literal in the program as written keeps the 1.17 words', async () => {
  const js = await one(
    'const { execFile } = require("child_process");\nfunction defaultStatusCommand() {\n  return { file: "git", args: ["status", "--porcelain"] };\n}\nfunction runStatus(command = defaultStatusCommand()) {\n  return execFile(command.file, command.args);\n}\nexports.runStatus = runStatus;\n',
    'src/status.js',
  );
  assertCodeExec(js);
  assert.equal(js.data.callShape, 'dynamic-program');
  assert.match(js.title, NEW_TITLE);
  assertSame117(js, 'execFile(command.file, command.args)', '95d032d87eb9d405e54a94aba3f634fb2cf560900be1f0a8263ab594bed95999');

  const git = await one(
    'import subprocess\n\n\ndef read_only_git_command(args):\n    return ["git", "--no-pager", *args]\n\n\ndef list_files(root):\n    return subprocess.run(read_only_git_command(["ls-files"]), cwd=root, capture_output=True, text=True)\n',
    'skylos/git_ops.py',
  );
  assertCodeExec(git);
  assert.equal(git.data.callShape, 'dynamic-program');
  // The program as written holds a string literal (the wrapper's argument): the 1.17 words stay.
  assert.match(git.title, OLD_TITLE);
  assert.ok(git.description.includes(`\`subprocess.run(…)\` — ${OLD_WORDS}`), git.description);
  assert.equal(git.remediation, OLD_REMEDIATION);
  assertSame117(git, 'subprocess.run(read_only_git_command(["ls-files"]), cwd=root, capture_output=True, text=True)', 'd2f8e9c308b1e537ec84872859e3afe769e029339d627ff3ba68d8de0a909412');

  const sops = await one(
    'import subprocess\n\n\nclass Sops:\n    def __init__(self, sops_binary="sops"):\n        self.sops_binary = sops_binary\n\n    def decrypt(self, path):\n        return subprocess.run([self.sops_binary, "-d", path], capture_output=True, text=True)\n',
    'sops_mcp/sops.py',
  );
  assertCodeExec(sops);
  assert.equal(sops.data.callShape, 'dynamic-program');
  assert.match(sops.title, NEW_TITLE);
  assert.ok(sops.description.includes(`\`subprocess.run(…)\` ${SAW_NO_INPUT}`), sops.description);
  assertSame117(sops, 'subprocess.run([self.sops_binary, "-d", path], capture_output=True, text=True)', '3bd795cd67567e72908167e81f022986eb4e56b7f3e74513b0eb900a4da255cc');
});

test('S2: a literal program that runs code chosen at runtime keeps the 1.17 words', async () => {
  for (const [content, path] of [
    ['const { execFile } = require("child_process");\nexports.run = (script) => execFile("osascript", ["-e", script]);\n', 'src/x.js'],
    ['const { spawn } = require("child_process");\nexports.run = (code) => spawn("node", ["-e", code]);\n', 'src/x.js'],
    ['const { spawn } = require("child_process");\nexports.run = (pkg) => spawn("npx", ["--yes", pkg]);\n', 'src/x.js'],
    ['const { spawn } = require("child_process");\nexports.run = (script) => spawn(process.execPath, [script]);\n', 'src/x.js'],
    ['import subprocess\n\n\ndef run(script):\n    return subprocess.run(["osascript", "-e", script], capture_output=True)\n', 'pkg/run.py'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'dynamic-program');
    assert.match(f.title, OLD_TITLE, content);
    assert.ok(f.description.includes(OLD_WORDS), f.description);
    assert.equal(f.remediation, OLD_REMEDIATION);
  }
});

test('S2: in a file that handles tool calls the words never say tool input was not seen', async () => {
  for (const [content, path, method] of [
    // Paths the tool-input tracker does not follow (verify round 1: m1-10, m1-11, j18).
    ['const { execFile } = require("child_process");\nserver.tool("x", {}, async (a) => { for (const bin of a.bins) execFile(bin, ["--version"]); });\n', 'src/x.js', 'execFile'],
    ['const { execFile } = require("child_process");\nclass R { constructor() { this.bin = ""; } go() { return execFile(this.bin, []); } }\nconst r = new R();\nserver.tool("x", {}, async (a) => { r.bin = a.program; return r.go(); });\n', 'src/x.js', 'execFile'],
    ['import { execFile } from "node:child_process";\nimport { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";\nconst handlers = { run: async (args) => execFile(args.program, []) };\nserver.setRequestHandler(CallToolRequestSchema, async (r) => handlers[r.params.name](r.params.arguments));\n', 'src/x.js', 'execFile'],
    // A handler the tracker does not recognise still marks the file.
    ['const { execFile } = require("child_process");\nserver.addTool({ name: "x", execute: async (a) => execFile(a.program, []) });\n', 'src/x.js', 'execFile'],
    // Python: the tracker follows no local assignment (m1-12).
    ['import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("x")\n\n\n@mcp.tool()\ndef run(program: str) -> str:\n    exe = program\n    return subprocess.run([exe, "--version"], capture_output=True).stdout\n', 'srv/server.py', 'subprocess.run'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.ok(!/no tool input reach/.test(f.description), f.description);
    assert.equal(f.data.toolInput, false, 'the tracker does not see these paths');
    assert.match(f.title, NEW_TITLE);
    assert.ok(f.description.includes(`\`${method}(…)\` ${NEUTRAL}`), f.description);
    assert.equal(f.remediation, OLD_REMEDIATION);
  }
});

test('S2: tool handlers the tracker does not recognise still mark the file (verify round 2: R2-03, rr-04, rr-05)', async () => {
  for (const [name, path, content, method, evidence, fingerprint] of [
    [
      'the low-level @server.call_tool() decorator',
      'pkg/server.py',
      'import subprocess\nfrom mcp.server import Server\n\nserver = Server("runner")\n\n\ndef run_program(cmd):\n    return subprocess.run(cmd, capture_output=True, text=True)\n\n\n@server.call_tool()\nasync def call_tool(name: str, arguments: dict):\n    cmd = [arguments["program"], "--version"]\n    return run_program(cmd)\n',
      'subprocess.run',
      'subprocess.run(cmd, capture_output=True, text=True)',
      '1d29ca776d212a1f33d54f115e4e9b621801ef0d6093793cb903d51855e0acf5',
    ],
    [
      'FastMCP add_tool(fn)',
      'pkg/server.py',
      'import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("runner")\n\n\ndef run(program: str) -> str:\n    return subprocess.run([program, "--version"], capture_output=True, text=True).stdout\n\n\nmcp.add_tool(run)\n',
      'subprocess.run',
      'subprocess.run([program, "--version"], capture_output=True, text=True)',
      '46e9b87f02e201bdf9591e3c1da217c44a044e0f3b98ddb6f2dce6f51241f6de',
    ],
    [
      'a hand-rolled "tools/call" dispatch',
      'src/server.js',
      'const { spawn } = require("child_process");\nfunction onMessage(msg) {\n  if (msg.method === "tools/call") {\n    const bin = msg.params.arguments.bin;\n    return spawn(bin, ["--version"]);\n  }\n}\nmodule.exports = { onMessage };\n',
      'spawn',
      'spawn(bin, ["--version"])',
      'e0a5ae35cdfee6f036d5f6a5d55e576f56a82d0181d55be978e29c6602acb1c0',
    ],
    [
      'a list of tool definitions with an input schema',
      'src/tools.mjs',
      'export function buildTools(api) {\n  return [{ name: "open", inputSchema: { type: "object", properties: { url: { type: "string" } } }, handler: async (args) => launch(args.url) }];\n}\nasync function launch(url) {\n  const { spawn } = await import("node:child_process");\n  const override = String(process.env.MY_BROWSER || "");\n  spawn(override, [url], { detached: true });\n}\n',
      'spawn',
      'spawn(override, [url], { detached: true })',
      '4c908c69e86cd552df7b594d81262f21937690007cae20176a8c50fea7cd0f0c',
    ],
    [
      'an MCP client that calls tools',
      'pkg/client.py',
      'import subprocess\n\n\nclass Client:\n    def __init__(self, command):\n        self.proc = subprocess.Popen([command, "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)\n\n    async def call_tool(self, name, arguments):\n        return await self._request("tools/call", {"name": name, "arguments": arguments})\n',
      'subprocess.Popen',
      'subprocess.Popen([command, "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)',
      '8b764d93ccce5e7e9e353b12d94e67ebd61ff412e8289928648c94ea977985c0',
    ],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.toolInput, false, `${name}: the tracker does not see this path`);
    assert.ok(!/no tool input reach/.test(f.description), `${name}: ${f.description}`);
    assert.ok(f.description.includes(`\`${method}(…)\` ${NEUTRAL}`), `${name}: ${f.description}`);
    assert.match(f.title, NEW_TITLE);
    assert.equal(f.remediation, OLD_REMEDIATION);
    assertSame117(f, evidence, fingerprint);
  }
});

// --- S2. Only a file with no sign of MCP or tools hears what the scanner did not see ---
//
// The tool-input tracker knows a few handler shapes; frameworks it does not know
// still run tools whose input can choose the program (final round 1: R3-01, R3-03).
// So the confident sentence and the "Nothing to fix" remediation are kept for a
// file with no sign of MCP or tools at all: "tool" or "mcp" in a name of its code,
// either word in an import or require specifier, `tools/call`, a tool input schema,
// or a recognised handler. Everywhere else a reworded finding says what is always
// true and keeps the 1.17 remediation.

test('S2: tool frameworks the tracker does not know mark the file (mcp-nest @Tool, mcp-framework MCPTool, xmcp ToolMetadata, a Python @register_tool, a tool input schema, an MCP SDK import)', async () => {
  for (const [name, path, content, method, evidence, fingerprint] of [
    [
      "@rekog/mcp-nest @Tool() method",
      "src/run.tool.ts",
      "import { Injectable } from '@nestjs/common';\nimport { Tool } from '@rekog/mcp-nest';\nimport { z } from 'zod';\nimport { execFileSync } from 'node:child_process';\n\n@Injectable()\nexport class RunTool {\n  @Tool({\n    name: 'run-program',\n    description: 'Run a program on the host',\n    parameters: z.object({ bin: z.string(), args: z.array(z.string()) }),\n  })\n  async run({ bin, args }: { bin: string; args: string[] }) {\n    return { content: [{ type: 'text', text: execFileSync(bin, args).toString() }] };\n  }\n}\n",
      "execFileSync",
      "execFileSync(bin, args)",
      "115a0df884e6b878896e1805dcb10cafa6b7bab718d1858d7de490d11c1d6afd",
    ],
    [
      "mcp-framework class extends MCPTool",
      "src/tools/RunTool.ts",
      "import { MCPTool } from \"mcp-framework\";\nimport { z } from \"zod\";\nimport { execFileSync } from \"child_process\";\n\ninterface RunInput {\n  bin: string;\n  args: string[];\n}\n\nclass RunTool extends MCPTool<RunInput> {\n  name = \"run_program\";\n  description = \"Run a program on the host\";\n  schema = {\n    bin: { type: z.string(), description: \"Program to run\" },\n    args: { type: z.array(z.string()), description: \"Arguments\" },\n  };\n\n  async execute(input: RunInput) {\n    return execFileSync(input.bin, input.args).toString();\n  }\n}\n\nexport default RunTool;\n",
      "execFileSync",
      "execFileSync(input.bin, input.args)",
      "59ded46a083cb66937de56818e2b11862ccf60d87f5c0174621d3f171c5c0ff4",
    ],
    [
      "xmcp file tool with ToolMetadata",
      "src/tools/run.ts",
      "import { z } from \"zod\";\nimport { type InferSchema, type ToolMetadata } from \"xmcp\";\nimport { execFileSync } from \"node:child_process\";\n\nexport const schema = {\n  bin: z.string().describe(\"Program to run\"),\n  args: z.array(z.string()).describe(\"Arguments\"),\n};\n\nexport const metadata: ToolMetadata = {\n  name: \"run_program\",\n  description: \"Run a program on the host\",\n};\n\nexport default async function run({ bin, args }: InferSchema<typeof schema>) {\n  return execFileSync(bin, args).toString();\n}\n",
      "execFileSync",
      "execFileSync(bin, args)",
      "6eaf404b54baa25c639eaf71da0681bf2338652ee1568a47f91709859d2bde22",
    ],
    [
      "a custom Python @register_tool decorator",
      "pkg/tools.py",
      "import subprocess\nfrom .registry import register_tool\n\n\n@register_tool(\"run\")\ndef run(binary: str) -> str:\n    return subprocess.run([binary, \"--version\"], capture_output=True, text=True).stdout\n",
      "subprocess.run",
      "subprocess.run([binary, \"--version\"], capture_output=True, text=True)",
      "1025243d7faf1696e8327a50552f22cfd856edad9162c8414c46368c61cf955c",
    ],
    [
      "only a tool input schema in a string",
      "pkg/spec.py",
      "import subprocess\n\nSPEC = {\"name\": \"run\", \"input_schema\": {\"type\": \"object\"}}\n\n\ndef run(binary):\n    return subprocess.run([binary, \"--version\"], capture_output=True, text=True)\n",
      "subprocess.run",
      "subprocess.run([binary, \"--version\"], capture_output=True, text=True)",
      "264b373d4ad6b9784dff3e2a98bfe755507c06730d913916b7dec3dc453a03f7",
    ],
    [
      "only an MCP SDK require specifier",
      "src/server.js",
      "const sdk = require(\"@modelcontextprotocol/sdk/server/index.js\");\nconst { execFile } = require(\"child_process\");\nexports.start = (bin) => { sdk.boot(); return execFile(bin, [\"--stdio\"]); };\n",
      "execFile",
      "execFile(bin, [\"--stdio\"])",
      "d6378b37137f34d9764e70b965f2eed70d5c0cfc4d91b36650a7b799a56f79e0",
    ],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.toolInput, false, `${name}: the tracker does not see this handler`);
    assert.match(f.title, NEW_TITLE);
    assert.ok(!/no tool input reach/.test(f.description), `${name}: ${f.description}`);
    assert.ok(f.description.includes(`\`${method}(…)\` ${NEUTRAL}`), `${name}: ${f.description}`);
    assert.equal(f.remediation, OLD_REMEDIATION, name);
    assertSame117(f, evidence, fingerprint);
  }
});

test('S2: a file-based tool with no "tool" or "mcp" in its names is still marked: a schema, an MCP tool annotation (final round 2: FR1-03)', async () => {
  for (const [name, path, content, method, evidence, fingerprint] of [
    [
      'xmcp without its type imports, with tool annotations',
      'src/tools/run-binary.ts',
      'import { z } from "zod";\nimport { execFileSync } from "node:child_process";\n\nexport const schema = {\n  bin: z.string().describe("Binary to run"),\n  args: z.array(z.string()).describe("Arguments"),\n};\n\nexport const metadata = {\n  name: "run-binary",\n  description: "Run a local binary and return its output",\n  annotations: { destructiveHint: true, openWorldHint: false },\n};\n\nexport default async function runBinary({ bin, args }: { bin: string; args: string[] }) {\n  return execFileSync(bin, args, { encoding: "utf8" });\n}\n',
      'execFileSync',
      'execFileSync(bin, args, { encoding: "utf8" })',
      'ee9fe6e73767bc3f89b9a63a3ccc14cfdd73e26876b1e23d0dd580c25bb81f75',
    ],
    [
      'xmcp without its type imports or annotations: only the schema',
      'src/tools/run.ts',
      'import { z } from "zod";\nimport { execFileSync } from "node:child_process";\n\nexport const schema = {\n  bin: z.string(),\n  args: z.array(z.string()),\n};\n\nexport const metadata = { name: "run", description: "Run a binary" };\n\nexport default async function run({ bin, args }: { bin: string; args: string[] }) {\n  return execFileSync(bin, args, { encoding: "utf8" });\n}\n',
      'execFileSync',
      'execFileSync(bin, args, { encoding: "utf8" })',
      '91a7f830ffe59db051f3c73f47119fa3597df824d74564e79a884c0b38c1d4b0',
    ],
    [
      'a Python tool annotation in a dict',
      'pkg/run.py',
      'import subprocess\n\nANNOTATIONS = {"readOnlyHint": False, "destructiveHint": True}\n\n\ndef run(binary):\n    return subprocess.run([binary, "--version"], capture_output=True, text=True)\n',
      'subprocess.run',
      'subprocess.run([binary, "--version"], capture_output=True, text=True)',
      '25dac9f134a98ba7f7dc16405411b8018b4e8d009c0ae4c20a2224914d194845',
    ],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.toolInput, false, name);
    assert.match(f.title, NEW_TITLE);
    assert.ok(f.description.includes(`\`${method}(…)\` ${NEUTRAL}`), `${name}: ${f.description}`);
    assert.equal(f.remediation, OLD_REMEDIATION, name);
    assertSame117(f, evidence, fingerprint);
  }
});

test('S2: a bound process function recorded as a value keeps the 1.17 words in any syntax (probe v3-07)', async () => {
  for (const [name, path, content, method, evidence, fingerprint] of [
    [
      "spawn[\"sync\"](a.cmd, \u2026)",
      "src/a-bracket.js",
      "const spawn = require(\"cross-spawn\");\nserver.tool(\"run\", { cmd: z.string(), args: z.array(z.string()) }, async (a) => {\n  const r = spawn[\"sync\"](a.cmd, a.args);\n  return { content: [{ type: \"text\", text: String(r.stdout) }] };\n});\n",
      "spawn",
      "string()) }, async (a) => { const r = spawn[\"sync\"](a.cmd, a.args); return { cont",
      "21a36bd309b413dfdf98d0116718c219f4d585f273b0e40a226adcb71de8253e",
    ],
    [
      "spawn.sync?.(a.cmd, \u2026)",
      "src/b-optional-call.js",
      "const spawn = require(\"cross-spawn\");\nserver.tool(\"run\", { cmd: z.string(), args: z.array(z.string()) }, async (a) => {\n  const r = spawn.sync?.(a.cmd, a.args);\n  return { content: [{ type: \"text\", text: String(r.stdout) }] };\n});\n",
      "spawn",
      "string()) }, async (a) => { const r = spawn.sync?.(a.cmd, a.args); return { conte",
      "520411a751542138c414629b79d75081dc553813ec0cf0698dadd242d3917ec9",
    ],
    [
      "(spawn.sync)(a.cmd, \u2026)",
      "src/c-paren-member.js",
      "const spawn = require(\"cross-spawn\");\nserver.tool(\"run\", { cmd: z.string(), args: z.array(z.string()) }, async (a) => {\n  const r = (spawn.sync)(a.cmd, a.args);\n  return { content: [{ type: \"text\", text: String(r.stdout) }] };\n});\n",
      "spawn",
      "tring()) }, async (a) => { const r = (spawn.sync)(a.cmd, a.args); return { conten",
      "57a7b78841c65b4fe5a67ef6e633e00825ca52281f625304dcb5f75a44afd0e9",
    ],
    [
      "spawn[\"call\"](null, a.cmd, \u2026)",
      "src/e-cp-bracket-call.js",
      "const { spawn } = require(\"child_process\");\nserver.tool(\"run\", { cmd: z.string() }, async (a) => {\n  const child = spawn[\"call\"](null, a.cmd, [], {});\n  return { content: [{ type: \"text\", text: String(child.pid) }] };\n});\n",
      "spawn",
      "ing() }, async (a) => { const child = spawn[\"call\"](null, a.cmd, [], {}); return",
      "83e5a49e8fc364ca2410b44a6d8bcbc8dfd49656d1c3f1b3d4f0b24a3751d1ef",
    ],
    [
      "a.cmds.map(execFileSync)",
      "src/f-map-receiver.js",
      "const { execFileSync } = require(\"child_process\");\nserver.tool(\"run\", { cmds: z.array(z.string()) }, async (a) => {\n  const out = a.cmds.map(execFileSync);\n  return { content: [{ type: \"text\", text: out.join(\"\\n\") }] };\n});\n",
      "execFileSync",
      "async (a) => { const out = a.cmds.map(execFileSync); return { content: [{ type: \"text\",",
      "d6e7841a08d79b4c4bc5764d161e613e84f493d4a143a2ad581037f5ae11bf40",
    ],
    [
      "Reflect.apply(execFileSync, null, [a.cmd])",
      "src/g-reflect-control.js",
      "const { execFileSync } = require(\"child_process\");\nserver.tool(\"run\", { cmd: z.string() }, async (a) => {\n  const out = Reflect.apply(execFileSync, null, [a.cmd]);\n  return { content: [{ type: \"text\", text: String(out) }] };\n});\n",
      "execFileSync",
      "nc (a) => { const out = Reflect.apply(execFileSync, null, [a.cmd]); return { content: [{",
      "52372e7144ffde8655fc418b378565f9cc3771017e87dc5ab5d4cf535ef0898c",
    ],
    [
      "spawn.sync(a.cmd, \u2026) (the dot form)",
      "src/d-dot-control.js",
      "const spawn = require(\"cross-spawn\");\nserver.tool(\"run\", { cmd: z.string(), args: z.array(z.string()) }, async (a) => {\n  const r = spawn.sync(a.cmd, a.args);\n  return { content: [{ type: \"text\", text: String(r.stdout) }] };\n});\n",
      "spawn",
      "string()) }, async (a) => { const r = spawn.sync(a.cmd, a.args); return { content",
      "ca07b19786f3cd6c864503b48a43fae4909837a67eb8424e00f008cdc40ff81f",
    ],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.toolInput, false, `${name}: a call recorded without its arguments, as in 1.17`);
    assert.ok(!/no tool input reach|cannot see the arguments/.test(f.description), `${name}: ${f.description}`);
    assert.equal(f.remediation, OLD_REMEDIATION, name);
    assertSame117(f, evidence, fingerprint);
    // Handed on as a value or used right there, in any syntax: the record does not say which, so the 1.17 words.
    assert.match(f.title, OLD_TITLE, name);
    assert.ok(f.description.includes(`\`${method}(…)\` — ${OLD_WORDS}`), `${name}: ${f.description}`);
  }
});

test('S2: a member or a type of a bound process function keeps the 1.17 words in a file with no sign either (final round 2: P1, P5)', async () => {
  // The program here is the literal `git`, or nothing runs at all: "Runs a program resolved at runtime" would be false.
  for (const [name, path, content, method, evidence, fingerprint] of [
    ['compiled (0, execa.execa)("git", …)', 'src/git.js', 'const execa = require("execa");\nasync function diff(dir) {\n  return (0, execa.execa)("git", ["diff"], { cwd: dir });\n}\nmodule.exports = { diff };\n', 'execFile', 'async function diff(dir) { return (0, execa.execa)("git", ["diff"], { cwd: dir });', '1b4bbcaac18b4eaee9f68deed2e448eaa80c6b219e42948d34a3021fbd5f1a2c'],
    ['parenthesized (spawn.sync)("git", …)', 'src/cs.js', 'const spawn = require("cross-spawn");\nfunction st() {\n  return (spawn.sync)("git", ["status"]);\n}\nmodule.exports = { st };\n', 'spawn', 'ross-spawn"); function st() { return (spawn.sync)("git", ["status"]); } module.expo', '7906c481a0a4631cef43041d5104e9c6215639121318b8b33e956140849431fe'],
    ['a member on the next line', 'src/nl.js', 'const spawn = require("cross-spawn");\nfunction st() {\n  return spawn\n    .sync("git", ["status"]);\n}\nmodule.exports = { st };\n', 'spawn', 'cross-spawn"); function st() { return spawn .sync("git", ["status"]); } module.', 'a19cb7f783f37822c4faa6b1731c7011d11e16bb49afbcf0991f2efff683daeb'],
    ['ReturnType<typeof spawnSync>', 'src/types.ts', 'import { spawnSync, execFileSync } from "node:child_process";\nfunction failed(r: ReturnType<typeof spawnSync>): boolean { return r.status !== 0; }\nexport function v(): string { return execFileSync("git", ["--version"]).toString(); }\nexport { failed };\n', 'spawnSync', '"; function failed(r: ReturnType<typeof spawnSync>): boolean { return r.status !== 0; } e', '711d88eff092315e6244c6815bf0d54ade3047dc3d5c4fe7131d964e8cccebd5'],
    ['spawnImpl?: typeof nodeSpawn', 'src/opts.ts', 'import { spawn as nodeSpawn } from "node:child_process";\nexport interface Options {\n  spawnImpl?: typeof nodeSpawn;\n}\n', 'spawn', 'nterface Options { spawnImpl?: typeof nodeSpawn; }', 'd0e1af61e957979512f85170cbb1a2f46d06054cf12e85aed7f200d727bd9f85'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.calls[0].program, '<passed on as a value>', name);
    assert.match(f.title, OLD_TITLE, name);
    assert.ok(f.description.includes(`\`${method}(…)\` — ${OLD_WORDS}`), `${name}: ${f.description}`);
    assert.equal(f.remediation, OLD_REMEDIATION, name);
    assertSame117(f, evidence, fingerprint);
  }
});

test('S2: a plain helper with no sign of MCP or tools keeps the confident sentence and remediation; "mcp" in a comment alone is no sign', async () => {
  for (const [name, path, content, method] of [
    ['a JS helper', 'src/git.js', 'const { execFile } = require("child_process");\n// Runs git for the sops-mcp CLI.\nfunction runGit(gitPath, args) {\n  return execFile(gitPath, args, { label: "git" });\n}\nmodule.exports = { runGit };\n', 'execFile'],
    ['a Python helper', 'pkg/runner.py', 'import subprocess\n\n\ndef run_binary(path, args):\n    """Run a binary."""\n    return subprocess.run([path, *args], capture_output=True, text=True)\n', 'subprocess.run'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.match(f.title, NEW_TITLE);
    assert.ok(f.description.includes(`\`${method}(…)\` ${SAW_NO_INPUT}`), `${name}: ${f.description}`);
    assert.equal(f.remediation, NEW_REMEDIATION, name);
  }
});

test('S2: "tool" or "schema" anywhere in the text is a sign, in a comment, a string or code the lexer misreads; so is "tool" in the path and "mcp" on an import line', async () => {
  const cp = 'const { execFile } = require("child_process");\n';
  const run = 'exports.run = (bin, args) => execFile(bin, args);\n';
  for (const [name, path, content] of [
    ['a comment', 'src/a.js', `${cp}// Runs the CLI tool.\n${run}`],
    ['a string', 'src/b.js', `${cp}const LABEL = "input schema";\n${run}`],
    ['a Python docstring', 'pkg/c.py', 'import subprocess\n\n\ndef run(path, args):\n    """Run a tool binary."""\n    return subprocess.run([path, *args])\n'],
    ['the path', 'src/tools/d.js', `${cp}${run}`],
    ['an import specifier', 'src/e.js', `${cp}const sdk = require("@modelcontextprotocol/sdk/server/index.js");\n${run}`],
    ['a Python import', 'pkg/f.py', 'import subprocess\nfrom mcp.server import Server\n\n\ndef run(path, args):\n    return subprocess.run([path, *args])\n'],
    // After `USAGE = """… \\""" …"""` the Python lexer reads the rest of the file as a string.
    ['a handler the lexer reads as a string', 'pkg/g.py', 'import subprocess\n\nUSAGE = """say \\""" twice"""\n\n\n@app.tool()\ndef run(path, args):\n    return subprocess.run([path, *args])\n'],
  ] as const) {
    const f = await one(content, path);
    assert.ok(!/saw no tool input/.test(f.description), `${name}: ${f.description}`);
    if (NEW_TITLE.test(f.title)) {
      assertCodeExec(f);
      assert.ok(f.description.includes(NEUTRAL), `${name}: ${f.description}`);
      assert.equal(f.remediation, OLD_REMEDIATION, name);
    }
  }
});

test('S2: the sign check is linear on a long run of blanks after `import` and on one long line of "mcp" strings', async () => {
  const cp = 'const { execFile } = require("child_process");\nexports.run = (bin, args) => execFile(bin, args);\n';
  for (const content of [`${cp}// import${' '.repeat(200000)}x\n`, `${cp}const L = [${'"mcp",'.repeat(60000)}];\n`]) {
    const t0 = performance.now();
    const f = await one(content);
    const ms = performance.now() - t0;
    assertCodeExec(f);
    assert.match(f.title, NEW_TITLE);
    // "mcp" more than a thousand times, even only in strings, is a sign; a comment that ends in "import" is not.
    assert.ok(f.description.includes(content.includes('"mcp"') ? NEUTRAL : SAW_NO_INPUT), f.description.slice(0, 300));
    // The draft's specifier regex took 6 s on 80,000 blanks.
    assert.ok(ms < 1500, `${ms.toFixed(0)} ms`);
  }
});

test('S2: the score and the client score of a text-only change equal those of the same code with tool input hidden', async () => {
  const hidden = await scan([{ path: 'src/x.js', content: 'const { execFile } = require("child_process");\nexports.version = (bin) => execFile(bin, ["--version"]);\n' }]);
  const visible = await scan([{ path: 'src/x.js', content: 'const { execFile } = require("child_process");\nserver.tool("v", {}, async (a) => execFile(a.bin, ["--version"]));\n' }]);
  const f = (r: any) => r.findings.find((x: any) => x.ruleId === 'MTC-SRC-002');
  assert.equal(f(hidden).data.toolInput, false);
  assert.equal(f(visible).data.toolInput, true);
  assert.equal(f(hidden).severity, f(visible).severity);
  assert.equal(f(hidden).confidence, f(visible).confidence);
  assert.equal(hidden.score.score, visible.score.score);
  assert.equal(hidden.score.threatScore, visible.score.threatScore);
});

// --- S3. Tool input in the program and the options of a runtime-program call ---

// --- S2: words that are true by construction ------------------------------------
//
// 'new': "`m(…)` runs a program resolved at runtime … In this file the scanner saw no
// tool input reach …" with the advice remediation; 'tell': the same first sentence, "The
// scanner cannot tell …" and the 1.17 remediation (a sign of MCP or tools in the text or
// the path); 'old': the exact 1.17 title, words and remediation. Every row keeps the
// 1.17.0 severity, shape, evidence and fingerprint, and no row is told there is nothing
// to fix.
const WORDING: ReadonlyArray<readonly [string, string, string, 'new' | 'tell' | 'old', string, string, string]> = [
  ["a comment before a literal program (Python # noqa)", "src/a.py", "import subprocess\n\n\ndef head(root):\n    return subprocess.run(  # noqa: S603\n        [\"git\", \"rev-parse\", \"HEAD\"], cwd=root, capture_output=True)\n", "old", "dynamic-program", "subprocess.run( # noqa: S603 [\"git\", \"rev-parse\", \"HEAD\"], cwd=root, capture_output=True)", "94bc8db08bacb7afbcc35e44c7111df0a80427b051a89e567a6d3c96837fe753"],
  ["a list concatenation that starts with a literal", "src/b.py", "import subprocess\n\n\ndef run(args):\n    return subprocess.run([\"git\"] + args, capture_output=True)\n", "old", "dynamic-program", "subprocess.run([\"git\"] + args, capture_output=True)", "b758f28ac0cc3ef5fa66693976fd39909f8669765307d3f4d541de4e5df224db"],
  ["a tuple", "src/c.py", "import subprocess\n\n\ndef size():\n    return subprocess.run((\"paperconf\", \"-s\"), capture_output=True)\n", "old", "dynamic-program", "subprocess.run((\"paperconf\", \"-s\"), capture_output=True)", "ed19a4f4343d018a4f3927616892ae9debbeb42c9289b882798f31468e22a018"],
  ["a wrapper call with a literal argument", "src/d.py", "import subprocess\n\n\ndef ls(root):\n    return subprocess.run(wrap([\"ls-files\"]), cwd=root)\n", "old", "dynamic-program", "subprocess.run(wrap([\"ls-files\"]), cwd=root)", "98d95b5f5fc395fec0dd6e603d5eea9efbf502f2fa8f6e767cb07c97132c5b0e"],
  ["a fallback literal: env.X ?? \"npx\"", "src/e.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (pkg) => spawn(process.env.RUNNER ?? \"npx\", [pkg]);\n", "old", "dynamic-program", "spawn(process.env.RUNNER ?? \"npx\", [pkg])", "5c740d413498d61274b470166466f9eb95708a4c31188c73cc114a3b830d92f5"],
  ["a lookup with a literal: which(\"uvx\")", "src/f.py", "import shutil\nimport subprocess\n\n\ndef run(pkg):\n    return subprocess.run([shutil.which(\"uvx\"), pkg])\n", "old", "dynamic-program", "subprocess.run([shutil.which(\"uvx\"), pkg])", "ef9517d838272adf4c0b015ed00b36962d5e07820bb279002373a7106f03d1e0"],
  ["a block comment before the program (JS)", "src/g.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (bin, args) => execFile(/* the tool */ bin, args);\n", "old", "dynamic-program", "execFile(/* the tool */ bin, args)", "f6a1f8b217968da78eeda37ea6a1c193023a09ec3ea89f31472c7a97f89f6891"],
  ["a template literal program", "src/h.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (dir, args) => execFile(`${dir}/bin/tool`, args);\n", "old", "dynamic-program", "execFile(`${dir}/bin/tool`, args)", "e1c83016481082ea06f5cb8a38157cfa54aeecdcb48f3f2328431ff4b359b8e6"],
  ["$SHELL -lc <command>", "src/i.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (command) => execFile(process.env.SHELL, [\"-lc\", command]);\n", "old", "dynamic-program", "execFile(process.env.SHELL, [\"-lc\", command])", "f98e3cb214b3e13e8a2576d8f51677cc7ec28276c2f15a7f367420c321e932f7"],
  ["%ComSpec% /d /c <command>", "src/j.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nconst CMD = process.env.ComSpec;\nexports.open = (url) => spawn(CMD, [\"/d\", \"/c\", `start \"\" \"${url}\"`]);\n", "old", "dynamic-program", "spawn(CMD, [\"/d\", \"/c\", `start \"\" \"${url}\"`])", "cf320ad28ee5ac974e6c158e479ffbeac832db62a09a925d536986059cba858f"],
  ["pwsh -EncodedCommand <script>", "src/k.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (pwsh, script) => execFileSync(pwsh, [\"-EncodedCommand\", script]);\n", "old", "dynamic-program", "execFileSync(pwsh, [\"-EncodedCommand\", script])", "292623245d6cc5b457552912cda5256af20396ac9646360993f17fe5007bf2eb"],
  ["Python [SHELL, \"-c\", line]", "src/l.py", "import os\nimport subprocess\n\nSHELL = os.environ.get\n\n\ndef run(shell, line):\n    return subprocess.run([shell, \"-c\", line])\n", "old", "dynamic-program", "subprocess.run([shell, \"-c\", line])", "1dcff31e905d314c1f956a80d6f4a07d87ef7ce55c2545c57f543347e97de3a2"],
  ["runtime -e <code>", "src/m.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (node, code) => spawn(node, [\"-e\", code]);\n", "old", "dynamic-program", "spawn(node, [\"-e\", code])", "a8273b680ae6039bd5174b697392db5754c282e459da60fb61261fd88e55321e"],
  ["a plain parameter with ordinary flags (git -C dir)", "src/n.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.status = (gitBin, dir) => spawn(gitBin, [\"-C\", dir, \"status\"]);\n", "new", "dynamic-program", "spawn(gitBin, [\"-C\", dir, \"status\"])", "78b90991df3911c920aa877a2eb5b68663789841b056ceb38cf5377fe3d1cbeb"],
  ["a member chain", "src/o.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cfg, args) => execFile(cfg.paths.bin, args);\n", "new", "dynamic-program", "execFile(cfg.paths.bin, args)", "ccc7355d1cfb449d03c37f6c53e913763d1e4a28131155201cc5c91808154f9e"],
  ["Python self.binary", "src/p.py", "import subprocess\n\n\nclass Runner:\n    def run(self, path):\n        return subprocess.run([self.binary, \"--check\", path])\n", "new", "dynamic-program", "subprocess.run([self.binary, \"--check\", path])", "0a322e4ef2d35f5655b956344df555477d23cb20fb68c36220634383dcb3c75f"],
  ["Python list of names plus names (not one inline list)", "src/q.py", "import subprocess\n\n\ndef run(binary, args):\n    return subprocess.run([binary] + args)\n", "old", "dynamic-program", "subprocess.run([binary] + args)", "f47c1788ee7d95b9e6d2a1c916a97c257853b6422696184c51a2e88df58c1ba7"],
  ["runtime program first, node -e later", "src/r1.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nconst BIN = process.env.APP_BIN;\nexports.version = () => execFile(BIN, [\"--version\"]);\nexports.evaluate = (code) => spawn(\"node\", [\"-e\", code]);\n", "old", "dynamic-program", "execFile(BIN, [\"--version\"])", "b0ee70216f743af9bd340786f2f1dcb64353ab9a230c79243c7e4053be3aad0f"],
  ["node -e first, runtime program later", "src/r2.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nconst BIN = process.env.APP_BIN;\nexports.evaluate = (code) => spawn(\"node\", [\"-e\", code]);\nexports.version = () => execFile(BIN, [\"--version\"]);\n", "old", "dynamic-program", "spawn(\"node\", [\"-e\", code])", "f1ddd039eb84bd538d9582c90f1d342029e97e7fb38edfddd10bc3a156e28d79"],
  ["runtime program first, a shell later", "src/r3.js", "const { execFile, exec } = require(\"child_process\");\nconst BIN = process.env.APP_BIN;\nexports.version = () => execFile(BIN, [\"--version\"]);\nexports.sh = (line) => exec(line);\n", "old", "shell-dynamic", "exec(line)", "98ed3de526f5f59bbef7cee3159837705cf2e659030a2367e736f7e2aaee715d"],
  ["two runtime programs", "src/r4.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nconst BIN = process.env.APP_BIN;\nexports.version = () => execFile(BIN, [\"--version\"]);\nexports.run = (other, args) => spawn(other, args);\n", "new", "dynamic-program", "execFile(BIN, [\"--version\"])", "d48d958905df3fa1ac47be148d6a8efa8dd0d2a29a7623a974876b0a076ec000"],
  ["passed as an argument", "src/s1.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.start = (cmd) => runWith(cmd, spawn);\n", "old", "dynamic-program", "; exports.start = (cmd) => runWith(cmd, spawn);", "28776052e1259b8b7aa5c3f989c21e52e7486c69b48d33925bc220db8f71216b"],
  ["in an object shorthand", "src/s2.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nmodule.exports = { spawn, name: 1 };\n", "old", "dynamic-program", "re(\"child_process\"); module.exports = { spawn, name: 1 };", "21afb1354cda7948fd0dda7ea2cfca2859396c15557a3a802acd7abdbc6e7874"],
  ["assigned to a name", "src/s3.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nlet impl;\nimpl = spawn;\nexports.set = (f) => { impl = f; };\n", "old", "dynamic-program", "uire(\"child_process\"); let impl; impl = spawn; exports.set = (f) => { impl = f; };", "20cc1005e362bcf0e87e432fa1ae0045adf03a7e55301811e0666d3bb40bf93a"],
  ["(spawn)(\"git\", …)", "src/t1.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = () => (spawn)(\"git\", [\"status\"]);\n", "old", "dynamic-program", "(\"child_process\"); exports.run = () => (spawn)(\"git\", [\"status\"]);", "8df2271268d927047494d55b9c8af920cdf4a76a5b7800d306460b4a0e8b12a3"],
  ["(0, spawnSync)(\"git\", …)", "src/t2.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = () => (0, spawnSync)(\"git\", [\"status\"]);\n", "old", "dynamic-program", "hild_process\"); exports.run = () => (0, spawnSync)(\"git\", [\"status\"]);", "6217522ae086ab4944de5b73f11a776edc563a1a629a1a4393bc3ee2dfadf97e"],
  ["execFileSync!(\"git\", …) (TypeScript)", "src/t3.ts", "import { execFileSync } from \"child_process\";\nexport const run = () => execFileSync!(\"git\", [\"--version\"]);\n", "old", "dynamic-program", "hild_process\"; export const run = () => execFileSync!(\"git\", [\"--version\"]);", "dadaf1ddbeac6316ad8b5d9d1bbfd6f4f76034afde3252cc0db727ef62e8e386"],
  ["a comment before a member", "src/t4.js", "const spawn = require(\"cross-spawn\");\nexports.run = () => spawn /* sync */ .sync(\"git\", [\"status\"]);\n", "old", "dynamic-program", "ire(\"cross-spawn\"); exports.run = () => spawn /* sync */ .sync(\"git\", [\"status\"]);", "6d9a2cf44a8022db2868def2a67046395e183a0fd0422aa91b68f7c4272c1e75"],
  ["a cast before a member (TypeScript)", "src/t5.ts", "import spawn from \"cross-spawn\";\nexport const run = () => (spawn as any).sync(\"git\", [\"status\"]);\n", "old", "dynamic-program", "cross-spawn\"; export const run = () => (spawn as any).sync(\"git\", [\"status\"]);", "61c0a3873ab2da95e2b82126f8ec2786edc749aad1c147421acb618c55f70f03"],
  ["a tagged template", "src/t6.js", "import { execa } from \"execa\";\nexport const head = () => execa`git rev-parse HEAD`;\n", "old", "dynamic-program", "from \"execa\"; export const head = () => execa`git rev-parse HEAD`;", "3ff0c848182d9cdba596a9311648c3e9fd9e1efa2965660f08294c1926a1917d"],
  ["handed on, then the result called", "src/t7.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = () => wrap(spawn)(\"git\", [\"status\"]);\n", "old", "dynamic-program", "ild_process\"); exports.run = () => wrap(spawn)(\"git\", [\"status\"]);", "2f25dd503daa3124d0c73100025b6898d17e5ed16d6d0248bd9360c4905fe528"],
  ["a call: getBin()", "src/u1.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (args) => execFile(getBin(), args);\n", "old", "dynamic-program", "execFile(getBin(), args)", "01ea5db6a4ba4e37ab3820197ba704d18d6104aabac24ff34edfc27640fdab62"],
  ["a cast of a literal with generics (TypeScript)", "src/u2.ts", "import { execFile } from \"child_process\";\ntype Brand<T, B> = T & { b: B };\nexport const run = (args: string[]) => execFile(<Brand<string, \"bin\">>\"node\", args);\n", "old", "dynamic-program", "execFile(<Brand<string, \"bin\">>\"node\", args)", "e585fc25c62b0c57faae0eaaebac2824e752b44c72f6fd591c4da12c6b5a638d"],
  ["a generic helper around a literal (TypeScript)", "src/u3.ts", "import { execFile } from \"child_process\";\ndeclare function asBin<T, U>(x: T): T;\nexport const run = (args: string[]) => execFile(asBin<string, never>(\"/usr/bin/git\"), args);\n", "old", "dynamic-program", "execFile(asBin<string, never>(\"/usr/bin/git\"), args)", "044e45cb93d5b82f1b455f2d1901a670df164ebdabfbb5ea3147e603ece00c61"],
  ["a program built from character codes", "src/u4.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (script) => execFile(String.fromCharCode(47, 98, 105, 110, 47, 115, 104), [script]);\n", "old", "dynamic-program", "execFile(String.fromCharCode(47, 98, 105, 110, 47, 115, 104), [script])", "635a361d4b568017941b6f426eab98d465a8959e0b4726bbc5902f010b541201"],
  ["a ternary", "src/u5.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (a, b, args) => spawn(process.platform === win ? a : b, args);\n", "old", "dynamic-program", "spawn(process.platform === win ? a : b, args)", "e1a77ed96e09bbeddbd689ce19395c9089ccb955ac76566cc862f8e2757aaa2d"],
  ["an await", "src/u6.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = async (find, args) => spawn(await find, args);\n", "old", "dynamic-program", "spawn(await find, args)", "15af3f2fdeda47c802f23778cf5b39e4ef39a557cce887e36300ab3fb13f174f"],
  ["Python: the program by keyword args=", "src/u7.py", "import subprocess\n\n\ndef status(root):\n    return subprocess.run(args=[\"git\", \"status\"], cwd=root)\n", "old", "dynamic-program", "subprocess.run(args=[\"git\", \"status\"], cwd=root)", "6696e749cfcc673d7a84cd13d12c50288aba6a27d0d4a1c9830a64d466e33c17"],
  ["Python: executable= names the program", "src/u8.py", "import subprocess\n\n\ndef run(argv):\n    return subprocess.run(argv, executable=\"/bin/sh\")\n", "old", "dynamic-program", "subprocess.run(argv, executable=\"/bin/sh\")", "cd6217c7c17cb6a490c6386077bf2cdad0bc10386784de6d9671b2008a2b8236"],
  ["Python: a call around the program", "src/u9.py", "import subprocess\n\n\ndef run(path, args):\n    return subprocess.run([str(path), *args])\n", "old", "dynamic-program", "subprocess.run([str(path), *args])", "504a8d08a750f84e318a34e468ecedc77b33353892fdb428e74097c031878e8d"],
  ["an element of a name: argv[0]", "src/v1.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (argv) => spawn(argv[0], argv.slice(1));\n", "new", "dynamic-program", "spawn(argv[0], argv.slice(1))", "b000f4fc9a4602c58c1ecfce0f2c1c1c71efa23e180826732f32b5a6f4e68fb5"],
  ["an optional member: cfg?.bin", "src/v2.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cfg, args) => execFile(cfg?.bin, args);\n", "new", "dynamic-program", "execFile(cfg?.bin, args)", "61dacb00c825b47bf825f9717bc5874984118093cd20668f89b10185d24dbd07"],
  ["Python: a splat *argv", "src/v3.py", "import asyncio\n\n\nasync def run(argv):\n    return await asyncio.create_subprocess_exec(*argv)\n", "new", "dynamic-program", "asyncio.create_subprocess_exec(*argv)", "b86358af5fe735a011dffb23ac12b7cea4598d780aa7ea4e557f292d8ab33a7f"],
  ["Python: a list in a name", "src/v4.py", "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, capture_output=True)\n", "new", "dynamic-program", "subprocess.run(cmd, capture_output=True)", "e28780c16a5249dd4050489e067b196b24d919c0dbfd4f32b9ec5d7a6ea59c68"],
  ["a sign only in a comment", "src/w1.js", "// Handlers for the MCP tools.\nconst { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (bin, args) => execFile(bin, args);\n", "tell", "dynamic-program", "execFile(bin, args)", "7210aecc6fb22d1603c3b18fd3caa885e35596bb6156aadd7fd04c5440cbac10"],
  ["\"mcp\" only in a comment is no sign", "src/w0.js", "// Part of the sops-mcp CLI.\nconst { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (bin, args) => execFile(bin, args);\n", "new", "dynamic-program", "execFile(bin, args)", "4e108e945fe34f6b08b50e63f26c7a6316c7472c2c8dc39e4963b7eb53ce275e"],
  ["a sign only in a string", "src/w2.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nconst NAME = \"run_tool\";\nexports.run = (bin, args) => execFile(bin, args);\n", "tell", "dynamic-program", "execFile(bin, args)", "0ce856fff924a5aa68084f3c184384e2ae937f452b77864c547c9f22f5892368"],
  ["a sign only in the path", "src/tools/exec.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (bin, args) => execFile(bin, args);\n", "tell", "dynamic-program", "execFile(bin, args)", "242efe7ce9022e24b568003fa1fbfd3179e68d772d9d98dce509f6eaee50eb70"],
  ["a JSON-RPC dispatch", "lib/rpc.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.handle = (msg) => (msg.jsonrpc ? execFile(msg.bin, msg.args) : null);\n", "tell", "dynamic-program", "execFile(msg.bin, msg.args)", "23373d22a0eefba0c1ec0aea355ba4a92f2d2d26b16473cb6785a571f1995f13"],
  ["a flag in a concat: [\"-c\"].concat(line)", "src/x1.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (sh, line) => spawn(sh, [\"-c\"].concat(line));\n", "old", "dynamic-program", "spawn(sh, [\"-c\"].concat(line))", "14ef421442545d2d57ce0aca8b89eb980aff6c0e8435df56d9b8760c415eeb52"],
  ["a flag in a ternary of arrays", "src/x2.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (sh, f, line) => execFile(sh, f ? [\"-c\", line] : [line]);\n", "old", "dynamic-program", "execFile(sh, f ? [\"-c\", line] : [line])", "d48ab2794623c6f699ca699a56a22479b4a2e82e90a77a808641e3ee8aebb150"],
  ["Python: a flag in a list concatenation", "src/x3.py", "import subprocess\n\n\ndef run(shell, line):\n    return subprocess.run([shell] + [\"-c\", line])\n", "old", "dynamic-program", "subprocess.run([shell] + [\"-c\", line])", "102ae20681ddc7a316b3795bd10c25ef915a28ba64a3d483b13a45c63ec575cb"],
  ["shell: true with a nested spread", "src/x6.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cmd, args) => spawn(cmd, args, { shell: true, env: { ...process.env } });\n", "old", "dynamic-program", "spawn(cmd, args, { shell: true, env: { ...process.env } })", "6f90e971d4cd78a9029e745fd931a4417ddf3639f1e9217cdbc50e4e0d86638d"],
  ["a shell key next to a spread", "src/x9.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cmd, args, win, extra) => spawn(cmd, args, { cwd: \"/\", shell: win, ...extra });\n", "old", "dynamic-program", "spawn(cmd, args, { cwd: \"/\", shell: win, ...extra })", "c4e0ed402dbc2519e78cb295de37c47bafcac9c82be8808419386cb3fd34df27"],
  ["options in a constant with shell: true", "src/x10.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nconst OPTS = { shell: true };\nexports.run = (cmd, args) => spawn(cmd, args, OPTS);\n", "old", "shell-dynamic", "spawn(cmd, args, OPTS)", "3ee42a775e46a237f9dec2d45f01a07404304c5084a1880304356b73975dea48"],
  ["options in a parameter", "src/x4.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cmd, args, opts) => spawn(cmd, args, opts);\n", "new", "dynamic-program", "spawn(cmd, args, opts)", "1531c413874e44e709212d415cb2883cee165beb61b64c004b58befe4d3f5a3d"],
  ["options with a spread and no shell key", "src/x5.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cmd, args, extra) => spawn(cmd, args, { cwd: \"/\", ...extra });\n", "new", "dynamic-program", "spawn(cmd, args, { cwd: \"/\", ...extra })", "fc30b550157c275240737e2ff8a44a7e6a0ad32f02d920a0c901e37cd622577a"],
  ["inline options without a shell key", "src/x7.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cmd, args, dir) => spawn(cmd, args, { cwd: dir, stdio: \"pipe\" });\n", "new", "dynamic-program", "spawn(cmd, args, { cwd: dir, stdio: \"pipe\" })", "c894d817a3eb86bf2109f158ff5b813477b572c068ac44eda97037d5def56656"],
  ["shell: false", "src/x8.js", "const { execFile, execFileSync, spawn, spawnSync } = require(\"child_process\");\nexports.run = (cmd, args) => spawn(cmd, args, { shell: false });\n", "new", "dynamic-program", "spawn(cmd, args, { shell: false })", "7f80e0fc80078e5563a509801900a4ef85053d1cea9ace0ef52af47259fd310e"],
];

for (const [name, path, content, expect, shape, evidence, fingerprint] of WORDING) {
  test(`S2 wording (${expect}) — ${name}`, async () => {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.callShape, shape);
    assertSame117(f, evidence, fingerprint);
    assert.ok(!/Nothing to fix if/.test(f.remediation), f.remediation);
    if (expect === 'old') {
      assert.match(f.title, OLD_TITLE);
      assert.equal(f.remediation, OLD_REMEDIATION);
      assert.ok(!/resolved at runtime|saw no tool input|cannot tell/.test(f.description), f.description);
    } else {
      assert.match(f.title, NEW_TITLE);
      assert.equal(f.remediation, expect === 'tell' ? OLD_REMEDIATION : NEW_REMEDIATION);
      assert.ok(f.description.includes(expect === 'tell' ? NEUTRAL : SAW_NO_INPUT), f.description);
    }
  });
}

test('S2 wording: every listed shell or eval flag keeps the 1.17 words; other flags do not', async () => {
  const file = (flag: string) => `const { execFile } = require("child_process");\nexports.run = (bin, x) => execFile(bin, [${JSON.stringify(flag)}, x]);\n`;
  for (const flag of ['-c', '-lc', '-ic', '-lic', '-e', '-p', '--eval', '--print', '--command', '--exec', '/c', '/C', '/k', '/r', '-Command', '-command', '-CommandWithArgs', '-EncodedCommand', '-enc']) {
    const f = await one(file(flag));
    assertCodeExec(f);
    assert.match(f.title, OLD_TITLE, flag);
    assert.equal(f.remediation, OLD_REMEDIATION, flag);
  }
  for (const flag of ['-C', '-v', '--version', '-m', '-i', '--config', 'status']) {
    const f = await one(file(flag));
    assertCodeExec(f);
    assert.match(f.title, NEW_TITLE, flag);
    assert.equal(f.remediation, NEW_REMEDIATION, flag);
  }
});

test('S2 wording: the order of a file\'s calls does not decide the words', async () => {
  const a = WORDING.find((w) => w[1] === 'src/r1.js')!;
  const b = WORDING.find((w) => w[1] === 'src/r2.js')!;
  const fa = await one(a[2], a[1]);
  const fb = await one(b[2], b[1]);
  assert.match(fa.title, OLD_TITLE);
  assert.match(fb.title, OLD_TITLE);
  assert.equal(fa.remediation, fb.remediation);
});

test('S3: tool input in the PROGRAM of a runtime-program call counts', async () => {
  const f = await one('const { execFile } = require("child_process");\nserver.tool("v", {}, async (a) => execFile(a.program, ["--version"]));\n');
  assertCodeExec(f);
  assert.equal(f.data.toolInput, true);
  assert.match(f.title, OLD_TITLE);
});

test('S3: tool input in the OPTIONS of a runtime-program call counts', async () => {
  const f = await one('const { execFile } = require("child_process");\nserver.tool("v", {}, async (a) => execFile(globalThis.bin, ["--version"], { env: a.env }));\n');
  assertCodeExec(f);
  assert.equal(f.data.toolInput, true);
});

test('S3: a fixed program keeps the argv-only tool input of 1.17 (no new medium)', async () => {
  const f = await one('const { execFile } = require("child_process");\nserver.tool("st", {}, async (a) => execFile("git", ["status"], { cwd: a.dir }));\n');
  assert.equal(f.data.callShape, 'fixed-program-fixed-args');
  assert.equal(f.data.toolInput, false);
  assert.equal(f.severity, 'info');
});

test('S3: a call recorded without its arguments keeps toolInput false, as in 1.17 (final round 1: R3-02)', async () => {
  // A 1.18 draft read the call it is handed to and the arguments of a member call: quadratic with nesting, for words only.
  const handed = await one('const { spawn } = require("child_process");\nconst runWith = require("./runner");\nserver.tool("run", {}, async (a) => runWith(spawn, a.program, a.argv));\n');
  assertCodeExec(handed);
  assert.deepEqual(calls(handed), PLACEHOLDER);
  assert.equal(handed.data.toolInput, false);
  assert.match(handed.title, OLD_TITLE);
  assert.ok(handed.description.includes(`\`spawn(…)\` — ${OLD_WORDS}`), handed.description);
  assert.equal(handed.remediation, OLD_REMEDIATION);
  const member = await one('const spawn = require("cross-spawn");\nserver.tool("run", {}, async (a) => spawn.sync.call(null, a.cmd, ["-v"]));\n');
  assertCodeExec(member);
  assert.deepEqual(calls(member), PLACEHOLDER);
  assert.equal(member.data.toolInput, false);
  assert.match(member.title, OLD_TITLE, 'a member call left unread keeps the 1.17 words');
  assert.equal(member.remediation, OLD_REMEDIATION);
  // child_process `spawn.call(…)` in a file with no sign: a member call too.
  const call = await one('const { spawn } = require("child_process");\nexports.f = () => spawn.call(null, "ls", []);\n');
  assertCodeExec(call);
  assert.deepEqual(calls(call), PLACEHOLDER);
  assert.match(call.title, OLD_TITLE);
  assert.ok(call.description.includes(`\`spawn(…)\` — ${OLD_WORDS}`), call.description);
  assert.equal(call.remediation, OLD_REMEDIATION);
  assertSame117(call, 'ire("child_process"); exports.f = () => spawn.call(null, "ls", []);', 'c1607531fb14cd31272c5440624a46127c043d2d2b88395413ddfccd4b378ba8');
});

test('S3: nested uses of a bound process function or of a computed API stay fast (final round 1: R3-02, probe v3-04)', async () => {
  const H = 'server.tool("t", {}, async (a) => a.x);\n';
  const nest = (open: string, inner: string, close: string) => open.repeat(4000) + inner + close.repeat(4000);
  for (const [name, path, content] of [
    ['member calls', 'src/member.js', `const { spawn } = require("child_process");\n${H}module.exports = () => ${nest('spawn.x(', '1', ')')};\n`],
    ['handed on', 'src/handed.js', `const { spawn } = require("child_process");\n${H}module.exports = ${nest('f(spawn, ', '1', ')')};\n`],
    ['a computed API', 'src/computed.js', `const cp = require("child_process");\n${H}module.exports = (k, b) => ${nest('cp[k](', 'b', ')')};\n`],
    ['getattr', 'pkg/run.py', `import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("x")\n\n\n@mcp.tool()\ndef t(a: str) -> str:\n    return a\n\n\ndef run(k, b):\n    return ${nest('getattr(subprocess, k)(', 'b', ')')}\n`],
  ] as const) {
    const t0 = performance.now();
    const f = await one(content, path);
    const ms = performance.now() - t0;
    assertCodeExec(f);
    // 1.17.0 takes ~15 ms each; the 1.18 draft took 2–7 s (a split and a token scan of the nested call per use).
    assert.ok(ms < 1500, `${name}: ${ms.toFixed(0)} ms`);
  }
});

test('S3: many uses of a bound process function in one call cost one walk (verify round 1: m1-14)', async () => {
  const content = `const { spawn } = require("child_process");\nserver.tool("t", {}, async (a) => a.x);\nrun(${Array(30000).fill('spawn').join(', ')});\n`;
  const t0 = performance.now();
  const f = await one(content);
  const ms = performance.now() - t0;
  assertCodeExec(f);
  // 1.17.0 takes ~0.1 s; the first 1.18 build took ~4 s (a 4000-character walk and a whole-call split per use).
  assert.ok(ms < 3000, `${ms.toFixed(0)} ms`);
});

test('S3: an API chosen at runtime takes no tool input, as in 1.17, and keeps the 1.17 words (final round 2: FR1-04)', async () => {
  // A 1.18 draft read its key for tool input: one walk over the file's functions per call (quadratic), for data only.
  const js = await one('const cp = require("child_process");\nserver.tool("run", {}, async (a) => cp[a.api](a.program, a.argv));\n');
  assertCodeExec(js);
  assert.equal(js.data.toolInput, false);
  assert.match(js.title, OLD_TITLE);
  assert.equal(js.remediation, OLD_REMEDIATION);
  const py = await one(
    'import subprocess\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("x")\n\n\n@mcp.tool()\ndef run(api: str, program: str) -> str:\n    return getattr(subprocess, api)([program])\n',
    'srv/server.py',
  );
  assertCodeExec(py);
  assert.equal(py.data.toolInput, false);
  assert.match(py.title, OLD_TITLE);
  assert.equal(py.remediation, OLD_REMEDIATION);
});

test('S3: tool input only in a result callback does not count; in the options it does (final round 2: P3, FR1-05)', async () => {
  const cb = await one('const { execFile } = require("child_process");\nconst BIN = process.env.MY_BIN;\nserver.tool("ver", {}, async (a) => new Promise((res) => execFile(BIN, ["--version"], (e, out) => res(a.prefix + out))));\n', 'src/server.js');
  assertCodeExec(cb);
  assert.equal(cb.data.toolInput, false);
  assert.equal(cb.data.calls[0].toolInput, false);
  assert.match(cb.title, NEW_TITLE);
  assert.ok(cb.description.includes(`\`execFile(…)\` ${NEUTRAL}`), cb.description);
  assertSame117(cb, 'execFile(BIN, ["--version"], (e, out) => res(a.prefix + out))', '1b735f804d14091a0d09e06a6d464d190d1a7ca62c7eda3061bebd12e75c9cd2');
  const execCb = await one('const { exec } = require("child_process");\nconst STATUS_CMD = process.env.STATUS_CMD;\nserver.tool("status", {}, async (args) => new Promise((resolve) => {\n  exec(STATUS_CMD, (error, stdout) => resolve(error ? `${args.name} failed` : stdout));\n}));\n', 'src/status.js');
  assertCodeExec(execCb);
  assert.equal(execCb.data.toolInput, false);
  const execOpts = await one('const { exec } = require("child_process");\nconst STATUS_CMD = process.env.STATUS_CMD;\nserver.tool("status", {}, async (args) => new Promise((resolve) => {\n  exec(STATUS_CMD, { cwd: args.dir }, (error, stdout) => resolve(stdout));\n}));\n', 'src/status.js');
  assertCodeExec(execOpts);
  assert.equal(execOpts.data.toolInput, true, 'tool input in the options of a shell call counts');
  assert.match(execOpts.title, OLD_TITLE);
});

test('S3: a program and options over 4 KB are not read again: the 1.17 reading stays (final round 2: P4)', async () => {
  const call = (pad: string) => `const { execFile } = require("child_process");\nserver.tool("v", {}, async (a) => execFile(globalThis.bin, ["--version"], { env: a.env, note: "${pad}" }));\n`;
  const small = await one(call('x'.repeat(3900)));
  assert.equal(small.data.toolInput, true);
  const big = await one(call('x'.repeat(4200)));
  assertCodeExec(big);
  assert.equal(big.data.toolInput, false, 'as 1.17, which reads only the argv');
  assert.ok(!/no tool input reach/.test(big.description), big.description);
  assert.equal(big.remediation, OLD_REMEDIATION);
});

test('S3: many computed APIs next to many functions scan in linear time (final round 2: FR1-04)', async () => {
  const defs = Array.from({ length: 50000 }, (_, i) => `def f${i}():\n    pass`).join('\n');
  const uses = Array.from({ length: 50000 }, () => '    getattr(subprocess, k)(x)').join('\n');
  const content = `import os\nimport subprocess\n\nk = os.environ["K"]\n\n\n@mcp.tool()\ndef t(x):\n    return x\n\n\n${defs}\n\n\ndef run(x):\n${uses}\n`;
  const t0 = performance.now();
  const f = await one(content, 'src/a.py');
  const ms = performance.now() - t0;
  assertCodeExec(f);
  // 1.17.0 takes ~0.13 s; a 1.18 draft that read every key for tool input took ~2.6 s.
  assert.ok(ms < 1500, `${ms.toFixed(0)} ms`);
});

test('S3: an expression that names no tainted binding is answered without a walk over the functions, with the same answer; several expressions take one walk (final round 2: FR1-04)', () => {
  const fns = Array.from({ length: 20000 }, (_, i) => `function f${i}() { return p; }`).join('\n');
  const src = `const p = process.env.P;\nserver.tool("t", {}, async (a) => { return a.x; });\n${fns}\n`;
  const flow = toolFlowOf(new FileCtx('src/x.js', src));
  const inside = src.indexOf('return a.x');
  const outside = src.indexOf('function f100');
  assert.equal(flow.carries('a.x', inside), true);
  assert.equal(flow.carries('p', inside), false);
  assert.equal(flow.carries('a.x', outside), false);
  // Several expressions in one walk: the answer of each one asked alone, or-ed.
  assert.equal(flow.carries(['p', 'a.x'], inside), true);
  assert.equal(flow.carries(['p', '"a.x"', ''], inside), false);
  assert.equal(flow.carries(['a.x'], outside), false);
  const t0 = performance.now();
  for (let i = 0; i < 20000; i++) assert.equal(flow.carries('p', outside + i), false);
  const ms = performance.now() - t0;
  // A walk over the 20000 functions per call took ~0.7 s here.
  assert.ok(ms < 200, `${ms.toFixed(0)} ms`);
});

test('S3: an expression that names a tainted binding visits only the functions that hold tool input, with the same answers', () => {
  // A minified bundle: the handler's parameter is called `e`, like the parameter of every other function.
  const fns = Array.from({ length: 20000 }, (_, i) => `function f${i}(e) { return e; }`).join('\n');
  const src = `server.tool("t", {}, async (e) => { return e.x; });\n${fns}\nfunction last(e) { return e; }\n`;
  const flow = toolFlowOf(new FileCtx('src/x.js', src));
  const inside = src.indexOf('return e.x');
  const outside = src.indexOf('function last');
  assert.equal(flow.carries('e.x', inside), true);
  assert.equal(flow.carries('e', outside + 20), false, 'another function\'s `e` is not the handler\'s');
  const t0 = performance.now();
  for (let i = 0; i < 20000; i++) assert.equal(flow.carries('e', outside + 20), false);
  const ms = performance.now() - t0;
  // A walk over the 20000 functions per call took ~0.7 s here.
  assert.ok(ms < 200, `${ms.toFixed(0)} ms`);
});

// --- S4. A shell option set at runtime ---------------------------------------

test('S4: spawn("npx", args, { shell: process.platform === "win32" }) is shell-dynamic, same numbers, 1.17 evidence', async () => {
  const f = await one(
    '"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\nconst child_process_1 = require("child_process");\nasync function installSkills(args) {\n    return new Promise((resolve, reject) => {\n        const proc = (0, child_process_1.spawn)("npx", args, { shell: process.platform === "win32", stdio: "inherit" });\n        proc.on("close", resolve);\n    });\n}\nexports.installSkills = installSkills;\n',
    'lib/agentSkills.js',
  );
  assertCodeExec(f);
  assert.equal(f.data.callShape, 'shell-dynamic');
  assert.deepEqual(calls(f), [['spawn', 'shell-dynamic', 'npx']]);
  assert.match(f.title, OLD_TITLE);
  assert.ok(f.description.includes(`\`spawn(…)\` — ${RUNTIME_SHELL_WORDS}.`), f.description);
  assert.equal(f.remediation, OLD_REMEDIATION, 'a shell-dynamic finding is not reworded');
  assertSame117(f, '(0, child_process_1.spawn)("npx", args, { shell: process.platform === "win32", stdio: "inherit" })', '1bc8097970107f408dee6380dde6da165d7e7c2f6e6295719949da199b61b0f0');
});

test('S4: the relabelled call ranks as the dynamic program it was: the file keeps its 1.17 worst call', async () => {
  const f = await one('const { execFile, spawn } = require("child_process");\nexports.version = (bin) => execFile(bin, ["--version"]);\nexports.install = (args) => spawn("npx", args, { shell: process.platform === "win32" });\n');
  assertCodeExec(f);
  assert.deepEqual(calls(f), [['execFile', 'dynamic-program', '<runtime value>'], ['spawn', 'shell-dynamic', 'npx']]);
  assert.equal(f.data.callShape, 'dynamic-program');
  assertSame117(f, 'execFile(bin, ["--version"])', '6eef544596ba8ec6e953783886c4abdb1cff363e1f57c93c217cc4d87bc8b5f6');
});

test('S4: what 1.17 called shell-fixed or fixed stays so; a shell 1.17 already assumed gets the runtime words', async () => {
  const shFixed = await one('import { spawn } from "node:child_process";\nexport function openFile(file) {\n  return spawn("sh", ["-c", \'xdg-open "$1"\', "sh", file], { shell: process.platform === "win32", stdio: "ignore" });\n}\n');
  assert.equal(shFixed.data.callShape, 'shell-fixed');
  assert.equal(shFixed.severity, 'low');
  const nodeE = await one('import { spawn } from "node:child_process";\nexport function printArg(value) {\n  return spawn("node", ["-e", "console.log(process.argv[1])", value], { shell: process.platform === "win32" });\n}\n');
  assert.equal(nodeE.data.callShape, 'shell-fixed');
  const fixed = await one('const { spawn } = require("child_process");\nexports.list = () => spawn("ls", ["-l"], { shell: process.platform === "win32" });\n');
  assert.equal(fixed.data.callShape, 'fixed-program-fixed-args');
  assert.equal(fixed.severity, 'info');
  const git = await one('const { spawn } = require("child_process");\nexports.run = (x) => spawn("git", ["status", x], { shell: process.platform === "win32" });\n');
  assertCodeExec(git);
  assert.equal(git.data.callShape, 'shell-dynamic');
  assert.ok(git.description.includes(RUNTIME_SHELL_WORDS), git.description);
});

test('S4: options the scanner cannot read keep the 1.17 words', async () => {
  const f = await one('const { spawn } = require("child_process");\nexports.run = (x, opts) => spawn("git", ["status", x], opts);\n');
  assertCodeExec(f);
  assert.equal(f.data.callShape, 'shell-dynamic');
  assert.ok(f.description.includes('`spawn(…)` — a shell runs a command line built at runtime.'), f.description);
});

test('S4: a shell option of literals only (`!1`, `!0`, `void 0`) or a constant of them is not "set at runtime": the 1.17 label and words (final round 2: P2)', async () => {
  for (const [name, path, content, shape, words, evidence, fingerprint] of [
    ['osascript -e with shell: !1', 'src/osa.js', 'const { spawn } = require("child_process");\nfunction osa(script) {\n  return spawn("osascript", ["-e", script], { detached: !0, shell: !1 });\n}\nmodule.exports = { osa };\n', 'dynamic-program', OLD_WORDS, 'spawn("osascript", ["-e", script], { detached: !0, shell: !1 })', 'a216e5506c769629800043874c80626ae12a09dc1fcd1923c9699f7afeed9d3f'],
    ['tar with runtime arguments, shell: !1', 'src/tar.js', 'const { spawnSync } = require("child_process");\nfunction untar(args) {\n  return spawnSync("tar", args, { shell: !1 });\n}\nmodule.exports = { untar };\n', 'shell-dynamic', 'a shell runs a command line built at runtime.', 'spawnSync("tar", args, { shell: !1 })', 'a6c12ff8c78154f1c9813e898b567b7360898bea55ba86a5399e4bad89566ece'],
    ['tar with runtime arguments, shell: void 0', 'src/void.js', 'const { spawnSync } = require("child_process");\nfunction untar(args) {\n  return spawnSync("tar", args, { shell: void 0 });\n}\nmodule.exports = { untar };\n', 'shell-dynamic', 'a shell runs a command line built at runtime.', 'spawnSync("tar", args, { shell: void 0 })', 'd716197b1c15948c7284a41e92fab8a8692e38bc5eb7452a8dfe00958e671852'],
    ['npx with shell: !0', 'src/h.js', 'const { spawn } = require("child_process");\nexports.run = (args) => spawn("npx", args, { shell: !0 });\n', 'dynamic-program', OLD_WORDS, 'spawn("npx", args, { shell: !0 })', '91074084a8e36c511a9f42aab55fec88e4822ebe83fb126096535f3064bac59f'],
    ['npx with { shell } and const shell = !0', 'src/s.js', 'const { spawn } = require("child_process");\nconst shell = !0;\nexports.run = (args) => spawn("npx", args, { shell });\n', 'dynamic-program', OLD_WORDS, 'spawn("npx", args, { shell })', '93cecb7d64b9497d70b2a8fb6330df3b3bc290b18dc5c627d867a9b89f48ad49'],
  ] as const) {
    const f = await one(content, path);
    assertCodeExec(f);
    assert.equal(f.data.callShape, shape, name);
    assert.equal(f.data.calls[0].shape, shape, name);
    assert.ok(!f.description.includes(RUNTIME_SHELL_WORDS), `${name}: ${f.description}`);
    assert.ok(f.description.includes(words), `${name}: ${f.description}`);
    assert.match(f.title, OLD_TITLE, name);
    assertSame117(f, evidence, fingerprint);
  }
  // A value that names a binding is set at runtime: a constant of one, or a parameter.
  for (const content of [
    'const { spawn } = require("child_process");\nconst isWin = process.platform === "win32";\nexports.run = (args) => spawn("npx", args, { shell: isWin });\n',
    'const { spawn } = require("child_process");\nexports.run = (args, shell) => spawn("npx", args, { shell });\n',
  ]) {
    const f = await one(content);
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'shell-dynamic');
    assert.ok(f.description.includes(RUNTIME_SHELL_WORDS), f.description);
  }
});

test('S4: "set at runtime" is said only of the value of a `shell` key at the top level of inline options', async () => {
  const cp = 'const { spawn } = require("child_process");\n';
  const fn = (opts: string) => `${cp}exports.run = (cmd, args, loginShell, shell, home, p) => spawn(cmd, args, ${opts});\n`;
  const yes = await one(fn('{ cwd: "/", shell: process.platform === "win32" }'));
  assertCodeExec(yes);
  assert.equal(yes.data.callShape, 'shell-dynamic');
  assert.ok(yes.description.includes(RUNTIME_SHELL_WORDS), yes.description);
  for (const [name, opts] of [
    ['a commented-out key', '{\n  // shell: process.platform === "win32",\n  cwd: "/" }'],
    ['a nested key', '{ env: { shell: loginShell } }'],
    ['the name inside another value', '{ cwd: cmd === shell ? shell : home }'],
    ['a nested key, then shell: false', '{ env: { PATH: p, shell: loginShell }, shell: false }'],
    ['the name inside another value, then shell: false', '{ cwd: cmd === shell ? shell : home, shell: false }'],
  ] as const) {
    const f = await one(fn(opts));
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'dynamic-program', name);
    assert.ok(!f.description.includes(RUNTIME_SHELL_WORDS), `${name}: ${f.description}`);
  }
  // Options held in a name, and a value too long to be a platform test: the 1.17 label, and the 1.17 words
  // (the options name a shell).
  for (const content of [
    `${cp}const OPTS = { shell: process.platform === "win32" };\nexports.run = (cmd, args) => spawn(cmd, args, OPTS);\n`,
    fn(`{ shell: ${Array.from({ length: 30 }, (_, i) => `p === "x${i}"`).join(' || ')} }`),
  ]) {
    const f = await one(content);
    assertCodeExec(f);
    assert.equal(f.data.callShape, 'dynamic-program');
    assert.ok(!f.description.includes(RUNTIME_SHELL_WORDS), f.description);
    assert.match(f.title, OLD_TITLE);
    assert.equal(f.remediation, OLD_REMEDIATION);
  }
});

// --- S5. Memoised reassignment lookups (results unchanged) ----------------------

test('S5: declarations of a reassigned name read the same on every lookup and in a fresh context', () => {
  // A minified bundle repeats `var e = …` in every function: one scan per name, not per declaration.
  const vars = Array.from({ length: 200 }, (_, i) => `function f${i}() { var e = "v${i}"; return e; }`).join('\n');
  const consts = Array.from({ length: 200 }, (_, i) => `function g${i}() { const k = "v${i}"; return k; }`).join('\n');
  const src = `let cmd = "git";\ncmd = globalThis.pick();\nlet once = "npm";\n${vars}\n${consts}\n`;
  const ctx = new FileCtx('src/x.js', src);
  assert.equal(ctx.declsOf('cmd').length, 0, 'a let assigned twice is not a constant');
  assert.equal(ctx.declsOf('e').length, 0, 'a var assigned in 200 places is not a constant');
  assert.equal(ctx.declsOf('once').length, 1, 'a let assigned once is');
  assert.equal(ctx.declsOf('k').length, 200);
  const fresh = new FileCtx('src/x.js', src);
  for (const name of ['cmd', 'e', 'once', 'k']) assert.deepEqual(fresh.declsOf(name).map((d) => [d.at, d.init]), ctx.declsOf(name).map((d) => [d.at, d.init]), name);
});
