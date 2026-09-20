import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// CI gating is only useful if the process exit code is correct. These drive the
// *built* CLI end-to-end (the real entrypoint users get).

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'dist', 'cli', 'index.js');
if (!existsSync(CLI)) execSync('npm run build', { cwd: ROOT, stdio: 'ignore' });

function run(...args: string[]): number {
  const res = spawnSync('node', [CLI, ...args, '--quiet', '--no-pager'], { cwd: ROOT, encoding: 'utf8' });
  return res.status ?? -1;
}
const CLEAN = 'test/fixtures/clean-server.json';
const POISONED = 'test/fixtures/poisoned-server.json';

test('a passing scan with no gate exits 0', () => {
  assert.equal(run('scan', CLEAN), 0);
});

test('--min-grade A: clean (A) passes, poisoned (F) fails', () => {
  assert.equal(run('scan', CLEAN, '--min-grade', 'A'), 0);
  assert.equal(run('scan', POISONED, '--min-grade', 'A'), 1);
});

test('--min-grade F never fails on grade', () => {
  assert.equal(run('scan', POISONED, '--min-grade', 'F'), 0);
});

test('--fail-under: score below threshold exits 1, at/above exits 0', () => {
  assert.equal(run('scan', POISONED, '--fail-under', '60'), 1); // poisoned scores below 60
  assert.equal(run('scan', CLEAN, '--fail-under', '90'), 0); // clean scores 100
});

test('an invalid --min-grade is a usage error (non-zero)', () => {
  assert.notEqual(run('scan', CLEAN, '--min-grade', 'Z'), 0);
});

test('--version exits 0 and prints the branded methodology', () => {
  const res = spawnSync('node', [CLI, '--version'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.match(res.stdout, /mcptrustchecker .*methodology mcptrustchecker-/);
});

// ---------------------------------------------------------------------------
// A usage error and a crash are different events, and CI has to act on them
// differently: one means "fix the pipeline", the other means "this is a bug".
// Until 1.13.1 the top-level catch reused fail()'s default of 2, so a typo'd
// flag and a stack trace were indistinguishable to the caller.
// ---------------------------------------------------------------------------
test('a usage error still exits 2, and is distinct from the internal-error code', () => {
  assert.equal(run('scan', CLEAN, '--min-grade', 'Z'), 2, 'a bad flag value is a usage error');
  assert.equal(run('scan', CLEAN, '--fail-under', 'not-a-number'), 2, 'a bad flag value is a usage error');
  // Not asserted here: an unknown first argument is NOT a usage error — the CLI
  // deliberately accepts a bare target (`mcptrustchecker ./tools.json`), so it
  // is read as something to scan rather than as a mistyped command.
});

test('the documented exit-code table matches the CLI', () => {
  // The table is the contract CI authors read; drift between it and the code is
  // the kind of thing nobody notices until a pipeline swallows a crash.
  const docs = readFileSync(join(ROOT, 'docs', 'ci-integration.md'), 'utf8');
  const table = docs.slice(docs.indexOf('## Exit codes'));
  for (const code of ['`0`', '`1`', '`2`', '`3`']) {
    assert.ok(table.includes(code), `exit code ${code} is not documented`);
  }

  const cli = readFileSync(join(ROOT, 'src', 'cli', 'index.ts'), 'utf8');
  assert.ok(
    /process\.exit\(3\)/.test(cli),
    'the CLI documents exit 3 but never produces it',
  );
  assert.ok(
    /function fail\(msg: string, code = 2\)/.test(cli),
    'usage errors must keep exiting 2',
  );
});
