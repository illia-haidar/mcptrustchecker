import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
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
