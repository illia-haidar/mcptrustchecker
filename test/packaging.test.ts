import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// What actually ships to npm. `npm pack --dry-run --json` reports the exact file
// list without publishing — so we can guarantee the tarball contains the built
// engine + license and NOTHING else (no source, tests, sites, or stray logs).

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function packedFiles(): string[] {
  const out = execSync('npm pack --dry-run --json', { cwd: ROOT, encoding: 'utf8' });
  const meta = JSON.parse(out);
  return (meta[0]?.files ?? []).map((f: any) => f.path.replace(/\\/g, '/'));
}

test('the published tarball contains the built engine, CLI, types, README and LICENSE', () => {
  const files = packedFiles();
  for (const required of ['dist/index.js', 'dist/index.d.ts', 'dist/cli/index.js', 'README.md', 'LICENSE']) {
    assert.ok(files.includes(required), `tarball must include ${required}`);
  }
});

test('the tarball leaks NO source, tests, landing pages or stray files', () => {
  const files = packedFiles();
  const forbidden = files.filter((f) =>
    /^src\//.test(f) ||
    /^test\//.test(f) ||
    /^site(-v2|-v3)?\//.test(f) ||
    /^docs\//.test(f) ||
    /\.(log|txt)$/.test(f) ||
    /^examples\//.test(f) ||
    /tsconfig/.test(f),
  );
  assert.deepEqual(forbidden, [], `tarball must not ship: ${forbidden.join(', ')}`);
});

test('the CLI bin path in package.json actually exists in the tarball', () => {
  const pkg = JSON.parse(execSync('cat package.json', { cwd: ROOT, encoding: 'utf8' }));
  const bin = pkg.bin.mcptrustchecker.replace(/^\.\//, '');
  assert.ok(packedFiles().includes(bin), `bin ${bin} present in tarball`);
});
