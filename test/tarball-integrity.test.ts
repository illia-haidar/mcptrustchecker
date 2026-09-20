import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkIntegrity, pinSurface, emptyLockfile, entryFor } from '../src/lockfile.js';
import { scanSurface } from '../src/engine.js';
import { makeSurface } from './helpers.js';
import type { PackageMeta } from '../src/types.js';

const meta = (version: string, sha: string): PackageMeta => ({
  registry: 'npm',
  name: 'some-mcp',
  version,
  tarballSha256: sha,
});

test('entryFor pins the verified artifact hash alongside the surface digest', () => {
  const surface = makeSurface({ packageMeta: meta('1.0.0', 'a'.repeat(64)) });
  const entry = entryFor(surface);
  assert.equal(entry.packageVersion, '1.0.0');
  assert.equal(entry.tarballSha256, 'a'.repeat(64));
});

test('same version + same bytes = unchanged', () => {
  const surface = makeSurface({ packageMeta: meta('1.0.0', 'a'.repeat(64)) });
  const lock = pinSurface(emptyLockfile(), surface);
  assert.equal(checkIntegrity(surface, lock).status, 'unchanged');
});

test('same version + different bytes = drift with a package-changed entry (even with an identical tool surface)', () => {
  const pinned = makeSurface({ packageMeta: meta('1.0.0', 'a'.repeat(64)) });
  const lock = pinSurface(emptyLockfile(), pinned);
  const republished = makeSurface({ packageMeta: meta('1.0.0', 'b'.repeat(64)) });
  const res = checkIntegrity(republished, lock);
  assert.equal(res.status, 'drift');
  assert.ok(res.changes?.some((ch) => ch.kind === 'package-changed'));
  assert.match(res.changes!.find((ch) => ch.kind === 'package-changed')!.detail, /republished with different content/);
});

test('a legitimate version bump is NOT a byte-level rug pull', () => {
  const pinned = makeSurface({ packageMeta: meta('1.0.0', 'a'.repeat(64)) });
  const lock = pinSurface(emptyLockfile(), pinned);
  const upgraded = makeSurface({ packageMeta: meta('1.1.0', 'b'.repeat(64)) });
  const res = checkIntegrity(upgraded, lock);
  assert.equal(res.status, 'unchanged', 'new version with new bytes is an expected update, not drift');
});

test('an offline rescan (no artifact hash) does not false-positive against an online pin', () => {
  const pinned = makeSurface({ packageMeta: meta('1.0.0', 'a'.repeat(64)) });
  const lock = pinSurface(emptyLockfile(), pinned);
  const offline = makeSurface({ packageMeta: { registry: 'npm', name: 'some-mcp', version: '1.0.0' } });
  assert.equal(checkIntegrity(offline, lock).status, 'unchanged');
});

test('engine emits critical MTC-TOFU-002 on a byte-level rug pull, without a spurious MTC-TOFU-001', async () => {
  const pinned = makeSurface({ packageMeta: meta('1.0.0', 'a'.repeat(64)) });
  const lock = pinSurface(emptyLockfile(), pinned);
  const republished = makeSurface({ packageMeta: meta('1.0.0', 'b'.repeat(64)) });
  const report = await scanSurface(republished, { lockfile: lock });
  const tofu2 = report.findings.find((f) => f.ruleId === 'MTC-TOFU-002');
  assert.ok(tofu2, 'MTC-TOFU-002 must fire');
  assert.equal(tofu2!.severity, 'critical');
  assert.equal(tofu2!.confidence, 'confirmed');
  assert.ok(
    !report.findings.some((f) => f.ruleId === 'MTC-TOFU-001'),
    'the unchanged tool surface must not also raise MTC-TOFU-001',
  );
});

test('engine still emits MTC-TOFU-001 alone for a pure tool-surface drift', async () => {
  const pinned = makeSurface({ tools: [{ name: 't', description: 'original' }] });
  const lock = pinSurface(emptyLockfile(), pinned);
  const mutated = makeSurface({ tools: [{ name: 't', description: 'changed' }] });
  const report = await scanSurface(mutated, { lockfile: lock });
  assert.ok(report.findings.some((f) => f.ruleId === 'MTC-TOFU-001'));
  assert.ok(!report.findings.some((f) => f.ruleId === 'MTC-TOFU-002'));
});
