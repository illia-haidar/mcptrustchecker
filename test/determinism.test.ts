import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { renderJson } from '../src/report/json.js';
import { loadFixture } from './helpers.js';

// The headline reproducibility contract: same methodology version + same target
// ⇒ byte-identical report. A report scanned without an explicit `scannedAt` is
// reproducible (the only non-deterministic field is intentionally omitted).

const manifest = loadFixture('toxic-flow-server.json');

test('a reproducible report omits scannedAt', async () => {
  const r = await scanSurface(surfaceFromManifest(manifest, 'repro'));
  assert.equal(r.scannedAt, undefined);
});

test('the same target scanned twice is byte-identical JSON', async () => {
  const a = await scanSurface(surfaceFromManifest(manifest, 'repro'));
  const b = await scanSurface(surfaceFromManifest(manifest, 'repro'));
  assert.equal(renderJson(a), renderJson(b));
});

test('surfaceDigest is stable for identical input', async () => {
  const a = await scanSurface(surfaceFromManifest(manifest, 'x'));
  const b = await scanSurface(surfaceFromManifest(manifest, 'x'));
  assert.equal(a.surfaceDigest, b.surfaceDigest);
});

test('score, grade and finding order are stable across 8 runs', async () => {
  const seen = new Set<string>();
  for (let i = 0; i < 8; i++) {
    const r = await scanSurface(surfaceFromManifest(manifest, 'x'));
    seen.add(JSON.stringify({ g: r.score.grade, s: r.score.score, ids: r.findings.map((f) => f.ruleId) }));
  }
  assert.equal(seen.size, 1, 'all runs must produce the identical grade/score/finding-order');
});

test('an explicit scannedAt is the ONLY thing that changes between two runs', async () => {
  const a = await scanSurface(surfaceFromManifest(manifest, 'x'), { scannedAt: '2026-01-01T00:00:00Z' });
  const b = await scanSurface(surfaceFromManifest(manifest, 'x'), { scannedAt: '2026-12-31T23:59:59Z' });
  const strip = (s: string) => s.replace(/"scannedAt":\s*"[^"]*",?\n?/, '');
  assert.equal(strip(renderJson(a)), strip(renderJson(b)));
});
