import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { GRADE_RANK } from '../src/scoring/model.js';

// Turns the benchmark into a CI regression gate: the measured precision/recall
// on the labeled corpus must not drop below the floor.

const corpus: { id: string; label: 'malicious' | 'benign'; manifest: unknown }[] = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'benchmark', 'corpus.json'), 'utf8'),
);

test('the labeled corpus exists and is balanced enough to be meaningful', () => {
  assert.ok(corpus.length >= 16, 'need a reasonable corpus size');
  assert.ok(corpus.filter((e) => e.label === 'malicious').length >= 6);
  assert.ok(corpus.filter((e) => e.label === 'benign').length >= 6);
});

test('precision and recall on the corpus stay ≥ 90% (concerning := grade ≤ C)', async () => {
  let tp = 0, fp = 0, fn = 0;
  const misses: string[] = [];
  for (const e of corpus) {
    const r = await scanSurface(surfaceFromManifest(e.manifest, e.id));
    const flagged = GRADE_RANK[r.score.grade] <= GRADE_RANK['C'];
    const malicious = e.label === 'malicious';
    if (flagged && malicious) tp++;
    else if (flagged && !malicious) { fp++; misses.push(`FP ${e.id} (${r.score.grade})`); }
    else if (!flagged && malicious) { fn++; misses.push(`FN ${e.id} (${r.score.grade})`); }
  }
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  assert.ok(precision >= 0.9, `precision ${(precision * 100).toFixed(1)}% < 90% — ${misses.join(', ')}`);
  assert.ok(recall >= 0.9, `recall ${(recall * 100).toFixed(1)}% < 90% — ${misses.join(', ')}`);
});

test('no benign server in the corpus is graded below B (zero false positives)', async () => {
  for (const e of corpus.filter((x) => x.label === 'benign')) {
    const r = await scanSurface(surfaceFromManifest(e.manifest, e.id));
    assert.ok(GRADE_RANK[r.score.grade] >= GRADE_RANK['B'], `benign "${e.id}" dropped to ${r.score.grade}`);
  }
});
