#!/usr/bin/env node
/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Measures the scanner against the labeled corpus and prints precision / recall
 * / F1 / accuracy. Predicted-positive ("concerning") := Trust grade C or worse.
 *
 *   npm run benchmark          (builds first)
 *
 * Exits non-zero if precision or recall drops below the floor — so calibration
 * regressions fail CI, not just review.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scanSurface } from '../dist/engine.js';
import { surfaceFromManifest } from '../dist/acquire/manifest.js';

const RANK = { F: 0, D: 1, C: 2, B: 3, A: 4 };
const FLOOR = { precision: 0.9, recall: 0.9 };
const HERE = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(join(HERE, 'corpus.json'), 'utf8'));

let tp = 0, fp = 0, tn = 0, fn = 0;
const misses = [];
for (const e of corpus) {
  const r = await scanSurface(surfaceFromManifest(e.manifest, e.id));
  const predictedPositive = RANK[r.score.grade] <= RANK['C']; // C/D/F = "concerning"
  const actualPositive = e.label === 'malicious';
  if (predictedPositive && actualPositive) tp++;
  else if (predictedPositive && !actualPositive) { fp++; misses.push(`FP  ${e.id}  → ${r.score.grade}(${r.score.score})`); }
  else if (!predictedPositive && actualPositive) { fn++; misses.push(`FN  ${e.id}  → ${r.score.grade}(${r.score.score})`); }
  else tn++;
}

const precision = tp / (tp + fp || 1);
const recall = tp / (tp + fn || 1);
const f1 = (2 * precision * recall) / (precision + recall || 1);
const accuracy = (tp + tn) / corpus.length;

const pct = (n) => (n * 100).toFixed(1) + '%';
console.log(`\nMCP Trust Checker — benchmark (${corpus.length} labeled servers)\n`);
console.log(`  Precision  ${pct(precision)}   (${tp}/${tp + fp} flagged were malicious)`);
console.log(`  Recall     ${pct(recall)}   (${tp}/${tp + fn} malicious were flagged)`);
console.log(`  F1         ${pct(f1)}`);
console.log(`  Accuracy   ${pct(accuracy)}   (${tp + tn}/${corpus.length})`);
console.log(`  FP-rate    ${pct(fp / (fp + tn || 1))}`);
if (misses.length) console.log('\n  misclassified:\n    ' + misses.join('\n    '));

if (precision < FLOOR.precision || recall < FLOOR.recall) {
  console.error(`\nFAIL: precision/recall below floor (need ≥ ${pct(FLOOR.precision)} / ${pct(FLOOR.recall)}).`);
  process.exit(1);
}
console.log(`\nPASS (floor: precision ≥ ${pct(FLOOR.precision)}, recall ≥ ${pct(FLOOR.recall)}).`);
