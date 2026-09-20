import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { RULE_CATALOG } from '../src/data/ruleCatalog.js';
import { loadFixture } from './helpers.js';

async function scanFixture(name: string) {
  const surface = surfaceFromManifest(loadFixture(name), name);
  return scanSurface(surface);
}

test('a clean server scores grade A with no findings', async () => {
  const report = await scanFixture('clean-server.json');
  assert.equal(report.score.grade, 'A');
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.tools, 2);
});

test('a poisoned server scores grade F and flags compound poisoning', async () => {
  const report = await scanFixture('poisoned-server.json');
  assert.equal(report.score.grade, 'F');
  assert.ok(report.findings.some((f) => f.ruleId === 'MTC-INJ-POISON'));
  assert.ok(report.findings.some((f) => f.ruleId === 'MTC-INJ-TARGET-1'));
});

test('a toxic-flow server surfaces the trifecta as CAPABILITY, not a trust hit', async () => {
  const report = await scanFixture('toxic-flow-server.json');
  // The cross-tool trifecta is still detected and surfaced...
  assert.ok(report.findings.some((f) => f.ruleId === 'MTC-FLOW-002'));
  assert.ok(report.toxicFlows.length >= 1);
  // ...and it raises the CAPABILITY level (blast radius)...
  assert.ok(['high', 'critical'].includes(report.capabilityProfile.level), report.capabilityProfile.level);
  // ...but a legit-looking server with no malice signals keeps a high TRUST grade.
  assert.ok(['A', 'B'].includes(report.score.grade), `expected A/B trust, got ${report.score.grade}`);
});

test('scanning is deterministic (same surface → identical score & digest)', async () => {
  const a = await scanFixture('poisoned-server.json');
  const b = await scanFixture('poisoned-server.json');
  assert.equal(a.score.score, b.score.score);
  assert.equal(a.surfaceDigest, b.surfaceDigest);
  assert.deepEqual(a.score.vector, b.score.vector);
});

test('every emitted rule id exists in the rule catalog', async () => {
  const catalog = new Set(RULE_CATALOG.map((r) => r.id));
  for (const name of ['clean-server.json', 'poisoned-server.json', 'toxic-flow-server.json']) {
    const report = await scanFixture(name);
    for (const f of report.findings) {
      assert.ok(catalog.has(f.ruleId), `rule ${f.ruleId} missing from catalog`);
    }
  }
});

test('the report exposes an auditable score vector and digest', async () => {
  const report = await scanFixture('poisoned-server.json'); // has real threat findings
  assert.equal(report.score.methodologyVersion, 'mcptrustchecker-1.13');
  assert.equal(report.surfaceDigest.length, 64);
  const sum = report.score.vector.reduce((s, v) => s + v.appliedPenalty, 0);
  assert.ok(sum > 0);
});

test('capability findings do not appear in the scored vector', async () => {
  const report = await scanFixture('toxic-flow-server.json');
  // The threat lines of the vector must contain only trust (non-capability)
  // rules. Client-adoption-risk lines (kind === 'client') are the three itemised
  // exposure terms, not findings, and carry no rule id.
  for (const v of report.score.vector) {
    if (v.kind !== 'threat') continue;
    assert.ok(!v.ruleId.startsWith('MTC-FLOW-00') || v.ruleId === 'MTC-FLOW-001', `capability rule ${v.ruleId} leaked into the score`);
  }
});

test('the vector itemises the three client-adoption-risk terms (no black box)', async () => {
  const report = await scanFixture('toxic-flow-server.json'); // offline → verification skipped
  const client = report.score.vector.filter((v) => v.kind === 'client');
  const terms = client.map((v) => (v.kind === 'client' ? v.term : ''));
  // capability-exposure and coverage-honesty always appear; verification is
  // skipped offline (verification === 'unknown').
  assert.ok(terms.includes('capability-exposure'), 'capability-exposure term missing');
  assert.ok(terms.includes('coverage-honesty'), 'coverage-honesty term missing');
  assert.ok(!terms.includes('verification-discount'), 'offline scan must NOT apply the verification term');
  // Every point of the client score is reconstructable from the threat score.
  const clientSubtracted = client.reduce((s, v) => s + v.appliedPenalty, 0);
  assert.equal(report.score.score, Math.max(0, report.score.threatScore - clientSubtracted));
  assert.ok(report.score.score <= report.score.threatScore, 'the client score never rises above the threat score');
});
