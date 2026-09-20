import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { renderSarif } from '../src/report/sarif.js';
import { loadFixture } from './helpers.js';

async function sarifFor(fixture: string): Promise<any> {
  const report = await scanSurface(surfaceFromManifest(loadFixture(fixture), 'sarif-test'));
  const text = renderSarif(report);
  return JSON.parse(text); // must be valid JSON
}

const LEVELS = new Set(['error', 'warning', 'note', 'none']);

test('SARIF output is a valid 2.1.0 log with one run', async () => {
  const s = await sarifFor('poisoned-server.json');
  assert.equal(s.version, '2.1.0');
  assert.match(s.$schema, /sarif-2\.1\.0\.json$/);
  assert.ok(Array.isArray(s.runs) && s.runs.length === 1);
  const driver = s.runs[0].tool.driver;
  assert.equal(driver.name, 'MCP Trust Checker');
  assert.ok(typeof driver.version === 'string');
  assert.ok(Array.isArray(driver.rules));
  assert.ok(Array.isArray(s.runs[0].results));
});

test('every result references a declared rule, a valid level, a message and a location', async () => {
  const s = await sarifFor('poisoned-server.json');
  const run = s.runs[0];
  assert.ok(run.results.length > 0, 'poisoned fixture must produce results');
  const declared = new Set(run.tool.driver.rules.map((r: any) => r.id));
  for (const res of run.results) {
    assert.ok(res.ruleId, 'result.ruleId present');
    assert.ok(declared.has(res.ruleId), `ruleId ${res.ruleId} is declared in driver.rules`);
    assert.ok(LEVELS.has(res.level), `valid level "${res.level}"`);
    assert.ok(res.message?.text, 'result.message.text present');
    assert.ok(Array.isArray(res.locations) && res.locations.length >= 1, 'result.locations present');
    assert.ok(res.locations[0].logicalLocations?.[0]?.name, 'a logical location name');
  }
});

test('every declared rule has a stable id, name and default level', async () => {
  const s = await sarifFor('poisoned-server.json');
  for (const rule of s.runs[0].tool.driver.rules) {
    assert.ok(/^MTC-/.test(rule.id), `rule id is branded: ${rule.id}`);
    assert.equal(rule.id, rule.name);
    assert.ok(rule.shortDescription?.text);
    assert.ok(LEVELS.has(rule.defaultConfiguration?.level));
    assert.ok(rule.properties?.['security-severity'], 'GitHub security-severity present');
  }
});

test('run.properties carries the branded score + methodology', async () => {
  const s = await sarifFor('poisoned-server.json');
  const p = s.runs[0].properties;
  assert.equal(typeof p.trustScore, 'number');
  assert.match(p.grade, /^[A-F]$/);
  assert.match(p.methodologyVersion, /^mcptrustchecker-/);
});

test('a clean server still emits schema-valid SARIF', async () => {
  const s = await sarifFor('clean-server.json');
  assert.equal(s.version, '2.1.0');
  assert.ok(Array.isArray(s.runs[0].results));
});
