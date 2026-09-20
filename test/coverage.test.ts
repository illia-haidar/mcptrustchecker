import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeCoverage, coverageLabel } from '../src/scoring/coverage.js';
import { scanSurface } from '../src/engine.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderTerminal } from '../src/report/terminal.js';
import { makeSurface } from './helpers.js';
import type { ServerSurface } from '../src/types.js';

const surf = (p: Partial<ServerSurface>): ServerSurface => makeSurface(p);

test('live transport (stdio/http) → coverage "live", no caveats', () => {
  const cov = computeCoverage(surf({ source: { kind: 'stdio', origin: 'x' }, tools: [{ name: 't' }] }));
  assert.equal(cov.level, 'live');
  assert.equal(cov.inputs.liveTransport, true);
  assert.equal(cov.caveats.length, 0);
});

test('a live scan with tools but no source does not nag about source', () => {
  const cov = computeCoverage(surf({ source: { kind: 'http', origin: 'u' }, tools: [{ name: 't' }] }));
  assert.equal(cov.level, 'live');
  assert.ok(!cov.caveats.some((c) => /implementation source/.test(c)));
});

test('package with source read but no tools → "source" + a no-tools caveat', () => {
  const cov = computeCoverage(
    surf({
      source: { kind: 'package', origin: 'p' },
      packageMeta: { registry: 'npm', name: 'p', version: '1.0.0' },
      sourceFiles: [{ path: 'index.js', content: 'x' }],
    }),
  );
  assert.equal(cov.level, 'source');
  assert.equal(cov.inputs.implementationSource, true);
  assert.equal(cov.inputs.toolSurface, false);
  assert.ok(cov.caveats.some((c) => /No tools were enumerated/.test(c)));
  // source WAS read, so no "add --online" nag
  assert.ok(!cov.caveats.some((c) => /Add --online/.test(c)));
});

test('metadata-only package (no tools, no source) → "metadata" + both caveats', () => {
  const cov = computeCoverage(surf({ source: { kind: 'package', origin: 'p' }, packageMeta: { registry: 'npm', name: 'p' } }));
  assert.equal(cov.level, 'metadata');
  assert.ok(cov.caveats.some((c) => /No tools were enumerated/.test(c)));
  assert.ok(cov.caveats.some((c) => /Add --online/.test(c)));
});

test('static manifest (tools, no source, not live) → "manifest"', () => {
  const cov = computeCoverage(surf({ source: { kind: 'manifest', origin: 'tools.json' }, tools: [{ name: 't' }] }));
  assert.equal(cov.level, 'manifest');
  assert.equal(cov.inputs.toolSurface, true);
  assert.ok(!cov.caveats.some((c) => /No tools were enumerated/.test(c)));
  assert.ok(cov.caveats.some((c) => /tool metadata only/.test(c)));
});

test('an empty surface → "empty" with an explicit not-a-clean-bill caveat', () => {
  const cov = computeCoverage(surf({ source: { kind: 'manifest', origin: 'x' } }));
  assert.equal(cov.level, 'empty');
  assert.ok(cov.caveats.some((c) => /empty surface is not a clean bill/.test(c)));
});

test('coverage is deterministic for the same surface', () => {
  const s = surf({ source: { kind: 'package', origin: 'p' }, packageMeta: { registry: 'npm', name: 'p' } });
  assert.deepEqual(computeCoverage(s), computeCoverage(s));
});

test('scanSurface attaches coverage to the report', async () => {
  const report = await scanSurface(surf({ source: { kind: 'package', origin: 'p' }, packageMeta: { registry: 'npm', name: 'p' } }));
  assert.equal(report.coverage.level, 'metadata');
  assert.ok(report.coverage.caveats.length > 0);
});

test('terminal and markdown render the Coverage axis and caveats', async () => {
  const report = await scanSurface(surf({ source: { kind: 'package', origin: 'p' }, packageMeta: { registry: 'npm', name: 'p' } }));
  const term = renderTerminal(report);
  const md = renderMarkdown(report);
  assert.match(term, /Coverage METADATA/);
  assert.match(term, /this grade reflects only what was inspected/i);
  assert.match(md, /\*\*Coverage:\*\*/);
  assert.match(md, /METADATA/);
});

test('coverageLabel returns a distinct human string per level', () => {
  const levels = ['live', 'source', 'manifest', 'metadata', 'empty'] as const;
  const labels = levels.map(coverageLabel);
  assert.equal(new Set(labels).size, levels.length);
});
