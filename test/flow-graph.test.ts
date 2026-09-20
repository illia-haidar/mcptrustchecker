import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { consumesFreeText, representativeTrifectaPath } from '../src/detectors/flowGraph.js';
import { extractCapabilities } from '../src/util/capabilities.js';
import { resolveConfig } from '../src/config.js';
import { loadFixture } from './helpers.js';
import type { ServerSurface } from '../src/types.js';

test('consumesFreeText detects an unconstrained content/body/url param, ignores enums', () => {
  assert.equal(consumesFreeText({ name: 't', inputSchema: { type: 'object', properties: { body: { type: 'string' } } } }), true);
  assert.equal(consumesFreeText({ name: 't', inputSchema: { type: 'object', properties: { url: {} } } }), true);
  assert.equal(consumesFreeText({ name: 't', inputSchema: { type: 'object', properties: { mode: { type: 'string', enum: ['a', 'b'] } } } }), false);
  assert.equal(consumesFreeText({ name: 't', inputSchema: { type: 'object', properties: { count: { type: 'number' } } } }), false);
});

test('a representative trifecta path is a concrete distinct-tool chain', () => {
  const surface = surfaceFromManifest(loadFixture('toxic-flow-server.json'), 'x') as ServerSurface;
  const caps = extractCapabilities(surface, resolveConfig({}));
  const p = representativeTrifectaPath(caps, surface.tools);
  assert.ok(p, 'a path should be recovered');
  assert.equal(p!.path.length, 3, 'three distinct legs');
  assert.equal(new Set(p!.path).size, 3, 'legs are distinct tools');
  assert.equal(p!.edges.length, 2);
});

test('MTC-FLOW-002 reports the concrete attack chain and a schema-wired flag', async () => {
  const r = await scanSurface(surfaceFromManifest(loadFixture('toxic-flow-server.json'), 'x'));
  const f = r.findings.find((x) => x.ruleId === 'MTC-FLOW-002');
  assert.ok(f, 'cross-tool trifecta finding present');
  const path = (f!.data as any).path as string[];
  assert.deepEqual(path, ['fetch_url', 'read_file', 'http_request']);
  assert.equal((f!.data as any).wired, true, 'http_request takes a free-text body → schema-wired leg');
  assert.match(f!.description, /fetch_url/);
});

test('the recovered path is deterministic across runs', async () => {
  const paths = new Set<string>();
  for (let i = 0; i < 5; i++) {
    const r = await scanSurface(surfaceFromManifest(loadFixture('toxic-flow-server.json'), 'x'));
    const f = r.findings.find((x) => x.ruleId === 'MTC-FLOW-002');
    paths.add(JSON.stringify((f!.data as any).path));
  }
  assert.equal(paths.size, 1);
});

test('a purely agent-mediated chain (no free-text sink param) is still detected but not wired', async () => {
  const r = await scanSurface(
    surfaceFromManifest(
      {
        tools: [
          { name: 'read_issue', description: 'Reads an untrusted GitHub issue body.', inputSchema: { type: 'object', properties: { issue: { type: 'number' } } } },
          { name: 'read_secret', description: 'Reads a secret from the vault.', inputSchema: { type: 'object', properties: { key: { type: 'string', enum: ['a', 'b'] } } } },
          { name: 'run_command', description: 'Executes a shell command.', inputSchema: { type: 'object', properties: { argv: { type: 'array' } } } },
        ],
      },
      'x',
    ),
  );
  const f = r.findings.find((x) => x.ruleId === 'MTC-FLOW-002');
  assert.ok(f, 'trifecta still detected across tools');
});
