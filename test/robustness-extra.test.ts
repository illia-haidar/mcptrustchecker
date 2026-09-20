import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';

// The scanner must never throw on a hostile / malformed surface — a crash is
// itself a denial-of-service and could mask a finding.

async function mustNotThrow(input: unknown, label: string) {
  await assert.doesNotReject(async () => {
    await scanSurface(surfaceFromManifest(input, 'robust'));
  }, `scanSurface threw on ${label}`);
}

test('prototype-pollution keys in a tool schema do not poison or crash', async () => {
  const evil = JSON.parse('{"tools":[{"name":"t","description":"x","inputSchema":{"type":"object","properties":{"__proto__":{"type":"string"},"constructor":{"type":"string"}}}}]}');
  await mustNotThrow(evil, 'proto-pollution keys');
  assert.equal(({} as any).polluted, undefined, 'Object.prototype must be untouched');
});

test('a deeply nested inputSchema does not stack-overflow', async () => {
  let schema: any = { type: 'string' };
  for (let i = 0; i < 2000; i++) schema = { type: 'object', properties: { nested: schema } };
  await mustNotThrow({ tools: [{ name: 't', description: 'x', inputSchema: schema }] }, 'deeply nested schema');
});

test('thousands of tools are handled without blowing up', async () => {
  const tools = Array.from({ length: 5000 }, (_, i) => ({ name: `tool_${i}`, description: 'does a thing' }));
  await mustNotThrow({ tools }, '5000 tools');
});

test('non-string / wrong-typed fields do not crash', async () => {
  await mustNotThrow({ tools: [{ name: 123, description: { not: 'a string' }, inputSchema: [1, 2, 3] }] }, 'wrong-typed fields');
  await mustNotThrow({ tools: 'not-an-array', prompts: 42, resources: null }, 'wrong-typed collections');
  await mustNotThrow({ tools: [null, undefined, 7, {}] }, 'junk tool entries');
});

test('null / empty / primitive top-level inputs do not crash', async () => {
  for (const junk of [null, undefined, 42, 'string', [], {}, { tools: [] }]) {
    await mustNotThrow(junk, `top-level ${JSON.stringify(junk)}`);
  }
});

test('an empty surface is flagged, never silently "clean"', async () => {
  const r = await scanSurface(surfaceFromManifest({ tools: [] }, 'empty'));
  assert.ok(r.findings.some((f) => f.ruleId === 'MTC-META-001'), 'empty surface should raise MTC-META-001');
});
