/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { extractToolsFromSource } from '../src/acquire/toolExtract.js';
import { OPEN_DESTINATION_REASON, UNTRUSTED_INPUT_OBSERVATION } from '../src/scoring/capability.js';
import { staticParamFacts } from '../src/util/capabilities.js';
import type { ScanReport, ServerSurface } from '../src/types.js';

// 1.16.1 — a statically recovered tool keeps only parameter names, so whether
// its url is pinned is read from the registration source. A pattern pins the
// destination only when it bounds the whole value, exactly as for a declared
// schema: `z.string().regex(/^https?:\/\//)` admits any host and stays moderate.

async function scanPkg(content: string): Promise<ScanReport> {
  const files = [{ path: 'dist/index.js', content }];
  const ex = extractToolsFromSource(files);
  assert.ok(ex.tools.length > 0, 'the registration is recovered');
  return scanSurface({
    id: 'pkg',
    source: { kind: 'package', origin: 'pkg' },
    server: {},
    tools: ex.tools,
    prompts: [],
    resources: [],
    sourceFiles: files,
    toolProvenance: 'static',
    staticTools: ex.origins,
  } as unknown as ServerSurface);
}

const registration = (url: string) =>
  `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nimport { z } from 'zod';\nimport { get } from './net.js';\n` +
  `server.registerTool('fetch_page', { description: 'Return a page.', inputSchema: { url: ${url} } }, async ({ url }) => ({ content: [{ type: 'text', text: await get(url) }] }));\n`;

test('a static url pinned only by a prefix pattern → moderate, like the same declared schema', async () => {
  for (const url of [
    'z.string().regex(/^https?:\\/\\//)',
    "z.string().regex(/^https:\\/\\/[a-z0-9.-]+/).describe('Page URL')",
    "{ type: 'string', pattern: '^https?://' }",
    "{ type: 'string', pattern: 'example\\\\.com$' }",
  ]) {
    const r = await scanPkg(registration(url));
    assert.equal(r.capabilityProfile.level, 'moderate', url);
    assert.deepEqual(r.capabilityProfile.reasons, [OPEN_DESTINATION_REASON], url);
    assert.deepEqual(r.capabilityProfile.observations, [], url);
  }
});

test('a static url pinned by a whole-value pattern, an enum or a literal → minimal, with the observation', async () => {
  for (const url of [
    "{ type: 'string', pattern: '^https://api\\\\.example\\\\.com/v1$' }",
    "z.enum(['https://api.example.com/a', 'https://api.example.com/b'])",
    "z.literal('https://api.example.com/search')",
  ]) {
    const r = await scanPkg(registration(url));
    assert.equal(r.capabilityProfile.level, 'minimal', url);
    assert.deepEqual(r.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION], url);
  }
});

test('staticParamFacts names the pattern only when it is the sole constraint; `constrained` is unchanged', () => {
  const js =
    "server.registerTool('x', { inputSchema: { url: z.string().regex(/^https?:\\/\\//), host: { type: 'string', enum: ['a'], pattern: '^[a-z]+$' }, raw: z.string() } }, h);";
  const s = {
    id: 's',
    source: { kind: 'package', origin: 's' },
    server: {},
    tools: [],
    prompts: [],
    resources: [],
    sourceFiles: [{ path: 'a.js', content: js }],
    toolProvenance: 'static',
    staticTools: { x: { file: 'a.js', line: 1, via: 'direct', hintSource: 'declared' } },
  } as unknown as ServerSurface;
  assert.deepEqual(staticParamFacts(s, 'x', 'url'), { constrained: true, pattern: '^https?:\\/\\/' });
  assert.deepEqual(staticParamFacts(s, 'x', 'host'), { constrained: true });
  assert.deepEqual(staticParamFacts(s, 'x', 'raw'), { constrained: false });
});

// MTC-CAP-007 reads a destination the same way: a prefix pattern leaves the host
// to the model, a whole-value pattern or an enum pins it — for a declared schema
// and for a statically recovered one alike.
const cap007 = (r: ScanReport) => r.findings.filter((f) => f.ruleId === 'MTC-CAP-007').length;

test('MTC-CAP-007 fires on a url pinned only by a prefix pattern, static or declared', async () => {
  for (const url of ['z.string().regex(/^https?:\\/\\//)', "{ type: 'string', pattern: '^https?://' }"]) {
    assert.equal(cap007(await scanPkg(registration(url))), 1, url);
  }
  const declared = await scanSurface({
    id: 'm',
    source: { kind: 'manifest', origin: 'm.json' },
    server: {},
    tools: [{ name: 'fetch_page', description: 'Fetch a web page and return its text.', inputSchema: { type: 'object', properties: { url: { type: 'string', pattern: '^https?://' } } } }],
    prompts: [],
    resources: [],
  } as unknown as ServerSurface);
  assert.equal(cap007(declared), 1);
});

test('MTC-CAP-007 stays silent on a url pinned by a whole-value pattern or an enum', async () => {
  for (const url of [
    "{ type: 'string', pattern: '^https://api\\\\.example\\\\.com/v1$' }",
    "z.enum(['https://api.example.com/a', 'https://api.example.com/b'])",
  ]) {
    assert.equal(cap007(await scanPkg(registration(url))), 0, url);
  }
  const declared = await scanSurface({
    id: 'm',
    source: { kind: 'manifest', origin: 'm.json' },
    server: {},
    tools: [{ name: 'fetch_page', description: 'Fetch a web page and return its text.', inputSchema: { type: 'object', properties: { url: { type: 'string', pattern: '^https://api\\.example\\.com/v1$' } } } }],
    prompts: [],
    resources: [],
  } as unknown as ServerSurface);
  assert.equal(cap007(declared), 0);
});
