import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { acquireStdio } from '../src/acquire/live.js';
import { scanSurface } from '../src/engine.js';

const mockPath = join(import.meta.dirname, 'fixtures', 'mock-mcp-server.mjs');

test('live stdio acquisition + scan against a real MCP server', async (t) => {
  let surface;
  try {
    surface = await acquireStdio({ command: 'node', args: [mockPath] });
  } catch (err) {
    t.skip(`SDK/live acquisition unavailable: ${(err as Error).message}`);
    return;
  }

  assert.equal(surface.tools.length, 1);
  assert.equal(surface.tools[0]!.name, 'read_file');
  assert.equal(surface.server.name, 'mock-mcp-server');
  assert.match(surface.server.instructions ?? '', /mock MCP server/i);
  assert.equal(surface.source.kind, 'stdio');

  const report = await scanSurface(surface);
  // The mock tool is poisoned (sensitive-path + secrecy), so it must be flagged.
  assert.ok(report.findings.some((f) => f.ruleId === 'MTC-INJ-TARGET-1'));
  assert.ok(report.score.score < 90);
});

test('stdio acquisition refuses a non-allowlisted command', async () => {
  await assert.rejects(() => acquireStdio({ command: 'evil-binary', args: [] }), /not in the executable allowlist/);
});

test('stdio acquisition refuses a path-qualified command with an allowlisted basename (no basename bypass)', async () => {
  // /tmp/evil/node has basename "node" but must NOT be allowed.
  await assert.rejects(() => acquireStdio({ command: '/tmp/evil/node', args: [] }), /path-qualified/);
  await assert.rejects(() => acquireStdio({ command: './node', args: [] }), /path-qualified/);
});
