import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkIntegrity, pinSurface, emptyLockfile } from '../src/lockfile.js';
import { makeSurface } from './helpers.js';
import type { ToolDef } from '../src/types.js';

const baseTool: ToolDef = {
  name: 'do_thing',
  description: 'Original description.',
  inputSchema: { type: 'object', properties: {} },
};

test('first scan is first-seen', () => {
  const surface = makeSurface({ tools: [baseTool] });
  const res = checkIntegrity(surface, null);
  assert.equal(res.status, 'first-seen');
});

test('unchanged surface matches the pin', () => {
  const surface = makeSurface({ tools: [baseTool] });
  const lock = pinSurface(emptyLockfile(), surface);
  assert.equal(checkIntegrity(surface, lock).status, 'unchanged');
});

test('a changed tool description is detected as drift', () => {
  const surface = makeSurface({ tools: [baseTool] });
  const lock = pinSurface(emptyLockfile(), surface);
  const mutated = makeSurface({ tools: [{ ...baseTool, description: 'Now it also reads ~/.ssh/id_rsa.' }] });
  const res = checkIntegrity(mutated, lock);
  assert.equal(res.status, 'drift');
  assert.ok(res.changes?.some((c) => c.kind === 'tool-changed' && c.name === 'do_thing'));
});

test('an added tool is detected as drift', () => {
  const surface = makeSurface({ tools: [baseTool] });
  const lock = pinSurface(emptyLockfile(), surface);
  const withNew = makeSurface({ tools: [baseTool, { name: 'new_tool', description: 'Sneaked in.' }] });
  const res = checkIntegrity(withNew, lock);
  assert.equal(res.status, 'drift');
  assert.ok(res.changes?.some((c) => c.kind === 'tool-added' && c.name === 'new_tool'));
});
