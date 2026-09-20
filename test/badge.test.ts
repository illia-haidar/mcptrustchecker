import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { renderBadge } from '../src/report/badge.js';
import { loadFixture } from './helpers.js';

async function badgeFor(fixture: string): Promise<any> {
  const report = await scanSurface(surfaceFromManifest(loadFixture(fixture), 'badge-test'));
  return JSON.parse(renderBadge(report)); // must be valid JSON
}

test('badge is a valid shields.io endpoint object', async () => {
  const b = await badgeFor('poisoned-server.json');
  assert.equal(b.schemaVersion, 1, 'shields endpoint schemaVersion is 1');
  assert.equal(typeof b.label, 'string');
  assert.ok(b.label.length > 0);
  assert.match(b.message, /^[A-F] \(\d{1,3}\)$/, 'message is "GRADE (score)"');
  assert.equal(typeof b.color, 'string');
});

test('a clean A server renders a green-ish badge; a poisoned F renders a red-ish badge', async () => {
  const clean = await badgeFor('clean-server.json');
  const poisoned = await badgeFor('poisoned-server.json');
  assert.match(clean.message, /^A /);
  assert.match(poisoned.message, /^F /);
  assert.notEqual(clean.color, poisoned.color, 'grade colour must differ between A and F');
});
