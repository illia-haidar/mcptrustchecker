import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverClientConfigs } from '../src/acquire/discover.js';

test('discoverClientConfigs returns an array without throwing', () => {
  const found = discoverClientConfigs();
  assert.ok(Array.isArray(found));
  for (const c of found) {
    assert.equal(typeof c.client, 'string');
    assert.equal(typeof c.path, 'string');
  }
});
