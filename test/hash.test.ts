import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stableStringify, surfaceDigest, toolDigest } from '../src/util/hash.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';

// The rug-pull fingerprint. Canonicalization must be order-independent (so the
// same server never looks "drifted") yet collision-resistant (so a changed tool
// definition always changes the digest).

test('stableStringify is key-order independent', () => {
  assert.equal(stableStringify({ a: 1, b: 2, c: 3 }), stableStringify({ c: 3, b: 2, a: 1 }));
  assert.equal(stableStringify({ x: { p: 1, q: 2 } }), stableStringify({ x: { q: 2, p: 1 } }));
});

test('stableStringify distinguishes different values and shapes', () => {
  assert.notEqual(stableStringify({ a: 1 }), stableStringify({ a: 2 }));
  assert.notEqual(stableStringify({ a: 1 }), stableStringify({ a: '1' }));
  assert.notEqual(stableStringify([1, 2]), stableStringify([2, 1]));
});

test('surfaceDigest is a stable 64-hex SHA-256, independent of manifest key order', () => {
  const a = surfaceFromManifest({ server: { name: 's' }, tools: [{ name: 't', description: 'd' }] }, 'id');
  const b = surfaceFromManifest({ tools: [{ name: 't', description: 'd' }], server: { name: 's' } }, 'id');
  assert.match(surfaceDigest(a), /^[0-9a-f]{64}$/);
  assert.equal(surfaceDigest(a), surfaceDigest(b));
});

test('any change to a tool definition changes the digest (no rug-pull blind spot)', () => {
  const base = surfaceFromManifest({ tools: [{ name: 't', description: 'safe' }] }, 'id');
  const drifted = surfaceFromManifest({ tools: [{ name: 't', description: 'now exfiltrates ~/.ssh' }] }, 'id');
  const added = surfaceFromManifest({ tools: [{ name: 't', description: 'safe' }, { name: 'u', description: 'x' }] }, 'id');
  assert.notEqual(surfaceDigest(base), surfaceDigest(drifted));
  assert.notEqual(surfaceDigest(base), surfaceDigest(added));
});

test('toolDigest is per-tool and order-independent', () => {
  assert.equal(toolDigest({ name: 't', description: 'd' }), toolDigest({ description: 'd', name: 't' } as any));
  assert.notEqual(toolDigest({ name: 't', description: 'a' }), toolDigest({ name: 't', description: 'b' }));
});
