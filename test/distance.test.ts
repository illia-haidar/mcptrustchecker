import { test } from 'node:test';
import assert from 'node:assert/strict';
import { damerauLevenshtein, isKeyboardTypo, isKeyboardAdjacent, compareVersions, bareName } from '../src/util/distance.js';

// The string/version primitives behind typosquat + CVE detection.

test('damerauLevenshtein: substitutions, insertions, and adjacent transposition', () => {
  assert.equal(damerauLevenshtein('kitten', 'kitten'), 0);
  assert.equal(damerauLevenshtein('kitten', 'sitting'), 3);
  assert.equal(damerauLevenshtein('', 'abc'), 3);
  assert.equal(damerauLevenshtein('abc', ''), 3);
  assert.equal(damerauLevenshtein('ab', 'ba'), 1); // a single transposition = distance 1 (Damerau, not plain Levenshtein)
  assert.equal(damerauLevenshtein('playwright', 'playright'), 1); // dropped letter — a classic squat
});

test('bareName strips an npm scope', () => {
  assert.equal(bareName('@modelcontextprotocol/server-filesystem'), 'server-filesystem');
  assert.equal(bareName('mcp-remote'), 'mcp-remote');
  assert.equal(bareName('@scope/pkg'), 'pkg');
});

test('compareVersions orders semver numerically, not lexically', () => {
  assert.ok(compareVersions('1.2.0', '1.10.0') < 0, '1.2.0 < 1.10.0 (2 < 10 numerically)');
  assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
  assert.ok(compareVersions('2.0.0', '1.9.9') > 0);
  assert.ok(compareVersions('0.1.16', '0.1.0') > 0); // the CVE boundary for mcp-remote
});

test('isKeyboardTypo: exactly one adjacent-key substitution, same length', () => {
  assert.equal(isKeyboardTypo('abc', 'abc'), false, 'zero diffs is not a typo');
  assert.equal(isKeyboardTypo('abc', 'xyz'), false, 'more than one diff is not a typo');
  assert.equal(isKeyboardTypo('ab', 'abc'), false, 'length mismatch is not a typo');
  // a genuine adjacent-key slip is caught (guarded on the adjacency map)
  assert.equal(isKeyboardTypo('s', 'a'), isKeyboardAdjacent('s', 'a'));
});
