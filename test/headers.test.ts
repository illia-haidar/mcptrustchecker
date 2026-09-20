import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHeaderArgs, applyCredentialGate } from '../src/util/headers.js';

test('parseHeaderArgs: undefined/empty → undefined', () => {
  assert.equal(parseHeaderArgs(undefined), undefined);
  assert.equal(parseHeaderArgs([]), undefined);
});

test('parseHeaderArgs: parses "Name: Value" and trims', () => {
  assert.deepEqual(parseHeaderArgs(['Authorization: Bearer 3|abc']), { Authorization: 'Bearer 3|abc' });
  assert.deepEqual(parseHeaderArgs(['  X-Api-Key :  k123  ']), { 'X-Api-Key': 'k123' });
});

test('parseHeaderArgs: multiple headers accumulate', () => {
  assert.deepEqual(parseHeaderArgs(['Authorization: Bearer t', 'X-Trace: on']), {
    Authorization: 'Bearer t',
    'X-Trace': 'on',
  });
});

test('parseHeaderArgs: value may contain colons (e.g. a URL)', () => {
  assert.deepEqual(parseHeaderArgs(['Referer: https://x.example/mcp']), {
    Referer: 'https://x.example/mcp',
  });
});

test('parseHeaderArgs: malformed input throws', () => {
  assert.throws(() => parseHeaderArgs(['no-colon-here']), /expected "Name: Value"/);
  assert.throws(() => parseHeaderArgs([': novalue-name']), /empty header name|expected "Name: Value"/);
});

test('applyCredentialGate: same-origin keeps request headers and adds static headers', () => {
  const h = applyCredentialGate({ authorization: 'Bearer tok', 'mcp-session-id': 's1' }, true, { 'X-Extra': 'v' });
  assert.equal(h.get('authorization'), 'Bearer tok');
  assert.equal(h.get('mcp-session-id'), 's1');
  assert.equal(h.get('x-extra'), 'v');
});

test('applyCredentialGate: cross-origin strips credentials AND drops static headers', () => {
  const h = applyCredentialGate(
    { authorization: 'Bearer tok', cookie: 'c=1', 'proxy-authorization': 'x', 'mcp-session-id': 's1', 'content-type': 'application/json' },
    false,
    { 'X-Extra': 'v', Authorization: 'Bearer static' },
  );
  assert.equal(h.get('authorization'), null);
  assert.equal(h.get('cookie'), null);
  assert.equal(h.get('proxy-authorization'), null);
  assert.equal(h.get('mcp-session-id'), null);
  assert.equal(h.get('x-extra'), null);
  // non-credential headers survive the cross-origin hop
  assert.equal(h.get('content-type'), 'application/json');
});
