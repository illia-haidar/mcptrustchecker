import { test } from 'node:test';
import assert from 'node:assert/strict';
import { expandVars, redactSensitiveArgs, packageSpecFromStdio } from '../src/acquire/clientConfig.js';

test('expandVars resolves ${VAR} and $VAR from env', () => {
  assert.equal(expandVars('Authorization:${AUTH}', { AUTH: 'Bearer abc' }), 'Authorization:Bearer abc');
  assert.equal(expandVars('$HOME/x', { HOME: '/tmp' }), '/tmp/x');
});

test('expandVars leaves unknown variables untouched', () => {
  assert.equal(expandVars('${MISSING}', {}), '${MISSING}');
});

test('redactSensitiveArgs scrubs bearer tokens and header values', () => {
  const out = redactSensitiveArgs(['-y', 'mcp-remote', 'https://h/mcp', '--header', 'Authorization:Bearer eyJabc123def456ghi']);
  assert.ok(!out.join(' ').includes('eyJabc123def456ghi'));
  assert.ok(out.join(' ').includes('<redacted>'));
  assert.equal(out[2], 'https://h/mcp'); // non-secret args untouched
});

test('redactSensitiveArgs redacts a bare value after a secret flag', () => {
  const out = redactSensitiveArgs(['--token', 'sk-supersecretvalue12345']);
  assert.equal(out[1], '<redacted>');
});

test('packageSpecFromStdio extracts name and version from an npx spec', () => {
  assert.deepEqual(packageSpecFromStdio('npx', ['-y', 'mcp-remote@1.2.3', 'https://x']), { name: 'mcp-remote', version: '1.2.3' });
});
