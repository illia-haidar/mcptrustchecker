import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeEnv, isBlockedHost, ALLOWED_COMMANDS } from '../src/acquire/live.js';

// Acquisition runs untrusted servers, so its sandbox is itself security-critical.
// These lock the guarantees that keep a scan from becoming RCE / SSRF.

test('env scrub strips every execution-hijacking variable, keeps benign ones', () => {
  const { clean, dropped } = sanitizeEnv({
    PATH: '/tmp/evil',
    NODE_PATH: '/tmp/x',
    NODE_OPTIONS: '--require /tmp/pwn.js',
    LD_PRELOAD: '/tmp/pwn.so',
    LD_LIBRARY_PATH: '/tmp',
    DYLD_INSERT_LIBRARIES: '/tmp/pwn.dylib',
    PYTHONPATH: '/tmp',
    PYTHONSTARTUP: '/tmp/x.py',
    BASH_FUNC_x: '() { echo pwned; }',
    API_BASE: 'https://ok.example.com',
    MY_TOKEN: 'keepme',
  });
  for (const dangerous of ['PATH', 'NODE_PATH', 'NODE_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'PYTHONPATH']) {
    assert.ok(!(dangerous in clean), `${dangerous} must be scrubbed`);
    assert.ok(dropped.includes(dangerous), `${dangerous} reported as dropped`);
  }
  assert.equal(clean.API_BASE, 'https://ok.example.com', 'benign vars survive');
  assert.equal(clean.MY_TOKEN, 'keepme');
});

test('SSRF guard blocks loopback, link-local and cloud-metadata hosts', () => {
  for (const blocked of ['127.0.0.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254']) {
    assert.equal(isBlockedHost(blocked), true, `${blocked} must be blocked`);
  }
});

test('SSRF guard does NOT over-block ordinary public DNS names', () => {
  for (const ok of ['example.com', 'api.example.com', 'fc-api.example.com', 'fdrive.io', 'mcp.acme.dev']) {
    assert.equal(isBlockedHost(ok), false, `${ok} must be allowed`);
  }
});

test('the executable allowlist is bare-name only and covers the known runtimes', () => {
  for (const cmd of ['npx', 'uvx', 'node', 'python', 'python3']) {
    assert.ok(ALLOWED_COMMANDS.has(cmd), `${cmd} is allow-listed`);
  }
  // a path-qualified command is never a bare allow-listed name
  assert.ok(!ALLOWED_COMMANDS.has('/tmp/evil/node'), 'path-qualified command is not allow-listed');
  assert.ok(!ALLOWED_COMMANDS.has('bash'), 'arbitrary shells are not allow-listed');
});
