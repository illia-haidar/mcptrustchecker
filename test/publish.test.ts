import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  buildPublishRequest,
  publishScan,
  publishableTarget,
  publishableTargets,
  publishEndpoint,
  normalizeCategory,
} from '../src/publish.js';
import type { ResolvedTarget } from '../src/acquire/index.js';
import type { ScanReport, ServerSurface } from '../src/types.js';

// Publishing talks to a server the user did not ask about, so the boundary is
// the security property: `scan` never publishes and never asks, `publish` is a
// separate command whose invocation IS the consent, and neither can change a
// scan's verdict or exit code.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'dist', 'cli', 'index.js');
if (!existsSync(CLI)) execSync('npm run build', { cwd: ROOT, stdio: 'ignore' });

function surface(partial: Partial<ServerSurface>): ServerSurface {
  return {
    id: 'x',
    source: { kind: 'manifest', origin: 'x' },
    server: { name: 'x' },
    tools: [],
    prompts: [],
    resources: [],
    ...partial,
  } as ServerSurface;
}

function target(partial: Partial<ServerSurface>): ResolvedTarget {
  const s = surface(partial);
  return { label: s.id, surface: s };
}

const PACKAGE_TARGET = target({
  id: '@scope/server',
  source: { kind: 'package', origin: '@scope/server' },
  packageMeta: { registry: 'npm', name: '@scope/server', version: '1.2.3' },
});
test('only a real registry identity is publishable', () => {
  assert.deepEqual(publishableTarget(PACKAGE_TARGET), {
    registry: 'npm',
    spec: '@scope/server',
    version: '1.2.3',
  });

  // A manifest has no package identity at all.
  assert.equal(publishableTarget(target({ id: 'tools.json' })), undefined);
  // A local directory scan carries a package.json name — but nothing published.
  assert.equal(
    publishableTarget(
      target({
        source: { kind: 'package', origin: './my-server' },
        packageMeta: { registry: 'npm', name: 'my-server' },
      }),
    ),
    undefined,
  );
  // A packed archive on disk, likewise.
  assert.equal(
    publishableTarget(
      target({
        source: { kind: 'package', origin: 'my-server-1.0.0.tgz' },
        packageMeta: { registry: 'npm', name: 'my-server' },
      }),
    ),
    undefined,
  );
  // A live endpoint and a spawned stdio command have no registry spec.
  assert.equal(publishableTarget(target({ source: { kind: 'http', origin: 'https://h/mcp' } })), undefined);
  assert.equal(publishableTarget(target({ source: { kind: 'stdio', origin: 'npx -y srv' } })), undefined);
  // A malformed name never leaves the machine.
  assert.equal(
    publishableTarget(
      target({
        source: { kind: 'package', origin: 'bad name' },
        packageMeta: { registry: 'npm', name: 'bad name' },
      }),
    ),
    undefined,
  );
});

test('a batch is deduplicated and keeps resolution order', () => {
  const out = publishableTargets([PACKAGE_TARGET, PACKAGE_TARGET, target({ id: 'manifest' })]);
  assert.equal(out.length, 1);
  assert.equal(out[0]!.spec, '@scope/server');
});

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

test('the body carries explicit consent and never an authoritative grade', () => {
  const report = { score: { grade: 'B', score: 81 } } as unknown as ScanReport;
  const body = buildPublishRequest(PACKAGE_TARGET, { category: 'developer-tools', report })!;
  assert.equal(body.consent, true);
  assert.equal(body.registry, 'npm');
  assert.equal(body.spec, '@scope/server');
  assert.equal(body.category, 'developer-tools');
  // The local grade travels as an informational field only; there is no `grade`
  // or `score` field the server could mistake for a verdict.
  assert.equal(body.localGrade, 'B');
  assert.deepEqual(Object.keys(body).sort(), [
    'category',
    'client',
    'consent',
    'localGrade',
    'registry',
    'spec',
    'version',
  ]);

  // An unknown category degrades to `other` rather than being sent through.
  assert.equal(buildPublishRequest(PACKAGE_TARGET, { category: 'nonsense' })!.category, 'other');
  assert.equal(normalizeCategory(undefined), 'other');
  // A target with no identity yields no body, so the caller can skip silently.
  assert.equal(buildPublishRequest(target({ id: 'tools.json' })), undefined);
});

test('the endpoint is derived from the origin and rejects non-http schemes', () => {
  assert.equal(publishEndpoint(), 'https://mcptrustchecker.com/api/v1/registry/publish');
  assert.equal(publishEndpoint('http://localhost:8790'), 'http://localhost:8790/api/v1/registry/publish');
  assert.equal(publishEndpoint('file:///etc/passwd'), undefined);
  assert.equal(publishEndpoint('not a url'), undefined);
});

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

test('publishScan sends the key, a User-Agent and the consenting body', async () => {
  let seen: { auth?: string; ua?: string; body?: Record<string, unknown> } = {};
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      seen = {
        auth: req.headers.authorization,
        ua: req.headers['user-agent'] as string,
        body: JSON.parse(raw),
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'queued', registry: 'npm', spec: '@scope/server', publicationId: 7 }));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const body = buildPublishRequest(PACKAGE_TARGET)!;
    const result = await publishScan(body, { token: 'k-test', origin: `http://127.0.0.1:${port}` });
    assert.equal(result.ok, true);
    assert.equal(result.ok && result.response.status, 'queued');
    assert.equal(seen.auth, 'Bearer k-test');
    assert.match(String(seen.ua), /^mcptrustchecker\//);
    assert.equal(seen.body!.consent, true);
  } finally {
    server.close();
  }
});

test('a network failure is a value, never a throw', async () => {
  const body = buildPublishRequest(PACKAGE_TARGET)!;
  // Port 1 on loopback refuses connections immediately.
  const result = await publishScan(body, { token: 'k', origin: 'http://127.0.0.1:1' });
  assert.equal(result.ok, false);
  assert.equal(typeof (result as { error: string }).error, 'string');
});

// ---------------------------------------------------------------------------
// The command boundary: scanning and publishing are separate acts
// ---------------------------------------------------------------------------

test('a plain scan never publishes and never mentions publishing', () => {
  const res = spawnSync('node', [CLI, 'scan', 'test/fixtures/clean-server.json', '--no-pager'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, MCPTRUSTCHECKER_TOKEN: 'should-be-ignored' },
    input: '',
  });
  assert.equal(res.status, 0);
  // Not even with a token in the environment: only the command decides.
  assert.doesNotMatch(res.stderr, /publish/i);
  assert.doesNotMatch(res.stdout, /publish/i);
});

test('the --publish flag is gone: publishing is a command, not a scan option', () => {
  const res = spawnSync('node', [CLI, 'scan', 'test/fixtures/clean-server.json', '--publish', '--no-pager'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.notEqual(res.status, 0, '--publish must no longer be accepted');
  assert.match(res.stderr, /unknown option|not allowed/i);
});

test('publish without a key fails fast, before any scanning', () => {
  const res = spawnSync('node', [CLI, 'publish', '@modelcontextprotocol/server-filesystem', '--no-pager'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, MCPTRUSTCHECKER_TOKEN: '' },
  });
  assert.equal(res.status, 2);
  assert.match(res.stderr, /publish needs an API key/i);
  // Fast means fast: it must not have downloaded the package first.
  assert.doesNotMatch(res.stdout, /TRUST GRADE/i);
});

test('publish refuses a target with no registry identity', () => {
  const res = spawnSync('node', [CLI, 'publish', 'test/fixtures/clean-server.json', '--token', 'k', '--no-pager'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(res.status, 2);
  assert.match(res.stderr, /only npm and PyPI packages/i);
});

test('help documents publish as its own command', () => {
  const res = spawnSync('node', [CLI, '--help'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.match(res.stdout, /publish <package>/);
  assert.match(res.stdout, /a plain scan never publishes and never asks/i);
  assert.doesNotMatch(res.stdout, /--no-publish/);
});
