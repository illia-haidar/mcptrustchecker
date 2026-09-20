import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { resolveTargets } from '../src/acquire/index.js';
import { scanSurface } from '../src/engine.js';
import { checkIntegrity, pinSurface, emptyLockfile } from '../src/lockfile.js';
import { analyzeArtifactError } from '../src/detectors/supplyChain.js';
import type { PackageMeta } from '../src/types.js';

// A registry stub that records every URL requested and answers npm/PyPI shapes.
function tarEntry(name: string, content: string): Buffer {
  const data = Buffer.from(content, 'utf8');
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write('0', 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([h, padded]);
}

function tgz(files: Record<string, string>): Buffer {
  return gzipSync(Buffer.concat([...Object.entries(files).map(([n, c]) => tarEntry(n, c)), Buffer.alloc(1024)]));
}

test('config uvx entry resolves the PyPI registry, not npm (#4)', async () => {
  const requested: string[] = [];
  const sdist = tgz({ 'pkg-1.0.0/mod.py': 'import os' });
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    requested.push(href);
    if (href.includes('pypi.org') && href.endsWith('/json')) {
      return new Response(
        JSON.stringify({
          info: { version: '1.0.0', license: 'MIT' },
          urls: [
            {
              packagetype: 'sdist',
              url: 'https://files.pythonhosted.org/packages/aa/bb/pkg-1.0.0.tar.gz',
              digests: { sha256: createHash('sha256').update(sdist).digest('hex') },
            },
          ],
        }),
        { status: 200 },
      );
    }
    if (href.includes('files.pythonhosted.org')) return new Response(new Uint8Array(sdist), { status: 200 });
    return new Response('null', { status: 404 });
  }) as unknown as typeof fetch;

  try {
    const config = {
      mcpServers: { fetch: { command: 'uvx', args: ['mcp-server-fetch'] } },
    };
    const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'mtc-cfg-'));
    const cfgPath = join(dir, 'claude_desktop_config.json');
    writeFileSync(cfgPath, JSON.stringify(config));
    try {
      const [t] = await resolveTargets(cfgPath, { online: true });
      assert.equal(t!.surface.packageMeta?.registry, 'pypi', 'uvx → PyPI registry');
      assert.ok(requested.some((u) => u.includes('pypi.org')), 'queried PyPI');
      assert.ok(!requested.some((u) => u.includes('registry.npmjs.org')), 'never queried npm for a uvx server');
      assert.ok((t!.surface.sourceFiles?.length ?? 0) > 0, 'read the PyPI sdist source');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('a pinned bare spec resolves the requested version, not latest (#2/#6)', async () => {
  const v100 = tgz({ 'package/index.js': 'const a = 1' });
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    if (href.includes('registry.npmjs.org') && !href.includes('/-/')) {
      return new Response(
        JSON.stringify({
          'dist-tags': { latest: '9.9.9' },
          versions: {
            '1.0.0': { dist: { tarball: 'https://registry.npmjs.org/p/-/p-1.0.0.tgz', integrity: `sha512-${createHash('sha512').update(v100).digest('base64')}` } },
            '9.9.9': { dist: { tarball: 'https://registry.npmjs.org/p/-/p-9.9.9.tgz', integrity: 'sha512-bogus' } },
          },
          time: { '1.0.0': '2020-01-01T00:00:00Z' },
        }),
        { status: 200 },
      );
    }
    if (href.endsWith('p-1.0.0.tgz')) return new Response(new Uint8Array(v100), { status: 200 });
    if (href.includes('api.npmjs.org')) return new Response(JSON.stringify({ downloads: 1 }), { status: 200 });
    return new Response('null', { status: 404 });
  }) as unknown as typeof fetch;
  try {
    const [t] = await resolveTargets('p@1.0.0', { online: true });
    assert.equal(t!.surface.packageMeta?.version, '1.0.0', 'resolved the pinned version, not latest 9.9.9');
    assert.equal(t!.surface.packageMeta?.requestedSpec, '1.0.0');
    assert.ok(t!.surface.packageMeta?.tarballSha256, 'byte-pinned the pinned version');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('integrity-mismatch during --online is NOT swallowed: it raises a critical finding (#5)', () => {
  const meta: PackageMeta = { registry: 'npm', name: 'p', version: '1.0.0', artifactError: { kind: 'integrity', detail: 'hash mismatch' } };
  const findings = analyzeArtifactError(meta);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'MTC-TOFU-003');
  assert.equal(findings[0]!.severity, 'critical');
  assert.equal(findings[0]!.confidence, 'confirmed');
});

test('a network failure during --online yields an INFO "not verified" signal, not a silent pass (#5)', () => {
  const meta: PackageMeta = { registry: 'npm', name: 'p', version: '1.0.0', artifactError: { kind: 'network', detail: 'HTTP 503' } };
  const findings = analyzeArtifactError(meta);
  assert.equal(findings[0]!.ruleId, 'MTC-TOFU-004');
  assert.equal(findings[0]!.severity, 'info');
});

test('pin --online then an offline rescan does NOT raise a false rug pull (#7)', () => {
  // Online pin: byte hash recorded, tools empty (packages expose no live tools).
  const onlinePinned = {
    id: 'p',
    source: { kind: 'package' as const, origin: 'p' },
    server: { name: 'p' },
    tools: [],
    prompts: [],
    resources: [],
    packageMeta: { registry: 'npm' as const, name: 'p', version: '1.0.0', tarballSha256: 'a'.repeat(64) },
    sourceFiles: [{ path: 'index.js', content: 'x' }],
  };
  const lock = pinSurface(emptyLockfile(), onlinePinned);
  // Offline rescan of the same id: no source, no byte hash.
  const offline = { ...onlinePinned, packageMeta: { registry: 'npm' as const, name: 'p', version: '1.0.0' }, sourceFiles: undefined };
  assert.equal(checkIntegrity(offline, lock).status, 'unchanged');
});

test('pin during a failed online fetch keeps the previously-pinned bytes (#5, no un-pin)', () => {
  const good = {
    id: 'p',
    source: { kind: 'package' as const, origin: 'p' },
    server: { name: 'p' },
    tools: [],
    prompts: [],
    resources: [],
    packageMeta: { registry: 'npm' as const, name: 'p', version: '1.0.0', tarballSha256: 'a'.repeat(64) },
  };
  const lock = pinSurface(emptyLockfile(), good);
  // Re-pin while the fetch failed (no tarballSha256, same version).
  const failed = { ...good, packageMeta: { registry: 'npm' as const, name: 'p', version: '1.0.0', artifactError: { kind: 'network' as const, detail: 'x' } } };
  const relock = pinSurface(lock, failed);
  assert.equal(relock.servers['p']!.tarballSha256, 'a'.repeat(64), 'byte pin survived the outage');
});

test('a source-file surface scans byte-identically regardless of file order (#12)', async () => {
  const files = Array.from({ length: 15 }, (_, i) => ({ path: `f${i}.js`, content: 'eval(x)' }));
  const mk = (fs: typeof files) => ({
    id: 's',
    source: { kind: 'package' as const, origin: 's' },
    server: { name: 's' },
    tools: [],
    prompts: [],
    resources: [],
    sourceFiles: fs,
  });
  const a = await scanSurface(mk([...files]));
  const b = await scanSurface(mk([...files].reverse()));
  // The source detector sorts internally, so the capped per-rule findings — and
  // thus the whole report — are identical no matter the input order.
  assert.equal(JSON.stringify(a.findings), JSON.stringify(b.findings));
  assert.equal(a.surfaceDigest, b.surfaceDigest);
});
