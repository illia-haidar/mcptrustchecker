import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { extractZip, type ArchiveLimits } from '../src/acquire/archive.js';
import { resolveTargets } from '../src/acquire/index.js';
import { checkIntegrity, pinSurface, emptyLockfile, entryFor } from '../src/lockfile.js';
import { makeSurface } from './helpers.js';
import type { PackageMeta } from '../src/types.js';

const LIMITS: ArchiveLimits = { maxFiles: 400, maxFileBytes: 512 * 1024, maxTotalBytes: 12 * 1024 * 1024 };

// ── Round-2 #1/#6: zip input-work amplification via aliased local headers ─────

test('extractZip: N central-directory entries aliasing ONE stream inflate it at most once (input-work DoS)', () => {
  const raw = Buffer.alloc(9 * 1024 * 1024); // inflates to 9 MB (> 512 KB cap) → discarded
  const comp = deflateRawSync(raw);
  const name = Buffer.from('a.js');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(comp.length, 18);
  local.writeUInt32LE(0, 22);
  local.writeUInt16LE(name.length, 26);
  const localBlock = Buffer.concat([local, name, comp]);

  const N = 400;
  const centrals: Buffer[] = [];
  for (let i = 0; i < N; i++) {
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(8, 10);
    c.writeUInt32LE(comp.length, 20);
    c.writeUInt32LE(0, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(0, 42); // every entry aliases the one local header at offset 0
    centrals.push(Buffer.concat([c, name]));
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(N, 8);
  eocd.writeUInt16LE(N, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(localBlock.length, 16);
  const zip = Buffer.concat([localBlock, cd, eocd]);

  const started = process.hrtime.bigint();
  const out = extractZip(zip, () => true, LIMITS);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(out.length, 0, 'the over-cap stream is discarded, not stored');
  // De-fix would do 400 full inflates; the seen-offset dedup keeps it at one.
  assert.ok(elapsedMs < 500, `aliased-stream extraction must stay bounded; took ${elapsedMs.toFixed(0)}ms`);
});

test('extractZip: distinct low-output streams are bounded by the compressed-input budget', () => {
  // Each entry is a distinct ~1 MB stream that inflates to 0 bytes (empty raw
  // deflate block). Without an input budget, 400 of them = 400 MB of inflate
  // reads; the inflatedBytes cap (12 MB) stops it after ~12 entries.
  const emptyStream = Buffer.from([0x03, 0x00]); // shortest empty raw-deflate stream → 0 bytes out
  // Pad the compressed region so each distinct entry charges ~1 MB of input.
  const pad = Buffer.alloc(1024 * 1024 - emptyStream.length, 0);
  const comp = Buffer.concat([emptyStream, pad]); // trailing bytes are ignored by inflate but read from disk region
  const name = Buffer.from('a.js');

  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  const N = 400;
  for (let i = 0; i < N; i++) {
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(0, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(Buffer.concat([local, name, comp]));
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(8, 10);
    c.writeUInt32LE(comp.length, 20);
    c.writeUInt32LE(0, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(offset, 42); // distinct local header offsets
    centrals.push(Buffer.concat([c, name]));
    offset += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(N, 8);
  eocd.writeUInt16LE(N, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  const zip = Buffer.concat([...locals, cd, eocd]);

  const started = process.hrtime.bigint();
  extractZip(zip, () => true, LIMITS);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(elapsedMs < 1000, `input-budget must bound distinct-stream work; took ${elapsedMs.toFixed(0)}ms`);
});

// ── Round-2 #4: scoped-package + version routing ─────────────────────────────

test('resolveTargets: @scope/name@version routes as a package, not a filesystem path', async () => {
  const [t] = await resolveTargets('@modelcontextprotocol/server-filesystem@1.0.0', {});
  assert.equal(t!.surface.source.kind, 'package');
  assert.equal(t!.surface.id, '@modelcontextprotocol/server-filesystem');
  assert.equal(t!.surface.packageMeta?.requestedSpec, '1.0.0');
});

// ── Round-2 #2: PyPI sibling-artifact addition is NOT a same-version republish ─

test('checkIntegrity: a different artifact URL at the same version is NOT a package-changed rug pull', () => {
  const wheel: PackageMeta = {
    registry: 'pypi',
    name: 'pkg',
    version: '1.0.0',
    tarballUrl: 'https://files.pythonhosted.org/packages/aa/pkg-1.0.0-py3-none-any.whl',
    tarballSha256: 'a'.repeat(64),
  };
  const lock = pinSurface(emptyLockfile(), makeSurface({ id: 'pkg', packageMeta: wheel }));
  // Later the maintainer uploads the sdist for 1.0.0 (wheel bytes unchanged).
  const sdist: PackageMeta = {
    registry: 'pypi',
    name: 'pkg',
    version: '1.0.0',
    tarballUrl: 'https://files.pythonhosted.org/packages/bb/pkg-1.0.0.tar.gz',
    tarballSha256: 'b'.repeat(64),
  };
  const res = checkIntegrity(makeSurface({ id: 'pkg', packageMeta: sdist }), lock);
  assert.equal(res.status, 'unchanged', 'a newly-added sibling artifact must not read as a republish');
});

test('checkIntegrity: SAME artifact URL with different bytes IS a republish (npm re-publish)', () => {
  const v1: PackageMeta = {
    registry: 'npm',
    name: 'pkg',
    version: '1.0.0',
    tarballUrl: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz',
    tarballSha256: 'a'.repeat(64),
  };
  const lock = pinSurface(emptyLockfile(), makeSurface({ id: 'pkg', packageMeta: v1 }));
  const republished = { ...v1, tarballSha256: 'c'.repeat(64) };
  const res = checkIntegrity(makeSurface({ id: 'pkg', packageMeta: republished }), lock);
  assert.equal(res.status, 'drift');
  assert.ok(res.changes?.some((ch) => ch.kind === 'package-changed'));
});

// ── Round-2 #3/#5: offline re-pin must not drop the byte pin ──────────────────

test('pinSurface: a truly-offline re-pin (no observed version) preserves the byte pin', () => {
  const online = makeSurface({
    id: 'foo',
    packageMeta: { registry: 'npm', name: 'foo', version: '1.2.3', tarballUrl: 'https://registry.npmjs.org/foo/-/foo-1.2.3.tgz', tarballSha256: 'a'.repeat(64) },
  });
  const lock = pinSurface(emptyLockfile(), online);
  // Offline re-pin: metaFor returns { registry, name } with NO version.
  const offline = makeSurface({ id: 'foo', packageMeta: { registry: 'npm', name: 'foo' } });
  const relock = pinSurface(lock, offline);
  assert.equal(relock.servers['foo']!.tarballSha256, 'a'.repeat(64), 'byte pin survived a networkless re-pin');
  assert.equal(relock.servers['foo']!.packageVersion, '1.2.3');
  assert.equal(relock.servers['foo']!.tarballUrl, 'https://registry.npmjs.org/foo/-/foo-1.2.3.tgz');
});

test('pinSurface: an online re-pin of a NEW version replaces the byte pin (no stale carry-forward)', () => {
  const v1 = makeSurface({ id: 'foo', packageMeta: { registry: 'npm', name: 'foo', version: '1.0.0', tarballSha256: 'a'.repeat(64) } });
  const lock = pinSurface(emptyLockfile(), v1);
  const v2 = makeSurface({ id: 'foo', packageMeta: { registry: 'npm', name: 'foo', version: '2.0.0', tarballSha256: 'b'.repeat(64) } });
  const relock = pinSurface(lock, v2);
  assert.equal(relock.servers['foo']!.packageVersion, '2.0.0');
  assert.equal(relock.servers['foo']!.tarballSha256, 'b'.repeat(64));
});

test('pinSurface: an online re-pin of a KNOWN-DIFFERENT version during a failed fetch does NOT keep the old pin', () => {
  const v1 = makeSurface({ id: 'foo', packageMeta: { registry: 'npm', name: 'foo', version: '1.0.0', tarballSha256: 'a'.repeat(64) } });
  const lock = pinSurface(emptyLockfile(), v1);
  // Online, version observed as 2.0.0, but the download failed (no hash): the
  // 1.0.0 pin no longer applies to the 2.0.0 the config now resolves.
  const v2Failed = makeSurface({ id: 'foo', packageMeta: { registry: 'npm', name: 'foo', version: '2.0.0', artifactError: { kind: 'network', detail: 'x' } } });
  const relock = pinSurface(lock, v2Failed);
  assert.equal(relock.servers['foo']!.tarballSha256, undefined, 'a different observed version must not inherit the old byte pin');
});

// ── Round-3 #1 (HIGH): a forged tarball URL must NOT suppress npm rug-pull ────

test('checkIntegrity: npm compares by version only — a changed URL cannot dodge MTC-TOFU-002', () => {
  const v1: PackageMeta = {
    registry: 'npm',
    name: 'foo',
    version: '1.0.0',
    tarballUrl: 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz',
    tarballSha256: 'a'.repeat(64),
  };
  const lock = pinSurface(emptyLockfile(), makeSurface({ id: 'foo', packageMeta: v1 }));
  // Attacker-controlled registry response: same version, DIFFERENT url string
  // (?rev=2) and malicious bytes with a matching (attacker-set) integrity.
  const forged: PackageMeta = {
    registry: 'npm',
    name: 'foo',
    version: '1.0.0',
    tarballUrl: 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz?rev=2',
    tarballSha256: 'd'.repeat(64),
  };
  const res = checkIntegrity(makeSurface({ id: 'foo', packageMeta: forged }), lock);
  assert.equal(res.status, 'drift', 'npm rug-pull must fire regardless of the URL string');
  assert.ok(res.changes?.some((ch) => ch.kind === 'package-changed'));
});

test('checkIntegrity: PyPI same-FILE different-bytes still fires (query stripped for identity)', () => {
  const pin: PackageMeta = {
    registry: 'pypi',
    name: 'p',
    version: '1.0.0',
    tarballUrl: 'https://files.pythonhosted.org/packages/aa/p-1.0.0.tar.gz',
    tarballSha256: 'a'.repeat(64),
  };
  const lock = pinSurface(emptyLockfile(), makeSurface({ id: 'p', packageMeta: pin }));
  const sameFileNewBytes: PackageMeta = {
    registry: 'pypi',
    name: 'p',
    version: '1.0.0',
    tarballUrl: 'https://files.pythonhosted.org/packages/aa/p-1.0.0.tar.gz?x=1',
    tarballSha256: 'e'.repeat(64),
  };
  const res = checkIntegrity(makeSurface({ id: 'p', packageMeta: sameFileNewBytes }), lock);
  assert.equal(res.status, 'drift', 'same PyPI file name with different bytes is a republish');
});

// ── Round-4 (MEDIUM): a missing pinned version must not silently become latest ─

test('fetchNpmMeta: a pinned version the registry drops is flagged, NOT substituted with latest', async () => {
  const { fetchNpmMeta } = await import('../src/acquire/npm.js');
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    if (href.includes('registry.npmjs.org')) {
      // Attacker drops 1.0.0 and points latest at a malicious 2.0.0.
      return new Response(
        JSON.stringify({
          'dist-tags': { latest: '2.0.0' },
          versions: { '2.0.0': { dist: { tarball: 'https://registry.npmjs.org/p/-/p-2.0.0.tgz', integrity: 'sha512-x' } } },
        }),
        { status: 200 },
      );
    }
    return new Response('null', { status: 404 });
  }) as unknown as typeof fetch;
  try {
    const meta = await fetchNpmMeta('p', '1.0.0');
    assert.equal(meta.version, '1.0.0', 'keeps the requested version, does not jump to latest');
    assert.equal(meta.requestedVersionMissing, true);
    assert.equal(meta.tarballUrl, undefined, 'no artifact resolved for a version that is not published');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('fetchNpmMeta: a hostile non-object `versions` fails closed, does not throw (D1)', async () => {
  const { fetchNpmMeta } = await import('../src/acquire/npm.js');
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ 'dist-tags': { latest: '9.9.9' }, versions: 'not-an-object' }), { status: 200 })) as unknown as typeof fetch;
  try {
    const meta = await fetchNpmMeta('p', '1.0.0');
    assert.equal(meta.version, '1.0.0');
    assert.equal(meta.requestedVersionMissing, true, 'a non-object version map fails closed as missing');
    assert.equal(meta.tarballUrl, undefined);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('fetchNpmMeta: an attacker-typed dist-tag never yields a non-string version (TOFU-002 evasion source-fix)', async () => {
  // The real fix is at the source: if dist-tags.latest is an array/object, it is
  // ignored (not cast to a string), and the version falls back to a real string
  // key. A non-string meta.version would round-trip into the lockfile and defeat
  // the `meta.version === entry.packageVersion` byte-pin comparison.
  const { fetchNpmMeta } = await import('../src/acquire/npm.js');
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    if (href.includes('registry.npmjs.org')) {
      return new Response(
        JSON.stringify({
          'dist-tags': { latest: ['9.9.9'] }, // hostile: array, not a string
          versions: { '9.9.9': { dist: { tarball: 'https://registry.npmjs.org/p/-/p-9.9.9.tgz', integrity: 'sha512-x' } } },
        }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ downloads: 0 }), { status: 200 });
  }) as unknown as typeof fetch;
  try {
    const meta = await fetchNpmMeta('p'); // unpinned/latest path
    assert.equal(typeof meta.version, 'string', 'version must be a string even when dist-tags.latest is hostile');
    assert.equal(meta.version, '9.9.9');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('checkIntegrity/entryFor: a non-string version is never stored as a pin (defense-in-depth)', () => {
  const bad = makeSurface({
    id: 'p',
    packageMeta: { registry: 'npm', name: 'p', version: ['1.0.0'] as unknown as string, tarballUrl: 'https://registry.npmjs.org/p/-/p-1.0.0.tgz', tarballSha256: 'a'.repeat(64) },
  });
  const e = entryFor(bad);
  assert.equal(e.packageVersion, undefined, 'a non-string version must not be pinned');
  assert.equal(e.tarballSha256, undefined);
});

test('fetchPypiMeta: an exact pin is labelled with the REQUESTED version, not the response (D2)', async () => {
  const { fetchPypiMeta } = await import('../src/acquire/npm.js');
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    // Hostile: the version endpoint for 1.0.0 claims to be 9.9.9.
    new Response(JSON.stringify({ info: { version: '9.9.9', license: 'MIT' }, urls: [] }), { status: 200 })) as unknown as typeof fetch;
  try {
    const meta = await fetchPypiMeta('p', '1.0.0');
    assert.equal(meta.version, '1.0.0', 'an attacker-controlled info.version cannot relabel a pinned exact version');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('a missing pinned version raises MTC-SUP-015 (not a silent clean scan)', async () => {
  const { scanSurface } = await import('../src/engine.js');
  const surface = makeSurface({
    id: 'p',
    source: { kind: 'package', origin: 'p' },
    packageMeta: { registry: 'npm', name: 'p', version: '1.0.0', requestedSpec: '1.0.0', requestedVersionMissing: true },
  });
  const report = await scanSurface(surface);
  const f = report.findings.find((x) => x.ruleId === 'MTC-SUP-015');
  assert.ok(f, 'MTC-SUP-015 must fire for a missing pinned version');
  assert.equal(f!.severity, 'medium');
});

// ── Round-3 #2 (LOW): scoped-shaped file paths route as paths, not packages ───

test('resolveTargets: a non-existent @scope/name.tgz is a missing file, not a package', async () => {
  await assert.rejects(resolveTargets('@myorg/server-1.0.0.tgz', {}), /No such file/);
  await assert.rejects(resolveTargets('@a/b.whl', {}), /No such file/);
  await assert.rejects(resolveTargets('@x/y.json', {}), /No such file/);
});

test('entryFor: records the artifact URL alongside the hash', () => {
  const e = entryFor(makeSurface({ packageMeta: { registry: 'npm', name: 'p', version: '1.0.0', tarballUrl: 'https://registry.npmjs.org/p/-/p-1.0.0.tgz', tarballSha256: 'a'.repeat(64) } }));
  assert.equal(e.tarballUrl, 'https://registry.npmjs.org/p/-/p-1.0.0.tgz');
  assert.equal(e.tarballSha256, 'a'.repeat(64));
});
