import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync, deflateRawSync } from 'node:zlib';
import { downloadCapped, fetchPackageSource, PackageSourceError } from '../src/acquire/packageSource.js';
import { extractZip, extractTar, type ArchiveLimits } from '../src/acquire/archive.js';
import type { PackageMeta } from '../src/types.js';

const LIMITS: ArchiveLimits = { maxFiles: 400, maxFileBytes: 512 * 1024, maxTotalBytes: 12 * 1024 * 1024 };

// ── #1: zip decompression-work accounting (bomb of discarded over-cap entries) ──

test('extractZip: bounds total decompression WORK, not just stored output (zip-bomb accounting)', () => {
  // One 600 KB (> 512 KB cap) deflate stream, referenced by many CD entries that
  // all declare uncompSize=0. Pre-fix these were discarded without charging the
  // caps, allowing ~unbounded inflate work. Now `total` charges each attempt.
  const raw = Buffer.alloc(600 * 1024); // inflates past maxFileBytes
  const comp = deflateRawSync(raw);
  const name = Buffer.from('x.js');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(comp.length, 18);
  local.writeUInt32LE(0, 22); // lie: uncompSize = 0
  local.writeUInt16LE(name.length, 26);
  const localBlock = Buffer.concat([local, name, comp]);

  const count = 60000;
  const centrals: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(8, 10);
    c.writeUInt32LE(comp.length, 20);
    c.writeUInt32LE(0, 24); // declared uncompSize = 0 → passes the cheap guard
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(0, 42); // all point at the one shared local header
    centrals.push(Buffer.concat([c, name]));
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(count & 0xffff, 8);
  eocd.writeUInt16LE(count & 0xffff, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(localBlock.length, 16);
  const zip = Buffer.concat([localBlock, cd, eocd]);

  const started = process.hrtime.bigint();
  const out = extractZip(zip, () => true, LIMITS);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(out.length, 0, 'nothing extracted (all entries are over-cap)');
  // The 12 MB total budget caps the work: ~24 discarded 512 KB inflates then stop,
  // NOT 60000. This must finish fast, not churn tens of GB.
  assert.ok(elapsedMs < 2000, `extraction must stay bounded; took ${elapsedMs.toFixed(0)}ms`);
});

// ── #8/#9: oversized tar metadata blocks (pax / GNU longname) capped ──────────

function tarHeaderBlock(name: string, size: number, type: string): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(type, 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

function tarEntryTyped(name: string, body: Buffer, type: string): Buffer {
  const padded = Buffer.alloc(Math.ceil(body.length / 512) * 512);
  body.copy(padded);
  return Buffer.concat([tarHeaderBlock(name, body.length, type), padded]);
}

test('extractTar: an oversized GNU longname block is ignored, not materialized', () => {
  // A 5 MB longname body (> 512 KB maxFileBytes). Pre-fix it was sliced+toString+
  // regex-scanned in full; now it is skipped and the following real file still reads.
  const huge = Buffer.alloc(5 * 1024 * 1024, 0x41);
  const tar = Buffer.concat([
    tarEntryTyped('././@LongLink', huge, 'L'),
    tarEntryTyped('package/ok.js', Buffer.from('console.log(1)'), '0'),
    Buffer.alloc(1024),
  ]);
  const out = extractTar(tar, () => true, LIMITS);
  // The longname was over-cap → ignored → the real entry keeps its own header name.
  assert.deepEqual(out.map((e) => e.path), ['package/ok.js']);
});

test('extractTar: an oversized pax header body is ignored (no giant key map built)', () => {
  const huge = Buffer.alloc(5 * 1024 * 1024, 0x41);
  const tar = Buffer.concat([
    tarEntryTyped('PaxHeader/x', huge, 'x'),
    tarEntryTyped('package/ok.js', Buffer.from('x'), '0'),
    Buffer.alloc(1024),
  ]);
  const out = extractTar(tar, () => true, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['package/ok.js']);
});

// ── #3: download must not follow redirects off the allowlisted host ───────────

test('downloadCapped: refuses a redirect to an unvalidated host (SSRF guard)', async () => {
  const fetchStub = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : input.href;
    if (href.includes('registry.npmjs.org')) {
      return new Response(null, { status: 302, headers: { location: 'https://evil.example/steal.tgz' } });
    }
    return new Response(new Uint8Array([1, 2, 3]), { status: 200 });
  }) as unknown as typeof fetch;

  await assert.rejects(
    downloadCapped(new URL('https://registry.npmjs.org/x/-/x-1.0.0.tgz'), 'npm', fetchStub),
    (err: unknown) => err instanceof PackageSourceError && err.kind === 'untrusted-redirect',
  );
});

test('downloadCapped: a same-host redirect is followed and its body returned', async () => {
  let hops = 0;
  const body = Buffer.from('final-bytes');
  const fetchStub = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : input.href;
    if (href.endsWith('/a.tgz') && hops++ === 0) {
      return new Response(null, {
        status: 302,
        headers: { location: 'https://registry.npmjs.org/x/-/b.tgz' },
      });
    }
    return new Response(new Uint8Array(body), { status: 200 });
  }) as unknown as typeof fetch;

  const buf = await downloadCapped(new URL('https://registry.npmjs.org/x/-/a.tgz'), 'npm', fetchStub);
  assert.equal(buf.toString(), 'final-bytes');
});

// ── #11: the streaming download caps (memory-exhaustion defense) ──────────────

test('downloadCapped: rejects a lying oversized Content-Length', async () => {
  const fetchStub = (async () =>
    new Response(new Uint8Array([1]), {
      status: 200,
      headers: { 'content-length': String(60 * 1024 * 1024) },
    })) as unknown as typeof fetch;
  await assert.rejects(
    downloadCapped(new URL('https://registry.npmjs.org/x.tgz'), 'npm', fetchStub),
    /safety cap/,
  );
});

test('downloadCapped: aborts a body that streams past the cap with no Content-Length', async () => {
  const chunk = new Uint8Array(1024 * 1024); // 1 MB per pull
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(chunk); // never closes → would be unbounded without the cap
    },
  });
  const fetchStub = (async () => new Response(stream, { status: 200 })) as unknown as typeof fetch;
  await assert.rejects(
    downloadCapped(new URL('https://registry.npmjs.org/x.tgz'), 'npm', fetchStub),
    /download cap/,
  );
});

test('downloadCapped: an HTTP error is a network-kind failure', async () => {
  const fetchStub = (async () => new Response(null, { status: 503 })) as unknown as typeof fetch;
  await assert.rejects(
    downloadCapped(new URL('https://registry.npmjs.org/x.tgz'), 'npm', fetchStub),
    (err: unknown) => err instanceof PackageSourceError && err.kind === 'network',
  );
});

// ── fetchPackageSource surfaces the right error KIND ──────────────────────────

function makeNpmTarball(): Buffer {
  const tarEntry = (name: string, content: string): Buffer => tarEntryTyped(name, Buffer.from(content), '0');
  return gzipSync(Buffer.concat([tarEntry('package/index.js', 'eval(x)'), Buffer.alloc(1024)]));
}

test('fetchPackageSource: integrity mismatch surfaces kind="integrity"', async () => {
  const tarball = makeNpmTarball();
  const meta: PackageMeta = {
    registry: 'npm',
    name: 'p',
    version: '1.0.0',
    tarballUrl: 'https://registry.npmjs.org/p/-/p-1.0.0.tgz',
    tarballIntegrity: `sha512-${createHash('sha512').update('DIFFERENT').digest('base64')}`,
  };
  const serve = (async () =>
    new Response(new Uint8Array(tarball), { status: 200 })) as unknown as typeof fetch;
  await assert.rejects(
    fetchPackageSource(meta, serve),
    (err: unknown) => err instanceof PackageSourceError && err.kind === 'integrity',
  );
});
