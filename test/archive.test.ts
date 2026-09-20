import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync, deflateRawSync } from 'node:zlib';
import {
  extractTar,
  extractZip,
  extractArchive,
  detectArchiveKind,
  gunzipBounded,
  safeEntryPath,
  stripCommonRoot,
  type ArchiveLimits,
} from '../src/acquire/archive.js';

const LIMITS: ArchiveLimits = { maxFiles: 100, maxFileBytes: 64 * 1024, maxTotalBytes: 512 * 1024 };
const all = (): boolean => true;

// ── in-memory ustar builder ─────────────────────────────────────────────────

function tarHeader(name: string, size: number, type = '0', prefix = ''): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100); // mode
  h.write('0000000\0', 108); // uid
  h.write('0000000\0', 116); // gid
  h.write(size.toString(8).padStart(11, '0') + '\0', 124); // size
  h.write('00000000000\0', 136); // mtime
  h.write('        ', 148); // checksum placeholder (spaces while summing)
  h.write(type, 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  if (prefix) h.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

function tarEntry(name: string, content: string | Buffer, type = '0', prefix = ''): Buffer {
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([tarHeader(name, data.length, type, prefix), padded]);
}

function makeTar(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.alloc(1024)]); // two zero blocks = end
}

// ── in-memory zip builder ───────────────────────────────────────────────────

interface ZipSpec {
  name: string;
  content: string;
  method?: 0 | 8;
  flags?: number;
}

function makeZip(specs: ZipSpec[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const s of specs) {
    const raw = Buffer.from(s.content, 'utf8');
    const method = s.method ?? 8;
    const comp = method === 8 ? deflateRawSync(raw) : raw;
    const nameBuf = Buffer.from(s.name, 'utf8');

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(s.flags ?? 0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(Buffer.concat([local, nameBuf, comp]));

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(s.flags ?? 0, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(comp.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(Buffer.concat([central, nameBuf]));

    offset += 30 + nameBuf.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(specs.length, 8);
  eocd.writeUInt16LE(specs.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

// ── tar ─────────────────────────────────────────────────────────────────────

test('extractTar: reads regular files, skips directories', () => {
  const tar = makeTar(
    tarEntry('package/', '', '5'),
    tarEntry('package/index.js', 'console.log(1)'),
    tarEntry('package/lib/util.js', 'export {}'),
  );
  const out = extractTar(tar, all, LIMITS);
  assert.deepEqual(
    out.map((e) => e.path),
    ['package/index.js', 'package/lib/util.js'],
  );
  assert.equal(out[0]!.data.toString(), 'console.log(1)');
});

test('extractTar: ustar prefix field builds the full path', () => {
  const tar = makeTar(tarEntry('index.js', 'x = 1', '0', 'package/deep'));
  const out = extractTar(tar, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['package/deep/index.js']);
});

test('extractTar: GNU longname (type L) overrides the next entry name', () => {
  const longName = 'package/' + 'a'.repeat(120) + '.js';
  const tar = makeTar(tarEntry('././@LongLink', longName, 'L'), tarEntry('truncated.js', 'x'));
  const out = extractTar(tar, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), [longName]);
});

test('extractTar: pax extended header path overrides the next entry name', () => {
  const paxPath = 'package/pax-named.py';
  const record = `path=${paxPath}\n`;
  const body = `${record.length + String(record.length + 3).length + 1} ${record}`;
  const tar = makeTar(tarEntry('PaxHeader/x', body, 'x'), tarEntry('short.py', 'print(1)'));
  const out = extractTar(tar, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), [paxPath]);
});

test('extractTar: rejects path traversal and absolute-drive entries', () => {
  const tar = makeTar(
    tarEntry('../../../etc/evil.js', 'x'),
    tarEntry('package/ok.js', 'fine'),
  );
  const out = extractTar(tar, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['package/ok.js']);
});

test('extractTar: per-file and total caps hold', () => {
  const big = 'A'.repeat(LIMITS.maxFileBytes + 1);
  const tar = makeTar(tarEntry('package/too-big.js', big), tarEntry('package/ok.js', 'ok'));
  const out = extractTar(tar, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['package/ok.js']);

  const tight: ArchiveLimits = { maxFiles: 2, maxFileBytes: 1024, maxTotalBytes: 1024 };
  const tar2 = makeTar(tarEntry('a.js', 'B'.repeat(600)), tarEntry('b.js', 'C'.repeat(600)));
  const out2 = extractTar(tar2, all, tight);
  assert.equal(out2.length, 1, 'total-bytes cap stops extraction');
});

test('extractTar: stops on a malformed size field instead of guessing offsets', () => {
  const good = tarEntry('ok.js', 'x');
  const bad = tarEntry('bad.js', 'y');
  bad.write('zzzzzzzzzzz\0', 124); // garbage size
  const out = extractTar(makeTar(good, bad, tarEntry('after.js', 'z')), all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['ok.js']);
});

// ── zip ─────────────────────────────────────────────────────────────────────

test('extractZip: reads stored and deflated entries', () => {
  const zip = makeZip([
    { name: 'pkg/mod.py', content: 'import os', method: 8 },
    { name: 'pkg/plain.py', content: 'x = 1', method: 0 },
  ]);
  const out = extractZip(zip, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['pkg/mod.py', 'pkg/plain.py']);
  assert.equal(out[0]!.data.toString(), 'import os');
  assert.equal(out[1]!.data.toString(), 'x = 1');
});

test('extractZip: skips encrypted entries and directories', () => {
  const zip = makeZip([
    { name: 'secret.py', content: 'hidden', flags: 0x1 },
    { name: 'dir/', content: '' },
    { name: 'open.py', content: 'visible' },
  ]);
  const out = extractZip(zip, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['open.py']);
});

test('extractZip: rejects zip-slip paths', () => {
  const zip = makeZip([
    { name: '../../evil.py', content: 'bad' },
    { name: 'ok.py', content: 'good' },
  ]);
  const out = extractZip(zip, all, LIMITS);
  assert.deepEqual(out.map((e) => e.path), ['ok.py']);
});

test('extractZip: non-zip buffer throws a clear error', () => {
  assert.throws(() => extractZip(Buffer.from('not a zip at all, definitely'), all, LIMITS), /end-of-central-directory/);
});

// ── sniffing / gzip / helpers ───────────────────────────────────────────────

test('detectArchiveKind: magic bytes win over the name hint', () => {
  const tgz = gzipSync(makeTar(tarEntry('a.js', 'x')));
  assert.equal(detectArchiveKind(tgz, 'weird.zip'), 'tgz');
  assert.equal(detectArchiveKind(makeZip([{ name: 'a.py', content: 'x' }]), 'pkg.whl'), 'zip');
  assert.equal(detectArchiveKind(makeTar(tarEntry('a.js', 'x')), 'pkg.tar'), 'tar');
});

test('extractArchive: gunzips a .tgz end-to-end', () => {
  const tgz = gzipSync(makeTar(tarEntry('package/index.js', 'module.exports = 1')));
  const out = extractArchive(tgz, 'pkg.tgz', all, LIMITS);
  assert.equal(out[0]!.data.toString(), 'module.exports = 1');
});

test('gunzipBounded: enforces the decompressed-size cap (gzip bomb)', () => {
  const bomb = gzipSync(Buffer.alloc(4 * 1024 * 1024));
  assert.throws(() => gunzipBounded(bomb, 1024 * 1024), /safety cap/);
});

test('safeEntryPath: normalizes and rejects hostile paths', () => {
  assert.equal(safeEntryPath('package/./lib//a.js'), 'package/lib/a.js');
  assert.equal(safeEntryPath('/etc/passwd'), 'etc/passwd');
  assert.equal(safeEntryPath('a/../../b.js'), null);
  assert.equal(safeEntryPath('C:/windows/evil.js'), null);
  assert.equal(safeEntryPath('has\0nul.js'), null);
});

test('stripCommonRoot: strips a single shared root, leaves multi-root archives alone', () => {
  const single = [
    { path: 'package/index.js', data: Buffer.from('a') },
    { path: 'package/lib/b.js', data: Buffer.from('b') },
  ];
  assert.deepEqual(stripCommonRoot(single).map((e) => e.path), ['index.js', 'lib/b.js']);

  const wheel = [
    { path: 'pkg/mod.py', data: Buffer.from('a') },
    { path: 'pkg-1.0.dist-info/METADATA', data: Buffer.from('b') },
  ];
  assert.deepEqual(stripCommonRoot(wheel).map((e) => e.path), ['pkg/mod.py', 'pkg-1.0.dist-info/METADATA']);

  const flat = [{ path: 'index.js', data: Buffer.from('a') }];
  assert.deepEqual(stripCommonRoot(flat).map((e) => e.path), ['index.js']);
});
