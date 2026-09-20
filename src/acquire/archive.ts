/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Dependency-free, in-memory archive readers (ustar/pax tar, gzip, zip) so the
 * scanner can read the *published bytes* of a package — npm tarballs, PyPI
 * sdists and wheels, packed release artifacts — without ever writing them to
 * disk or executing anything. Every reader is bounded (entry count, per-file
 * size, total size, decompressed size) so a hostile archive (zip bomb, header
 * spoofing, path traversal) can degrade a scan, not the machine running it.
 */

import { gunzipSync, inflateRawSync } from 'node:zlib';

export interface ArchiveEntry {
  /** Normalized relative path inside the archive (always `/`-separated). */
  path: string;
  data: Buffer;
}

export interface ArchiveLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
}

/** Decompressed-archive safety cap: a .tgz may not inflate past this. */
export const MAX_UNPACKED_BYTES = 200 * 1024 * 1024; // 200 MB

const TAR_BLOCK = 512;

/**
 * Normalize an archive member path and reject anything that could mislead a
 * report or (defense-in-depth) escape a directory: `..` segments, drive
 * letters, NUL bytes. Absolute paths are made relative — entries are only ever
 * held in memory, the path just labels evidence.
 */
export function safeEntryPath(raw: string): string | null {
  const norm = raw.replace(/\\/g, '/');
  if (!norm || norm.includes('\0')) return null;
  const parts = norm.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.length === 0) return null;
  if (parts.some((p) => p === '..')) return null;
  if (/^[a-zA-Z]:$/.test(parts[0]!)) return null;
  return parts.join('/');
}

/** Gunzip with a hard output cap so a gzip bomb can't exhaust memory. */
export function gunzipBounded(buf: Buffer, maxBytes = MAX_UNPACKED_BYTES): Buffer {
  try {
    return gunzipSync(buf, { maxOutputLength: maxBytes });
  } catch (err) {
    throw new Error(
      `Failed to decompress gzip data (corrupt, or larger than the ${Math.round(maxBytes / 1024 / 1024)} MB safety cap): ${(err as Error).message}`,
    );
  }
}

/** Octal (or GNU base-256) numeric field from a tar header. NaN on garbage. */
function tarNumber(header: Buffer, off: number, len: number): number {
  if (header[off]! & 0x80) {
    // GNU base-256 for values that don't fit in octal.
    let v = header[off]! & 0x7f;
    for (let i = 1; i < len; i++) v = v * 256 + header[off + i]!;
    return v;
  }
  const s = header.toString('ascii', off, off + len).replace(/\0[\s\S]*$/, '').trim();
  if (!s) return 0;
  const v = parseInt(s, 8);
  return Number.isFinite(v) ? v : NaN;
}

function tarString(header: Buffer, off: number, len: number): string {
  return header.toString('utf8', off, off + len).replace(/\0[\s\S]*$/, '');
}

/**
 * Only these pax keys can override an entry's path — the rest are irrelevant to
 * source extraction, so we never build a map of attacker-chosen keys (a hostile
 * header can otherwise carry millions of distinct keys; see MAX_PAX_RECORDS).
 */
const PAX_WANTED_KEYS = new Set(['path', 'linkpath']);
/** Hard cap on records parsed from one pax header (defense-in-depth vs. key-flooding). */
const MAX_PAX_RECORDS = 4096;

/** Parse the pax keys we care about from a header body: `"<len> <key>=<value>\n"`. */
function parsePax(body: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let off = 0;
  let records = 0;
  while (off < body.length && records < MAX_PAX_RECORDS) {
    const sp = body.indexOf(0x20, off);
    if (sp < 0) break;
    const len = parseInt(body.toString('ascii', off, sp), 10);
    if (!Number.isFinite(len) || len <= 0 || off + len > body.length) break;
    records++;
    const eq = body.indexOf(0x3d, sp + 1); // '='
    if (eq > 0 && eq < off + len) {
      const key = body.toString('utf8', sp + 1, eq);
      // Only materialize values for keys that can affect extraction.
      if (PAX_WANTED_KEYS.has(key)) out[key] = body.toString('utf8', eq + 1, off + len).replace(/\n$/, '');
    }
    off += len;
  }
  return out;
}

/**
 * Read regular files out of a (already-decompressed) ustar/pax tar buffer.
 * Handles POSIX prefix fields, pax `path` overrides and GNU longnames; skips
 * directories, links and device nodes; stops on the first malformed header
 * rather than guessing at offsets.
 */
export function extractTar(tar: Buffer, wanted: (path: string) => boolean, limits: ArchiveLimits): ArchiveEntry[] {
  const out: ArchiveEntry[] = [];
  let total = 0;
  let off = 0;
  let gnuLongName: string | undefined;
  let paxPath: string | undefined;

  while (off + TAR_BLOCK <= tar.length) {
    const header = tar.subarray(off, off + TAR_BLOCK);
    if (header.every((b) => b === 0)) break; // end-of-archive marker
    const size = tarNumber(header, 124, 12);
    if (!Number.isFinite(size) || size < 0 || off + TAR_BLOCK + size > tar.length) break;
    const dataStart = off + TAR_BLOCK;
    const next = dataStart + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
    const type = String.fromCharCode(header[156]!);

    // A metadata block (GNU longname / pax header) precedes a real entry and is
    // discarded after one use. Its `size` is bounded only by the archive length,
    // so a hostile ~190 MB longname/pax body would be materialized OUTSIDE the
    // per-file cap — cap it here (a legitimate path/header is far under 512 KB).
    if (type === 'L' || type === 'K') {
      // GNU longname/longlink: the data block holds the NEXT entry's path.
      if (size <= limits.maxFileBytes && type === 'L') {
        gnuLongName = tar.subarray(dataStart, dataStart + size).toString('utf8').replace(/\0[\s\S]*$/, '');
      }
      off = next;
      continue;
    }
    if (type === 'x' || type === 'g') {
      // pax extended header ('g' is global — applied conservatively to the next entry only).
      if (size <= limits.maxFileBytes) {
        const pax = parsePax(tar.subarray(dataStart, dataStart + size));
        if (type === 'x' && pax.path) paxPath = pax.path;
      }
      off = next;
      continue;
    }

    let name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    if (prefix) name = `${prefix}/${name}`;
    if (gnuLongName) name = gnuLongName;
    if (paxPath) name = paxPath; // pax path wins over both
    gnuLongName = undefined;
    paxPath = undefined;

    // '0' and NUL are regular files; everything else (dirs, links, devices) is skipped.
    if (type === '0' || type === '\0') {
      const path = safeEntryPath(name);
      if (path && size <= limits.maxFileBytes && wanted(path)) {
        if (out.length >= limits.maxFiles || total + size > limits.maxTotalBytes) return out;
        out.push({ path, data: Buffer.from(tar.subarray(dataStart, dataStart + size)) });
        total += size;
      }
    }
    off = next;
  }
  return out;
}

const ZIP_EOCD_SIG = 0x06054b50;
const ZIP_CDIR_SIG = 0x02014b50;
const ZIP_LOCAL_SIG = 0x04034b50;

function findEocd(zip: Buffer): number {
  const floor = Math.max(0, zip.length - 22 - 65535);
  for (let i = zip.length - 22; i >= floor; i--) {
    if (zip.readUInt32LE(i) === ZIP_EOCD_SIG) return i;
  }
  return -1;
}

/**
 * Read regular files out of a zip buffer (PyPI wheels, .zip sdists, .mcpb-style
 * bundles) via the central directory. Supports stored and deflate entries;
 * skips encrypted entries and directories; zip64 archives are rejected (a
 * package artifact has no business being >4 GB).
 */
export function extractZip(zip: Buffer, wanted: (path: string) => boolean, limits: ArchiveLimits): ArchiveEntry[] {
  const eocd = findEocd(zip);
  if (eocd < 0) throw new Error('Not a zip archive (no end-of-central-directory record).');
  const count = zip.readUInt16LE(eocd + 10);
  const cdOffset = zip.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff) throw new Error('zip64 archives are not supported.');

  const out: ArchiveEntry[] = [];
  // Three independent budgets bound a hostile zip's work:
  //  • `total`         — decompression OUTPUT (charged even for a discarded
  //                      over-cap inflate), so an output-bomb can't bypass it;
  //  • `inflatedBytes` — compressed INPUT actually fed to zlib, so a stream that
  //                      inflates to ~0 output (empty stored blocks) but reads a
  //                      huge compressed region still hits a ceiling — the input
  //                      work amplified by many CD entries pointing at one blob;
  //  • `seen` offsets  — a physical stream is inflated AT MOST ONCE, so N central-
  //                      directory entries aliasing one local header do N× nothing.
  // `processed` additionally bounds the entry count. Any single guard tripping
  // stops extraction, so worst-case CPU is bounded regardless of archive shape.
  let total = 0;
  let inflatedBytes = 0;
  let processed = 0;
  const seen = new Set<number>();
  let p = cdOffset;
  for (let i = 0; i < count && p + 46 <= zip.length; i++) {
    if (zip.readUInt32LE(p) !== ZIP_CDIR_SIG) break;
    const flags = zip.readUInt16LE(p + 8);
    const method = zip.readUInt16LE(p + 10);
    const compSize = zip.readUInt32LE(p + 20);
    const uncompSize = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const localOff = zip.readUInt32LE(p + 42);
    const rawName = zip.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    if (flags & 0x0041) continue; // encrypted (bit 0) / strong encryption (bit 6)
    if (rawName.endsWith('/')) continue; // directory
    const path = safeEntryPath(rawName);
    // Cheap rejections (bad path, declared over-cap, unwanted, over-budget
    // compressed size, or an already-inflated stream) cost no decompression.
    if (!path || uncompSize > limits.maxFileBytes || !wanted(path)) continue;
    if (compSize > limits.maxTotalBytes || seen.has(localOff)) continue;
    // Stop before any more work once ANY budget is spent.
    if (processed >= limits.maxFiles || total >= limits.maxTotalBytes || inflatedBytes >= limits.maxTotalBytes) break;

    // Local header re-read: its name/extra lengths can differ from the central directory's.
    if (localOff + 30 > zip.length || zip.readUInt32LE(localOff) !== ZIP_LOCAL_SIG) continue;
    const lNameLen = zip.readUInt16LE(localOff + 26);
    const lExtraLen = zip.readUInt16LE(localOff + 28);
    const dataOff = localOff + 30 + lNameLen + lExtraLen;
    if (dataOff + compSize > zip.length) continue;
    const comp = zip.subarray(dataOff, dataOff + compSize);

    // Bound each inflate by the smaller of the per-file cap and the remaining
    // output budget; charge both the output produced and the input consumed.
    seen.add(localOff);
    processed++;
    inflatedBytes += compSize;
    const budget = Math.min(limits.maxFileBytes, limits.maxTotalBytes - total);
    let data: Buffer;
    if (method === 0) {
      if (compSize !== uncompSize || uncompSize > budget) {
        total += Math.min(compSize, budget);
        continue;
      }
      data = Buffer.from(comp);
    } else if (method === 8) {
      try {
        data = inflateRawSync(comp, { maxOutputLength: budget });
      } catch {
        total += budget; // over-cap or corrupt: charge the bounded work we just did
        continue;
      }
    } else {
      continue; // unsupported compression method — no work done
    }
    if (data.length > limits.maxFileBytes) {
      total += data.length;
      continue;
    }
    out.push({ path, data });
    total += data.length;
  }
  return out;
}

export type ArchiveKind = 'tar' | 'tgz' | 'zip';

/** Sniff the archive container by magic bytes, falling back to the file name. */
export function detectArchiveKind(buf: Buffer, nameHint = ''): ArchiveKind {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return 'tgz';
  if (buf.length >= 4 && buf.readUInt32LE(0) === ZIP_LOCAL_SIG) return 'zip';
  if (buf.length >= 22 && findEocd(buf) >= 0) return 'zip';
  if (buf.length >= 265 && buf.toString('ascii', 257, 262) === 'ustar') return 'tar';
  const lower = nameHint.toLowerCase();
  if (lower.endsWith('.zip') || lower.endsWith('.whl')) return 'zip';
  if (lower.endsWith('.tar')) return 'tar';
  return 'tgz';
}

/** One entry point: sniff the container, decompress if needed, extract. */
export function extractArchive(
  buf: Buffer,
  nameHint: string,
  wanted: (path: string) => boolean,
  limits: ArchiveLimits,
): ArchiveEntry[] {
  const kind = detectArchiveKind(buf, nameHint);
  if (kind === 'zip') return extractZip(buf, wanted, limits);
  const tar = kind === 'tgz' ? gunzipBounded(buf) : buf;
  return extractTar(tar, wanted, limits);
}

/**
 * Strip the single shared top-level directory when every entry lives under one
 * (npm's `package/`, a PyPI sdist's `name-version/`) so paths read like the
 * package root. Archives with multiple roots (wheels) are left untouched.
 */
export function stripCommonRoot(entries: ArchiveEntry[]): ArchiveEntry[] {
  if (entries.length === 0) return entries;
  let root: string | undefined;
  for (const e of entries) {
    const slash = e.path.indexOf('/');
    if (slash <= 0) return entries; // a top-level file — nothing to strip
    const first = e.path.slice(0, slash);
    if (root === undefined) root = first;
    else if (root !== first) return entries; // multiple roots — leave as-is
  }
  return entries.map((e) => ({ path: e.path.slice(root!.length + 1), data: e.data }));
}
