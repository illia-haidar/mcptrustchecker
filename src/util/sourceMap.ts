/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Source maps, read just far enough to answer one question: which original file
 * does a position in a bundled `dist` file come from? A single-file esbuild/tsup
 * bundle inlines its dependencies (Ajv arrives with the MCP SDK), so a sink found
 * in the bundle may be a dependency's code, not the server's. The map that ships
 * next to the bundle says which.
 *
 * Only generated JavaScript (`.js`/`.mjs`/`.cjs`) has a map. A map is the package
 * author's own data, so it is read as a CLAIM about origin and checked against
 * the file it describes: it may not describe more lines than the file has, its
 * segments must fit the lines, and (see the detector) a site counts as mapped
 * only when a segment starts at the site itself.
 *
 * Dependency-free and bounded: a capped map size and JSON nesting depth checked
 * before parsing, one linear pass over `mappings` per file however many positions
 * are asked about, index-map sections one level deep, `sourcesContent` lines
 * indexed once per source, and nothing is ever fetched — a remote
 * `sourceMappingURL` is ignored.
 */

/** A map larger than this is not read (the 6–8 MB SDK bundles have 15–25 MB maps). */
export const MAX_SOURCE_MAP_BYTES = 32 * 1024 * 1024;
/** Index-map sections read from one map (they never nest). */
const MAX_SECTIONS = 1024;
/** JSON nesting a source map can need (an index map's section map's `sources` is 5 deep). */
const MAX_JSON_DEPTH = 8;
/** Strings in one map (real SDK bundles: tens of thousands). Counted before `JSON.parse`. */
const MAX_JSON_STRINGS = 500_000;
/** `sources` / `names` entries in one map. */
const MAX_ENTRIES = 200_000;
/** A `sourceRoot` longer than this makes the map unusable; a longer `sources` entry is unmappable. */
const MAX_ROOT = 1024;
const MAX_SOURCE_PATH = 4096;
/** A `sources` entry longer than this is cut before it reaches a report. */
const MAX_SOURCE_LABEL = 240;

export interface SourceMapData {
  /** `sources` as written ('' for an entry that is not a string or is too long). */
  sources: string[];
  /** `sourceRoot`, trailing slashes trimmed. */
  root: string;
  /** Per source index: its path (root applied, normalized), npm dependency and printable label — built once. */
  sourceInfo: Map<number, SourceInfo>;
  /** `sourcesContent`, aligned with {@link sources}; null where absent. */
  sourcesContent: (string | null)[];
  mappings: string;
  /** Generated lines `mappings` describes (`;`-separated groups). */
  lines: number;
  /** An index map's sections, sorted by offset (then `sources`/`mappings` are empty). */
  sections?: { line: number; column: number; map: SourceMapData }[];
  /** Line offsets of each `sourcesContent` entry, built on first use. */
  contentLines: Map<number, Int32Array>;
}

export interface SourceInfo {
  path: string;
  dependency: DependencyRef | null;
  label: string;
}

/** A position in the generated file: 0-based line, 0-based UTF-16 column. */
export interface GeneratedPosition {
  line: number;
  column: number;
}

/** Where a generated position came from. `line` is 1-based, `column` 0-based. */
export interface OriginalPosition {
  source: string;
  line: number;
  column: number;
  /** The generated column where the segment that answered starts. */
  generatedColumn: number;
  map: SourceMapData;
  sourceIndex: number;
}

/** The generated file a map claims to describe: its line count and line lengths. */
export interface GeneratedFile {
  lineCount: number;
  lineLength: (line: number) => number;
}

const B64 = new Int8Array(128).fill(-1);
for (let k = 0; k < 64; k++) B64['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.charCodeAt(k)] = k;

/** Generated JavaScript — the only files a source map can describe. */
export function isGeneratedScript(path: string): boolean {
  return /\.[cm]?js$/i.test(path);
}

/**
 * A JSON object whose nesting stays within `max` and that holds at most
 * {@link MAX_JSON_STRINGS} strings — checked linearly BEFORE `JSON.parse`, so a
 * small compressed map cannot make the parser build millions of values.
 */
function jsonShapeOk(text: string, max: number): boolean {
  let i = 0;
  while (i < text.length && (text[i] === ' ' || text[i] === '\n' || text[i] === '\r' || text[i] === '\t')) i++;
  if (text[i] !== '{') return false;
  let depth = 0;
  let strings = 0;
  let inStr = false;
  for (; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++;
      else if (c === 34) inStr = false;
    } else if (c === 34) {
      inStr = true;
      if (++strings > MAX_JSON_STRINGS) return false;
    } else if (c === 123 || c === 91) {
      if (++depth > max) return false;
    } else if (c === 125 || c === 93) depth--;
  }
  return true;
}

/** Parse a v3 source map (plain or index map). Null when it is over the cap, too deep, or not a map. */
export function parseSourceMap(text: string): SourceMapData | null {
  if (typeof text !== 'string' || text.length > MAX_SOURCE_MAP_BYTES) return null;
  // The spec allows an XSSI guard line (`)]}'`) before the JSON.
  const body = text.startsWith(")]}'") ? text.slice(text.indexOf('\n') + 1) : text;
  if (!jsonShapeOk(body, MAX_JSON_DEPTH)) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return null;
  }
  return normalizeMap(raw, 0);
}

function normalizeMap(raw: unknown, depth: number): SourceMapData | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (Array.isArray(o.sections)) {
    if (depth > 0) return null; // sections do not nest
    const sections: NonNullable<SourceMapData['sections']> = [];
    for (const s of o.sections.slice(0, MAX_SECTIONS)) {
      const off = (s as { offset?: { line?: unknown; column?: unknown } } | null)?.offset;
      const line = off?.line;
      const column = off?.column;
      if (!Number.isInteger(line) || !Number.isInteger(column) || (line as number) < 0 || (column as number) < 0) continue;
      // A section that points at a `url` instead of embedding its map is not followed.
      const map = normalizeMap((s as { map?: unknown }).map, depth + 1);
      if (map) sections.push({ line: line as number, column: column as number, map });
    }
    sections.sort((a, b) => a.line - b.line || a.column - b.column);
    const last = sections[sections.length - 1];
    return {
      sources: [],
      root: '',
      sourceInfo: new Map(),
      sourcesContent: [],
      mappings: '',
      lines: last ? last.line + last.map.lines : 0,
      sections,
      contentLines: new Map(),
    };
  }
  if (typeof o.mappings !== 'string' || !Array.isArray(o.sources)) return null;
  if (o.sources.length > MAX_ENTRIES || (Array.isArray(o.names) && o.names.length > MAX_ENTRIES)) return null;
  let root = typeof o.sourceRoot === 'string' ? o.sourceRoot : '';
  if (root.length > MAX_ROOT) return null;
  let end = root.length;
  while (end > 0 && root.charCodeAt(end - 1) === 47) end--; // trailing `/`, without a regex
  root = root.slice(0, end);
  const sources = o.sources.map((s) => (typeof s === 'string' && s.length <= MAX_SOURCE_PATH ? s : ''));
  const sc = Array.isArray(o.sourcesContent) ? o.sourcesContent : [];
  let lines = 1;
  for (let at = o.mappings.indexOf(';'); at >= 0; at = o.mappings.indexOf(';', at + 1)) lines++;
  return {
    sources,
    root,
    sourceInfo: new Map(),
    sourcesContent: sources.map((_, i) => (typeof sc[i] === 'string' ? (sc[i] as string) : null)),
    mappings: o.mappings,
    lines,
    contentLines: new Map(),
  };
}

/**
 * A source's path (`sourceRoot` prepended unless it is already absolute, then
 * normalized — a root of `node_modules/ajv/` with `../../src/x.ts` is `src/x.ts`),
 * its npm dependency and its printable label, computed once per source index.
 */
export function sourceInfoOf(map: SourceMapData, index: number): SourceInfo {
  const hit = map.sourceInfo.get(index);
  if (hit) return hit;
  const raw = map.sources[index] ?? '';
  const joined = raw && map.root && !/^(?:[a-z][a-z0-9+.-]{0,30}:|\/)/i.test(raw) ? `${map.root}/${raw}` : raw;
  const path = joined ? normalizeSourcePath(joined) : '';
  const info: SourceInfo = { path, dependency: path ? dependencyOfNormalized(path) : null, label: sourceLabel(path) };
  map.sourceInfo.set(index, info);
  return info;
}

/**
 * A source path with any `scheme://authority` prefix (`webpack://pkg/`,
 * `file://`) dropped, `\` turned into `/`, and `.`/`..` collapsed — so where a
 * path really points is decided on the normalized form. Leading `..` that climb
 * above the map's own directory are kept.
 */
export function normalizeSourcePath(p: string): string {
  const s = p.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '').replace(/\\/g, '/');
  const out: string[] = [];
  for (const seg of s.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (out.length && out[out.length - 1] !== '..') out.pop();
      else out.push('..');
    } else out.push(seg);
  }
  return out.join('/');
}

/**
 * Resolve generated positions to original ones. Each answer is the segment with
 * the greatest generated column ≤ the position's column on its line; a position
 * before the line's first segment, on a segment with no source, or past the end
 * of `mappings` resolves to null. All positions are answered in ONE pass over
 * `mappings` (sorted queries, sorted segments), so the cost is linear in the map
 * whatever the number of findings. A malformed `mappings`, or one that does not
 * fit `file` (more lines than the file has, a segment past the end of its line),
 * resolves nothing — and the pass stops at the first segment that does not fit.
 */
export function resolvePositions(
  map: SourceMapData,
  queries: readonly GeneratedPosition[],
  file?: GeneratedFile,
): (OriginalPosition | null)[] {
  const out: (OriginalPosition | null)[] = queries.map(() => null);
  if (file && map.lines > file.lineCount) return out;
  if (!map.sections) {
    decodeInto(map, queries, queries.map((_, i) => i), out, file);
    return out;
  }
  // Index map: each position belongs to the last section starting at or before it,
  // and is asked of that section's map relative to the section's offset.
  const bySection = new Map<number, number[]>();
  queries.forEach((q, i) => {
    let k = -1;
    for (let s = 0; s < map.sections!.length; s++) {
      const o = map.sections![s]!;
      if (o.line < q.line || (o.line === q.line && o.column <= q.column)) k = s;
      else break;
    }
    if (k >= 0) {
      const list = bySection.get(k);
      if (list) list.push(i);
      else bySection.set(k, [i]);
    }
  });
  for (const [k, ids] of bySection) {
    const sec = map.sections[k]!;
    const local = ids.map((i) => {
      const q = queries[i]!;
      return { line: q.line - sec.line, column: q.line === sec.line ? q.column - sec.column : q.column };
    });
    const res: (OriginalPosition | null)[] = local.map(() => null);
    const secFile: GeneratedFile | undefined = file && {
      lineCount: file.lineCount - sec.line,
      lineLength: (l) => file.lineLength(l + sec.line) - (l === 0 ? sec.column : 0),
    };
    decodeInto(sec.map, local, local.map((_, j) => j), res, secFile);
    ids.forEach((i, j) => {
      const r = res[j];
      out[i] = r ? { ...r, generatedColumn: r.generatedColumn + (local[j]!.line === 0 ? sec.column : 0) } : null;
    });
  }
  return out;
}

function decodeInto(
  map: SourceMapData,
  queries: readonly GeneratedPosition[],
  ids: number[],
  out: (OriginalPosition | null)[],
  file: GeneratedFile | undefined,
): void {
  const order = ids
    .filter((i) => Number.isInteger(queries[i]!.line) && queries[i]!.line >= 0)
    .sort((a, b) => queries[a]!.line - queries[b]!.line || queries[a]!.column - queries[b]!.column);
  if (!order.length) return;
  const s = map.mappings;
  const n = s.length;
  let i = 0;
  let genLine = 0;
  let genCol = 0;
  let lineLen = file ? file.lineLength(0) : Infinity;
  let src = 0;
  let oLine = 0;
  let oCol = 0;
  // The previous segment on the current line: 0 none, 1 no source, 2 mapped.
  let prevKind = 0;
  let prevSrc = 0;
  let prevLine = 0;
  let prevCol = 0;
  let prevGen = 0;
  let qi = 0;

  const settle = (q: number): void => {
    if (prevKind !== 2 || prevSrc < 0 || prevSrc >= map.sources.length || prevLine < 0 || prevCol < 0) return;
    const source = sourceInfoOf(map, prevSrc).path;
    if (!source) return;
    out[q] = { source, line: prevLine + 1, column: prevCol, generatedColumn: prevGen, map, sourceIndex: prevSrc };
  };
  /** One base64 VLQ value at `i`; NaN on a bad digit or an absurd length. */
  const vlq = (): number => {
    let result = 0;
    let shift = 0;
    let digit: number;
    do {
      if (i >= n || shift > 30) return NaN;
      const c = s.charCodeAt(i++);
      digit = c < 128 ? B64[c]! : -1;
      if (digit < 0) return NaN;
      result += (digit & 31) * 2 ** shift;
      shift += 5;
    } while (digit & 32);
    const v = Math.floor(result / 2);
    return result % 2 ? -v : v;
  };
  const boundary = (): boolean => i >= n || s.charCodeAt(i) === 44 || s.charCodeAt(i) === 59; // end , ;

  while (qi < order.length) {
    if (i >= n || s.charCodeAt(i) === 59) {
      // End of a generated line: every position still open on it takes the last segment.
      while (qi < order.length && queries[order[qi]!]!.line === genLine) settle(order[qi++]!);
      if (i >= n) return; // positions on later lines are unmapped
      genLine++;
      genCol = 0;
      lineLen = file ? file.lineLength(genLine) : Infinity;
      prevKind = 0;
      i++;
      continue;
    }
    if (s.charCodeAt(i) === 44) {
      i++;
      continue;
    }
    const dc = vlq();
    if (Number.isNaN(dc)) return clear(out, ids);
    genCol += dc;
    // A segment past the end of its line: this map is not the map of this file.
    if (genCol < 0 || genCol > lineLen) return clear(out, ids);
    let kind = 1;
    if (!boundary()) {
      const a = vlq();
      const b = vlq();
      const c = vlq();
      if (Number.isNaN(a) || Number.isNaN(b) || Number.isNaN(c)) return clear(out, ids);
      src += a;
      oLine += b;
      oCol += c;
      kind = 2;
      if (!boundary() && Number.isNaN(vlq())) return clear(out, ids); // the name index: read, not used
      if (!boundary()) return clear(out, ids); // more than five fields is not a segment
    }
    // Positions on this line that sit BEFORE this segment belong to the previous one.
    while (qi < order.length && queries[order[qi]!]!.line === genLine && queries[order[qi]!]!.column < genCol) settle(order[qi++]!);
    prevKind = kind;
    prevSrc = src;
    prevLine = oLine;
    prevCol = oCol;
    prevGen = genCol;
  }
}

/** A map that does not fit: forget anything it resolved — none of it can be trusted. */
function clear(out: (OriginalPosition | null)[], ids: number[]): void {
  for (const i of ids) out[i] = null;
}

/**
 * The original text from a resolved position to the end of its line (bounded),
 * or null when the map embeds no `sourcesContent` for that source. The source's
 * line offsets are indexed once, so any number of lookups is linear overall.
 */
export function originalTextAt(pos: OriginalPosition, max = 400): string | null {
  const content = pos.map.sourcesContent[pos.sourceIndex];
  if (typeof content !== 'string') return null;
  const from = originalOffset(pos);
  if (from === null) return '';
  let lineEnd = content.indexOf('\n', from);
  if (lineEnd < 0) lineEnd = content.length;
  return content.slice(from, Math.min(lineEnd, from + max));
}

/** The offset of a resolved position in its `sourcesContent` text, or null (no content, or out of range). */
export function originalOffset(pos: OriginalPosition): number | null {
  const content = pos.map.sourcesContent[pos.sourceIndex];
  if (typeof content !== 'string') return null;
  let starts = pos.map.contentLines.get(pos.sourceIndex);
  if (!starts) {
    let count = 1;
    for (let at = content.indexOf('\n'); at >= 0; at = content.indexOf('\n', at + 1)) count++;
    starts = new Int32Array(count);
    let k = 1;
    for (let at = content.indexOf('\n'); at >= 0; at = content.indexOf('\n', at + 1)) starts[k++] = at + 1;
    pos.map.contentLines.set(pos.sourceIndex, starts);
  }
  if (pos.line < 1 || pos.line > starts.length) return null;
  const from = starts[pos.line - 1]! + pos.column;
  const lineEnd = pos.line < starts.length ? starts[pos.line]! - 1 : content.length;
  return from > lineEnd ? null : from;
}

/**
 * The `sourceMappingURL` a generated file names: the LAST `//# sourceMappingURL=`
 * (or `//@`, or a `/*# … *\/` block), only as a directive that starts its own
 * line and is followed by nothing but whitespace — the same string inside code
 * (a source-map library bundled into the file) is not a directive.
 */
export function sourceMappingUrlOf(content: string): string | null {
  const at = content.lastIndexOf('sourceMappingURL=');
  if (at < 3) return null;
  const lineStart = content.lastIndexOf('\n', at) + 1;
  if (at - lineStart > 64 || !/^[ \t]*(?:\/\/|\/\*)[#@][ \t]*$/.test(content.slice(lineStart, at))) return null;
  const re = /[^\s'"`]+/y;
  re.lastIndex = at + 17;
  const m = re.exec(content);
  if (!m) return null;
  let url = m[0];
  let rest = content.slice(re.lastIndex, re.lastIndex + 64);
  if (url.endsWith('*/')) {
    url = url.slice(0, -2);
    rest = `*/${rest}`;
  }
  rest = rest.trim();
  if (rest !== '' && rest !== '*/') return null;
  return url || null;
}

/** The text of an inline `data:` source map, or null when `url` is not one (or is over the cap). */
export function inlineSourceMap(url: string): string | null {
  const m = /^data:application\/json(?:;[\w=-]{1,40})*?(;base64)?,/i.exec(url);
  if (!m) return null;
  const payload = url.slice(m[0].length);
  if (payload.length > (MAX_SOURCE_MAP_BYTES * 4) / 3 + 4) return null;
  try {
    return m[1] ? Buffer.from(payload, 'base64').toString('utf8') : decodeURIComponent(payload);
  } catch {
    return null;
  }
}

/**
 * The package-relative paths where a generated file's map may sit: the target of
 * its `sourceMappingURL` (resolved against the file's own directory) and the
 * conventional `<file>.map` sidecar. Only `.js`/`.mjs`/`.cjs` files have maps;
 * remote URLs, absolute paths and anything that climbs out of the package are
 * never followed.
 */
export function sourceMapPathsFor(path: string, content: string): string[] {
  if (!isGeneratedScript(path)) return [];
  const out: string[] = [];
  const url = sourceMappingUrlOf(content);
  if (url && !url.startsWith('data:') && !/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith('/')) {
    let rel = url.replace(/[?#].*$/, '');
    try {
      rel = decodeURIComponent(rel);
    } catch {
      /* keep it as written */
    }
    const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
    const joined = normalizeRelPath(dir + rel);
    if (joined) out.push(joined);
  }
  if (!out.includes(`${path}.map`)) out.push(`${path}.map`);
  return out;
}

/** Collapse `.`/`..` in a `/`-separated relative path; null when it leaves the root. */
function normalizeRelPath(p: string): string | null {
  const parts: string[] = [];
  for (const seg of p.replace(/\\/g, '/').split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(seg);
  }
  return parts.length ? parts.join('/') : null;
}

/**
 * Which map a generated file uses: `inline` (its own `data:` URL), the path of a
 * sidecar the acquirer kept, or null. Non-JavaScript files never have one.
 */
export function sourceMapRefOf(path: string, content: string, maps: ReadonlyMap<string, string>): { inline: string } | { path: string } | null {
  const p = path.replace(/\\/g, '/');
  if (!isGeneratedScript(p)) return null;
  const url = sourceMappingUrlOf(content);
  if (url?.startsWith('data:')) return { inline: url };
  if (!maps.size) return null;
  for (const c of sourceMapPathsFor(p, content)) if (maps.has(c)) return { path: c };
  return null;
}

export interface DependencyRef {
  package: string;
  version?: string;
}

const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const VERSION = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:[-+][0-9A-Za-z.+-]{1,64})?$/;

/**
 * The npm package an original source path belongs to, decided on the NORMALIZED
 * path: the package after the last `node_modules/` segment (a nested dependency
 * is its own package); a path whose `..` climb back out of `node_modules` is not
 * a dependency. The version comes from the store layout when it carries one —
 * pnpm `.pnpm/<name>@<ver>[_peer|(peer)]/node_modules/<name>/`, bun
 * `.bun/<name>@<ver>/node_modules/<name>/` (scoped as `@scope+name`), yarn berry
 * `.yarn/cache/<name>-npm-<ver>-<hash>.zip/node_modules/<name>/` (scoped as
 * `@scope-name`). A pnpm store of a LOCAL package (`file+…`, `link+…`,
 * `workspace+…`) is the author's own workspace, not a dependency; nor is anything
 * under `node_modules` that does not name a package (a bundler's `.vite/deps`).
 */
export function dependencyOfSource(source: string): DependencyRef | null {
  return source.length > MAX_SOURCE_PATH ? null : dependencyOfNormalized(normalizeSourcePath(source));
}

function dependencyOfNormalized(path: string): DependencyRef | null {
  const norm = `/${path}`;
  const key = '/node_modules/';
  const last = norm.lastIndexOf(key);
  if (last < 0) return null;
  const rest = norm.slice(last + key.length).split('/');
  let name = rest[0] ?? '';
  if (name.startsWith('@')) {
    if (!rest[1] || rest.length < 3) return null;
    name = `${name}/${rest[1]}`;
  } else if (rest.length < 2) return null;
  if (!name || name.length > 214 || !NPM_NAME.test(name) || name.startsWith('.')) return null;
  const before = norm.slice(0, last);
  const store = before.slice(before.lastIndexOf('/') + 1);
  const parent = before.slice(0, before.lastIndexOf('/'));
  if (/(?:^|@)(?:file|link|workspace)\+/.test(store)) return null;
  // The version comes from the store only when the store names the SAME package as
  // the directory. A store of another package — pnpm's `.pnpm/A@v/node_modules/B`
  // is a symlink to B, one of A's dependencies — says nothing about B: fail
  // closed, keep the directory's package, without a version.
  if (parent.endsWith('/.pnpm') || parent.endsWith('/.bun')) {
    const prefix = `${name.replace('/', '+')}@`;
    if (store.startsWith(prefix)) {
      const version = store.slice(prefix.length).split(/[_(]/)[0]!;
      if (VERSION.test(version)) return { package: name, version };
    }
  } else if (store.endsWith('.zip') && store.length <= 300) {
    // yarn berry: `<name>-npm-<version>-<checksum>[-<cacheKey>].zip` (a scope as `@scope-name`).
    const prefix = `${name.replace('/', '-')}-npm-`;
    if (store.startsWith(prefix)) {
      const parts = store.slice(prefix.length, -4).split('-');
      for (let k = 0; k < 2 && parts.length > 1 && /^[0-9a-f]{5,}$/.test(parts[parts.length - 1]!); k++) parts.pop();
      const version = parts.join('-');
      if (VERSION.test(version)) return { package: name, version };
    }
  }
  return { package: name };
}

/** A map-supplied path made safe to print: no control/bidi characters, bounded length. */
export function sourceLabel(source: string): string {
  const clean = source.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, '');
  return clean.length > MAX_SOURCE_LABEL ? `…${clean.slice(clean.length - MAX_SOURCE_LABEL + 1)}` : clean;
}
