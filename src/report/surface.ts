/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The scanned surface as part of the JSON report (`--surface`).
 *
 * A report names the tools it graded (`capabilities[].tool`) but not what they
 * say. A marketplace that lists a server's tools wants the ones the score was
 * computed on — descriptions, schemas and, for a surface recovered from source,
 * where each tool is registered — not a second reading of the package that may
 * disagree with the grade. So this is built from the very surface the detectors
 * read: after normalization, before analysis, with the tools the extractor
 * drops as test/example code already absent.
 *
 * Opt-in: without it a report is byte-identical to one built before it existed.
 * Text is passed on as read, line endings normalized and nothing else — hidden
 * characters are what the Unicode detectors report, and a consumer escapes for
 * its own medium. Bounded, so a hostile surface cannot blow up the report: every
 * cut is listed in `truncated`, saying what and why. Deterministic: tools in the
 * code-unit name order of the canonical surface behind `surfaceDigest`, so the
 * same surface always gives byte-identical JSON. The digest itself is untouched.
 */

import type {
  PromptArgument,
  PromptDef,
  ReportSurface,
  ReportSurfaceTool,
  ResourceDef,
  ServerSurface,
  ToolAnnotations,
} from '../types.js';

/** What `report.surface` keeps at most; anything over is cut and listed in `truncated`. */
export const SURFACE_LIMITS = Object.freeze({
  /** Tools listed (and, separately, prompts, resources and one prompt's arguments). */
  maxItems: 500,
  /** Characters (UTF-16 code units) of one description or title. */
  maxText: 8000,
  /** Bytes of one tool's inputSchema, outputSchema or annotations, as compact JSON. */
  maxSchemaBytes: 64 * 1024,
});

// A legitimate JSON Schema is a few levels deep; a copy deeper than this is a
// payload, and would also be deeper than JSON.stringify's stack can serialize.
const MAX_JSON_DEPTH = 64;

const HINT_KEYS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const;

type AnyObj = Record<string, unknown>;

function isObject(v: unknown): v is AnyObj {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v);
}

/** An own data property, `__proto__` included — a plain assignment would set the prototype. */
function setOwn(o: AnyObj, k: string, v: unknown): void {
  if (k === '__proto__') Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
  else o[k] = v;
}

/** Code-unit order, never localeCompare: the same names must sort the same on every machine. */
function byKey<T>(key: (x: T) => string): (a: T, b: T) => number {
  return (a, b) => {
    const x = key(a);
    const y = key(b);
    return x < y ? -1 : x > y ? 1 : 0;
  };
}

/** A list of the surface as objects; a hand-built surface may carry anything there. */
function objects(v: unknown): AnyObj[] {
  return Array.isArray(v) ? v.filter(isObject) : [];
}

function nameOf(v: unknown): string {
  return typeof v === 'string' ? v : String(v ?? '');
}

/**
 * Where the tools came from. Acquisition marks only a reconstructed surface
 * (`static`); the rest follows from how the surface was read: a running server
 * (stdio / HTTP, or a client-config entry, which only carries tools when `--run`
 * started it) is `live`, a declared list (a tools.json / server.json, or one a
 * package ships) is `manifest`. A package or repository with nothing recovered
 * from its code is `static`: its source was what the scan had.
 */
function provenanceOf(s: ServerSurface): ReportSurface['provenance'] {
  const p = s.toolProvenance;
  if (p === 'live' || p === 'manifest' || p === 'static') return p;
  const kind = s.source?.kind;
  if (kind === 'stdio' || kind === 'http') return 'live';
  const tools = objects(s.tools).length;
  if (kind === 'client-config') return tools || objects(s.prompts).length || objects(s.resources).length ? 'live' : 'manifest';
  if ((kind === 'package' || kind === 'repo') && tools === 0) return 'static';
  return 'manifest';
}

/** A text field as read: line endings normalized, capped without splitting a surrogate pair. */
function text(v: unknown, where: string, cut: string[]): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.includes('\r') ? v.replace(/\r\n?/g, '\n') : v;
  if (s.length <= SURFACE_LIMITS.maxText) return s;
  let end = SURFACE_LIMITS.maxText;
  const last = s.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  cut.push(`${where}: ${s.length} characters, cut to ${end} (limit ${SURFACE_LIMITS.maxText})`);
  return s.slice(0, end);
}

type Copy = { ok: true; value: unknown } | { ok: false; why: string };

/**
 * A JSON copy of `value` that fits `budget` bytes of compact JSON, or why it
 * does not. Follows JSON.stringify's rules (undefined/functions dropped from
 * objects, null in arrays, non-finite numbers as null) and counts the exact
 * bytes it would print, so the walk stops as soon as the budget is spent — a
 * 100 MB schema, a sparse array claiming a billion items, or a shared subtree
 * repeated a million times all cost at most `budget` bytes of work.
 */
function jsonCopy(value: unknown, budget: number): Copy {
  let left = budget;
  let why = '';
  const path = new Set<object>();
  const walk = (v: unknown, depth: number): unknown => {
    if (v === null) {
      left -= 4;
      return null;
    }
    if (typeof v === 'string') {
      left -= Buffer.byteLength(JSON.stringify(v));
      return v;
    }
    if (typeof v === 'number') {
      left -= Number.isFinite(v) ? String(v).length : 4;
      return Number.isFinite(v) ? v : null;
    }
    if (typeof v === 'boolean') {
      left -= v ? 4 : 5;
      return v;
    }
    // undefined, a function, a symbol, a bigint: not JSON (the caller drops or nulls it).
    if (typeof v !== 'object') return undefined;
    if (depth >= MAX_JSON_DEPTH) {
      why = `nested deeper than ${MAX_JSON_DEPTH} levels`;
      return undefined;
    }
    if (path.has(v)) {
      why = 'it contains itself';
      return undefined;
    }
    path.add(v);
    left -= 2;
    let out: unknown;
    if (Array.isArray(v)) {
      const arr: unknown[] = [];
      for (let i = 0; i < v.length && !why && left >= 0; i++) {
        if (i > 0) left -= 1;
        const item = walk(v[i], depth + 1);
        if (item === undefined) left -= 4;
        arr.push(item === undefined ? null : item);
      }
      out = arr;
    } else {
      const o: AnyObj = {};
      let n = 0;
      for (const k of Object.keys(v)) {
        if (why || left < 0) break;
        const raw = (v as AnyObj)[k];
        if (raw === undefined || typeof raw === 'function' || typeof raw === 'symbol' || typeof raw === 'bigint') continue;
        left -= Buffer.byteLength(JSON.stringify(k)) + 1 + (n++ > 0 ? 1 : 0);
        setOwn(o, k, walk(raw, depth + 1));
      }
      out = o;
    }
    path.delete(v);
    return out;
  };
  const copy = walk(value, 0);
  if (why) return { ok: false, why };
  if (left < 0) return { ok: false, why: `larger than ${budget} bytes as compact JSON` };
  return { ok: true, value: copy };
}

function isTypeValue(t: unknown): boolean {
  return typeof t === 'string' || (Array.isArray(t) && t.length <= 16 && t.every((x) => typeof x === 'string'));
}

/** What survives of an oversized schema: its type, its top-level parameters with their types, what is required. */
function schemaOutline(schema: AnyObj): AnyObj {
  const out: AnyObj = {};
  if (isTypeValue(schema.type)) out.type = schema.type;
  if (isObject(schema.properties)) {
    const props: AnyObj = {};
    for (const k of Object.keys(schema.properties)) {
      const p = schema.properties[k];
      setOwn(props, k, isObject(p) && isTypeValue(p.type) ? { type: p.type } : {});
    }
    out.properties = props;
  }
  if (Array.isArray(schema.required)) out.required = schema.required.filter((r) => typeof r === 'string');
  return out;
}

/** A schema as read when it fits; otherwise its outline, or nothing — each cut recorded. */
function schemaField(v: unknown, where: string, cut: string[]): AnyObj | undefined {
  if (v === undefined || v === null) return undefined;
  if (!isObject(v)) {
    cut.push(`${where}: not a JSON object — omitted`);
    return undefined;
  }
  const full = jsonCopy(v, SURFACE_LIMITS.maxSchemaBytes);
  if (full.ok) return full.value as AnyObj;
  const outline = jsonCopy(schemaOutline(v), SURFACE_LIMITS.maxSchemaBytes);
  if (outline.ok) {
    cut.push(`${where}: ${full.why} — reduced to its top-level properties and their types`);
    return outline.value as AnyObj;
  }
  cut.push(`${where}: ${full.why}, and so is its outline — omitted`);
  return undefined;
}

/** Annotations as read when they fit; otherwise the four behaviour hints the score reads. */
function annotationsField(v: unknown, where: string, cut: string[]): ToolAnnotations | undefined {
  if (v === undefined || v === null) return undefined;
  if (!isObject(v)) {
    cut.push(`${where}: not a JSON object — omitted`);
    return undefined;
  }
  const full = jsonCopy(v, SURFACE_LIMITS.maxSchemaBytes);
  if (full.ok) return full.value as ToolAnnotations;
  const hints: ToolAnnotations = {};
  for (const k of HINT_KEYS) if (typeof v[k] === 'boolean') hints[k] = v[k] as boolean;
  cut.push(`${where}: ${full.why} — reduced to the behaviour hints`);
  return hints;
}

/** The first `maxItems` of a list, recording what was left out. */
function capList<T>(items: T[], label: string, cut: string[]): T[] {
  const max = SURFACE_LIMITS.maxItems;
  if (items.length <= max) return items;
  cut.push(`${label}: ${items.length} present, the first ${max} included (limit ${max})`);
  return items.slice(0, max);
}

function toolEntry(raw: AnyObj, s: ServerSurface, provenance: ReportSurface['provenance'], cut: string[]): ReportSurfaceTool {
  const name = nameOf(raw.name);
  const at = `tool ${JSON.stringify(name)}`;
  const out: ReportSurfaceTool = { name };
  const title = text(raw.title, `${at} title`, cut);
  if (title !== undefined) out.title = title;
  const description = text(raw.description, `${at} description`, cut);
  if (description !== undefined) out.description = description;
  const inputSchema = schemaField(raw.inputSchema, `${at} inputSchema`, cut);
  if (inputSchema) out.inputSchema = inputSchema;
  const outputSchema = schemaField(raw.outputSchema, `${at} outputSchema`, cut);
  if (outputSchema) out.outputSchema = outputSchema;
  const annotations = annotationsField(raw.annotations, `${at} annotations`, cut);
  if (annotations) out.annotations = annotations;
  const origins = s.staticTools;
  if (provenance === 'static' && origins && Object.hasOwn(origins, name)) {
    const o = origins[name]!;
    out.origin = { file: o.file, line: o.line, shape: o.via };
  }
  return out;
}

function promptEntry(raw: AnyObj, cut: string[]): PromptDef {
  const name = nameOf(raw.name);
  const at = `prompt ${JSON.stringify(name)}`;
  const out: PromptDef = { name };
  const title = text(raw.title, `${at} title`, cut);
  if (title !== undefined) out.title = title;
  const description = text(raw.description, `${at} description`, cut);
  if (description !== undefined) out.description = description;
  if (Array.isArray(raw.arguments)) {
    const args = capList(objects(raw.arguments), `${at} arguments`, cut);
    out.arguments = args.map((a): PromptArgument => {
      const arg: PromptArgument = { name: nameOf(a.name) };
      const d = text(a.description, `${at} argument ${JSON.stringify(arg.name)} description`, cut);
      if (d !== undefined) arg.description = d;
      if (typeof a.required === 'boolean') arg.required = a.required;
      return arg;
    });
  }
  return out;
}

function resourceKey(r: AnyObj): string {
  return typeof r.uri === 'string' ? r.uri : typeof r.uriTemplate === 'string' ? r.uriTemplate : nameOf(r.name);
}

function resourceEntry(raw: AnyObj, cut: string[]): ResourceDef {
  const at = `resource ${JSON.stringify(resourceKey(raw))}`;
  const out: ResourceDef = {};
  for (const k of ['uri', 'uriTemplate', 'name'] as const) if (typeof raw[k] === 'string') out[k] = raw[k] as string;
  const title = text(raw.title, `${at} title`, cut);
  if (title !== undefined) out.title = title;
  const description = text(raw.description, `${at} description`, cut);
  if (description !== undefined) out.description = description;
  if (typeof raw.mimeType === 'string') out.mimeType = raw.mimeType;
  return out;
}

/**
 * The surface the report was computed on, bounded and in canonical order.
 * Pure: reads the surface, never changes it.
 */
export function buildReportSurface(surface: ServerSurface): ReportSurface {
  const cut: string[] = [];
  const provenance = provenanceOf(surface);
  for (const f of Array.isArray(surface.staticToolsTruncated) ? surface.staticToolsTruncated : []) {
    cut.push(`file ${f}: static tool recovery hit a reading cap — tools it registers may be missing`);
  }

  const server: ReportSurface['server'] = {};
  const srv = isObject(surface.server) ? surface.server : {};
  if (typeof srv.name === 'string') server.name = srv.name;
  if (typeof srv.version === 'string') server.version = srv.version;
  const serverTitle = text(srv.title, 'server title', cut);
  if (serverTitle !== undefined) server.title = serverTitle;

  // The order canonicalSurface (util/hash.ts) gives `surfaceDigest`: a stable
  // code-unit sort by name, so two tools of one name keep the order they came in.
  const tools = capList(
    objects(surface.tools).sort(byKey((t) => nameOf(t.name))),
    'tools',
    cut,
  ).map((t) => toolEntry(t, surface, provenance, cut));
  const prompts = capList(
    objects(surface.prompts).sort(byKey((p) => nameOf(p.name))),
    'prompts',
    cut,
  ).map((p) => promptEntry(p, cut));
  const resources = capList(
    objects(surface.resources).sort(byKey(resourceKey)),
    'resources',
    cut,
  ).map((r) => resourceEntry(r, cut));

  return { provenance, truncated: cut, server, tools, prompts, resources };
}
