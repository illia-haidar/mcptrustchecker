/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * `report.surface` (1.16.1): the tools, prompts and resources a report was
 * computed on, attached on request (`--surface`, `scanSurface(s, { surface: true })`).
 *
 * A marketplace that runs this engine could take only tool NAMES from a report
 * (`capabilities[].tool`). The surface carries what the grade is about — the
 * descriptions, schemas and, for a surface recovered from source, where each
 * tool is registered — from the same normalized surface the detectors read.
 * Opt-in, bounded, deterministic, and invisible when not asked for.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSurface } from '../src/engine.js';
import { resolveTargets } from '../src/acquire/index.js';
import { acquireStdio } from '../src/acquire/live.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { canonicalSurface } from '../src/util/hash.js';
import { renderJson } from '../src/report/json.js';
import { buildReportSurface, SURFACE_LIMITS } from '../src/index.js';
import type { ScanReport, ServerSurface, ToolDef } from '../src/types.js';
import { loadFixture, makeSurface } from './helpers.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'src', 'cli', 'index.ts');
const TSX = import.meta.resolve('tsx');
const WORK = mkdtempSync(join(tmpdir(), 'mtc-surface-1161-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

const byName = <T extends { name: string }>(xs: T[]): T[] => [...xs].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

/** The report as it would be without the option: every key but `surface`, in order. */
function withoutSurface(r: ScanReport): Omit<ScanReport, 'surface'> {
  const { surface: _surface, ...rest } = r;
  return rest;
}

function write(rel: string, content: string): string {
  const p = join(WORK, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
  return p;
}

function cli(args: string[]) {
  const res = spawnSync(process.execPath, ['--max-old-space-size=1024', '--import', TSX, CLI, ...args, '--no-lock', '--no-pager'], {
    cwd: WORK,
    encoding: 'utf8',
    timeout: 60_000,
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

// ── static: the Staan shape ──────────────────────────────────────────────────
// staan-mcp 1.0.1 registers its two tools with `server.add_tool(fn, title=…,
// description=…, annotations=…)`, the title and description being constants
// imported from a sibling module (contract.py), and ships tests that register
// throwaway tools. Reproduced here offline, in the same layout.

const CONTRACT = `from __future__ import annotations

from typing import Final

SERVER_NAME: Final = "staan-like"
WEB_SEARCH_TITLE: Final = "Staan-like web search"
ANSWER_TITLE: Final = "Staan-like answer"

WEB_SEARCH_DESCRIPTION: Final = """\\
Search the web and return ranked results.
"""

ANSWER_DESCRIPTION: Final = """\\
Answer a question from web sources, with citations.
"""
`;

const SERVER = `from __future__ import annotations

from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from staan_like.contract import (
    ANSWER_DESCRIPTION,
    ANSWER_TITLE,
    SERVER_NAME,
    WEB_SEARCH_DESCRIPTION,
    WEB_SEARCH_TITLE,
)


def _annotations(*, idempotent: bool) -> ToolAnnotations:
    return ToolAnnotations(readOnlyHint=True, openWorldHint=True, idempotentHint=idempotent)


async def web_search(query: Annotated[str, Field(min_length=1)], *, offset: int = 0) -> dict[str, Any]:
    """Search the web; see the tool description registered in create_server."""
    return {"query": query, "offset": offset}


async def answer(query: Annotated[str, Field(min_length=1)]) -> dict[str, Any]:
    """Answer a question; see the tool description registered in create_server."""
    return {"query": query}


def create_server() -> MCPServer:
    server = MCPServer(SERVER_NAME)
    server.add_tool(
        web_search,
        title=WEB_SEARCH_TITLE,
        description=WEB_SEARCH_DESCRIPTION,
        annotations=_annotations(idempotent=True),
    )
    server.add_tool(
        answer,
        title=ANSWER_TITLE,
        description=ANSWER_DESCRIPTION,
        annotations=_annotations(idempotent=False),
    )
    return server
`;

const TEST_FILE = `from mcp.server import MCPServer


def fake(query: str) -> str:
    return query


def test_server() -> None:
    server = MCPServer("t")
    server.add_tool(fake, name="test_only_tool", description="A throwaway tool from the test suite.")
`;

function staanLikeDir(): string {
  const dir = join(WORK, 'staan-like');
  write('staan-like/pyproject.toml', '[project]\nname = "staan-like-mcp"\nversion = "1.0.1"\nlicense = "MIT"\n');
  write('staan-like/src/staan_like/__init__.py', '__version__ = "1.0.1"\n');
  write('staan-like/src/staan_like/contract.py', CONTRACT);
  write('staan-like/src/staan_like/server.py', SERVER);
  write('staan-like/tests/test_server.py', TEST_FILE);
  return dir;
}

test('static: a Staan-shaped package lists both tools, with where each is registered; test-suite tools stay out', async () => {
  const [target] = await resolveTargets(staanLikeDir());
  const report = await scanSurface(target!.surface, { surface: true });
  const s = report.surface!;
  assert.equal(s.provenance, 'static');
  assert.deepEqual(s.tools.map((t) => t.name), ['answer', 'web_search']);
  const lines = SERVER.split('\n');
  const addTool = (fn: string) => lines.findIndex((l, i) => /server\.add_tool\(/.test(l) && lines[i + 1]!.trim() === `${fn},`) + 1;
  for (const t of s.tools) {
    assert.deepEqual(t.origin, { file: 'src/staan_like/server.py', line: addTool(t.name), shape: 'direct' }, t.name);
    // The title and description are constants from a SIBLING module; since 1.17
    // the static reader follows the import (one hop) and recovers the constant itself.
    const want = t.name === 'web_search'
      ? { title: 'Staan-like web search', description: 'Search the web and return ranked results.\n' }
      : { title: 'Staan-like answer', description: 'Answer a question from web sources, with citations.\n' };
    assert.equal(t.title, want.title);
    assert.equal(t.description, want.description);
  }
  // The tool registered in tests/ was dropped by the extractor (SKIP_PATH): it
  // is in neither the graded surface nor the listed one.
  assert.ok(!s.tools.some((t) => t.name === 'test_only_tool'));
  assert.equal(report.stats.tools, s.tools.length);
  assert.deepEqual(report.capabilities.map((c) => c.tool).sort(), s.tools.map((t) => t.name));
  assert.deepEqual(s.truncated, []);
});

// ── manifest ─────────────────────────────────────────────────────────────────

const MANIFEST = {
  server: { name: 'notes', version: '2.0.0', title: 'Notes', instructions: 'Never part of report.surface.' },
  tools: [
    {
      name: 'search_notes',
      title: 'Search notes',
      description: 'Find notes by text.',
      inputSchema: { type: 'object', properties: { q: { type: 'string', minLength: 1 } }, required: ['q'] },
      annotations: { readOnlyHint: true },
    },
    {
      name: 'delete_note',
      description: 'Delete one note.',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
      outputSchema: { type: 'object', properties: { ok: { type: 'boolean' } } },
      annotations: { destructiveHint: true, readOnlyHint: false },
    },
  ],
  prompts: [{ name: 'digest', title: 'Digest', description: 'A daily digest.', arguments: [{ name: 'day', required: false }] }],
  resources: [{ uriTemplate: 'notes://{id}', name: 'note', mimeType: 'text/markdown' }],
};

test('manifest: a server.json with tools gives provenance manifest and the fields as written', async () => {
  const path = write('manifest/server.json', JSON.stringify(MANIFEST, null, 2));
  const [target] = await resolveTargets(path);
  const s = (await scanSurface(target!.surface, { surface: true })).surface!;
  assert.equal(s.provenance, 'manifest');
  assert.deepEqual(s.server, { name: 'notes', version: '2.0.0', title: 'Notes' });
  assert.deepEqual(s.tools, byName(MANIFEST.tools));
  assert.deepEqual(s.prompts, MANIFEST.prompts);
  assert.deepEqual(s.resources, MANIFEST.resources);
  assert.deepEqual(s.truncated, []);
});

test('CLI: --surface adds report.surface to --json; without it the report is unchanged', () => {
  const path = write('cli/server.json', JSON.stringify(MANIFEST));
  const plain = cli(['scan', path, '--json']);
  const withSurface = cli(['scan', path, '--json', '--surface']);
  assert.equal(plain.status, 0, plain.stderr);
  assert.equal(withSurface.status, 0, withSurface.stderr);
  const a = JSON.parse(plain.stdout) as ScanReport;
  const b = JSON.parse(withSurface.stdout) as ScanReport;
  assert.equal('surface' in a, false);
  assert.equal(b.surface!.provenance, 'manifest');
  assert.deepEqual(b.surface!.tools.map((t) => t.name), ['delete_note', 'search_notes']);
  // Everything but the timestamp and the new key is byte-for-byte the same.
  const strip = (r: ScanReport) => JSON.stringify({ ...withoutSurface(r), scannedAt: undefined });
  assert.equal(strip(b), strip(a));

  const help = cli(['--help']);
  assert.match(help.stdout, /--surface\s+with --json: add the scanned tools/);
});

// ── live ─────────────────────────────────────────────────────────────────────

const LIVE = JSON.parse(readFileSync(join(ROOT, 'test', 'fixtures', 'surface-live.json'), 'utf8')) as typeof MANIFEST;

test('live: a running server gives provenance live and exactly its tools/list answer', async (t) => {
  let surface: ServerSurface;
  try {
    surface = await acquireStdio({ command: 'node', args: [join(ROOT, 'test', 'fixtures', 'surface-live-server.mjs')] });
  } catch (err) {
    t.skip(`SDK/live acquisition unavailable: ${(err as Error).message}`);
    return;
  }
  const s = (await scanSurface(surface, { surface: true })).surface!;
  assert.equal(s.provenance, 'live');
  // The answer as sent, in the canonical (name) order — not cleaned: the
  // zero-width space in write_note's description is still there.
  assert.deepEqual(s.tools, byName(LIVE.tools));
  assert.ok(s.tools.find((x) => x.name === 'write_note')!.description!.includes('\u200b'));
  assert.deepEqual(s.prompts, LIVE.prompts);
  assert.deepEqual(s.resources, LIVE.resources);
  assert.deepEqual(s.server, LIVE.server);
  assert.deepEqual(s.truncated, []);
});

// ── off by default ───────────────────────────────────────────────────────────

test('without the option the report is byte-identical — the code path changes nothing else', async () => {
  const surfaces: (() => ServerSurface)[] = [
    () => surfaceFromManifest(loadFixture('clean-server.json'), 'clean'),
    () => surfaceFromManifest(loadFixture('poisoned-server.json'), 'poisoned'),
    () => surfaceFromManifest(loadFixture('toxic-flow-server.json'), 'toxic'),
    () => surfaceFromManifest(MANIFEST, 'manifest'),
  ];
  for (const make of surfaces) {
    const base = await scanSurface(make());
    const off = await scanSurface(make(), { surface: false });
    const on = await scanSurface(make(), { surface: true });
    assert.equal('surface' in base, false);
    assert.equal(renderJson(off), renderJson(base));
    assert.equal(JSON.stringify(withoutSurface(on)), JSON.stringify(base));
    // A truthy value that is not `true` does not opt in.
    assert.equal('surface' in (await scanSurface(make(), { surface: 'yes' as unknown as boolean })), false);
  }
});

// ── limits ───────────────────────────────────────────────────────────────────

test('limits: 600 tools → the first 500 in canonical order, and an entry in truncated', async () => {
  const tools: ToolDef[] = [];
  for (let i = 599; i >= 0; i--) tools.push({ name: `tool_${String(i).padStart(3, '0')}`, description: 'Returns the current time.' });
  const report = await scanSurface(makeSurface({ tools }), { surface: true });
  const s = report.surface!;
  assert.equal(report.stats.tools, 600, 'the grade still covers every tool');
  assert.equal(s.tools.length, 500);
  assert.equal(s.tools[0]!.name, 'tool_000');
  assert.equal(s.tools[499]!.name, 'tool_499');
  assert.deepEqual(s.truncated, ['tools: 600 present, the first 500 included (limit 500)']);
});

test('limits: a 100 KB schema is cut to its outline and recorded; the report stays valid JSON', async () => {
  const properties: Record<string, { type: string; description: string }> = {};
  for (let i = 0; i < 100; i++) properties[`field_${i}`] = { type: i % 2 ? 'string' : 'integer', description: 'd'.repeat(1000) };
  const inputSchema = { type: 'object', properties, required: ['field_0', 'field_1'] };
  assert.ok(JSON.stringify(inputSchema).length > 100_000);
  const report = await scanSurface(makeSurface({ tools: [{ name: 'big', description: 'A big schema.', inputSchema }] }), { surface: true });
  const t = report.surface!.tools[0]!;
  const outline = t.inputSchema as { type: string; properties: Record<string, unknown>; required: string[] };
  assert.equal(outline.type, 'object');
  assert.deepEqual(outline.properties.field_0, { type: 'integer' });
  assert.deepEqual(outline.properties.field_1, { type: 'string' });
  assert.equal(Object.keys(outline.properties).length, 100);
  assert.deepEqual(outline.required, ['field_0', 'field_1']);
  assert.ok(JSON.stringify(outline).length <= SURFACE_LIMITS.maxSchemaBytes);
  assert.deepEqual(report.surface!.truncated, [
    'tool "big" inputSchema: larger than 65536 bytes as compact JSON — reduced to its top-level properties and their types',
  ]);
  assert.doesNotThrow(() => JSON.parse(renderJson(report)));

  // A schema just under the limit is kept whole.
  const fits = { type: 'object', properties: { a: { type: 'string', description: 'x'.repeat(60_000) } } };
  const kept = buildReportSurface(makeSurface({ tools: [{ name: 'fits', inputSchema: fits }] }));
  assert.deepEqual(kept.tools[0]!.inputSchema, fits);
  assert.deepEqual(kept.truncated, []);
});

test('limits: an outline that is itself too large, a hostile depth or a cycle — omitted or reduced, never a crash', () => {
  const wide: Record<string, unknown> = {};
  for (let i = 0; i < 4000; i++) wide[`p${i}_${'n'.repeat(20)}`] = { type: 'string' };
  let deep: Record<string, unknown> = { type: 'string' };
  for (let i = 0; i < 5000; i++) deep = { type: 'object', properties: { x: deep } };
  const cyclic: Record<string, unknown> = { type: 'object', properties: {} };
  (cyclic.properties as Record<string, unknown>).self = cyclic;
  const s = buildReportSurface(
    makeSurface({
      tools: [
        { name: 'cyclic', inputSchema: cyclic },
        { name: 'deep', inputSchema: deep, outputSchema: 'not a schema' as unknown as ToolDef['outputSchema'] },
        { name: 'wide', inputSchema: { type: 'object', properties: wide } },
      ],
    }),
  );
  const [cyc, dp, wd] = s.tools;
  assert.deepEqual(cyc!.inputSchema, { type: 'object', properties: { self: { type: 'object' } } });
  assert.deepEqual(dp!.inputSchema, { type: 'object', properties: { x: { type: 'object' } } });
  assert.equal(dp!.outputSchema, undefined);
  assert.equal(wd!.inputSchema, undefined);
  assert.deepEqual(s.truncated, [
    'tool "cyclic" inputSchema: it contains itself — reduced to its top-level properties and their types',
    'tool "deep" inputSchema: nested deeper than 64 levels — reduced to its top-level properties and their types',
    'tool "deep" outputSchema: not a JSON object — omitted',
    'tool "wide" inputSchema: larger than 65536 bytes as compact JSON, and so is its outline — omitted',
  ]);
  assert.doesNotThrow(() => JSON.stringify(s));
});

test('text: line endings normalized, nothing else touched; over 8,000 characters cut and recorded', () => {
  const long = 'Line one.\r\nLine two.\rLine three.\n' + 'x'.repeat(9000);
  const smuggled = 'Plain text\u200b with a hidden\u{E0041} tag.';
  const surrogate = 'y'.repeat(7999) + '\u{1F600}' + 'z';
  const s = buildReportSurface(
    makeSurface({
      tools: [
        { name: 'a_long', description: long },
        { name: 'b_smuggled', description: smuggled, title: 'T\r\nitle' },
        { name: 'c_pair', description: surrogate },
      ],
    }),
  );
  const [a, b, c] = s.tools;
  assert.equal(a!.description!.length, 8000);
  assert.ok(a!.description!.startsWith('Line one.\nLine two.\nLine three.\nxxx'));
  assert.equal(b!.description, smuggled);
  assert.equal(b!.title, 'T\nitle');
  // A cut never splits a surrogate pair.
  assert.equal(c!.description, 'y'.repeat(7999));
  assert.deepEqual(s.truncated, [
    'tool "a_long" description: 9032 characters, cut to 8000 (limit 8000)',
    'tool "c_pair" description: 8002 characters, cut to 7999 (limit 8000)',
  ]);
});

// ── determinism ──────────────────────────────────────────────────────────────

test('determinism: two runs give a byte-identical surface, in the order behind surfaceDigest, which it leaves alone', async () => {
  const make = () =>
    makeSurface({
      tools: [
        { name: 'zeta', description: 'Z.' },
        { name: 'Alpha', description: 'Capital A sorts before lower case.' },
        { name: 'émoji', description: 'Non-ASCII sorts by code unit.' },
        { name: 'alpha', description: 'First of two with this name.', inputSchema: { type: 'object', properties: { b: { type: 'string' }, a: { type: 'number' } } } },
        { name: 'alpha', description: 'Second of two with this name.' },
        { name: '\u{1F600}', description: 'Astral.' },
      ],
      prompts: [{ name: 'p2' }, { name: 'p1', arguments: [{ name: 'x' }] }],
      resources: [{ uri: 'b://2' }, { uri: 'a://1', name: 'one' }],
    });
  const one = await scanSurface(make(), { surface: true });
  const two = await scanSurface(make(), { surface: true });
  assert.equal(JSON.stringify(one.surface), JSON.stringify(two.surface));
  const names = one.surface!.tools.map((t) => t.name);
  assert.deepEqual(names, (canonicalSurface(make()).tools as { name: string }[]).map((t) => t.name));
  assert.deepEqual(names, ['Alpha', 'alpha', 'alpha', 'zeta', 'émoji', '\u{1F600}']);
  assert.equal(one.surface!.tools[1]!.description, 'First of two with this name.');
  // Schema keys keep the order they were declared in.
  assert.deepEqual(Object.keys((one.surface!.tools[1]!.inputSchema as { properties: object }).properties), ['b', 'a']);
  assert.deepEqual(one.surface!.prompts.map((p) => p.name), ['p1', 'p2']);
  assert.deepEqual(one.surface!.resources.map((r) => r.uri), ['a://1', 'b://2']);
  assert.equal(one.surfaceDigest, (await scanSurface(make())).surfaceDigest);
});

test('provenance follows how the surface was read', () => {
  const p = (partial: Partial<ServerSurface>) => buildReportSurface(makeSurface(partial)).provenance;
  const tool = [{ name: 't' }];
  assert.equal(p({ source: { kind: 'stdio', origin: 'node x' }, tools: tool }), 'live');
  assert.equal(p({ source: { kind: 'http', origin: 'https://h/mcp' }, tools: tool }), 'live');
  // A client-config entry only carries tools when --run started the server.
  assert.equal(p({ source: { kind: 'client-config', origin: 'c.json' }, tools: tool }), 'live');
  assert.equal(p({ source: { kind: 'client-config', origin: 'c.json' } }), 'manifest');
  assert.equal(p({ source: { kind: 'manifest', origin: 'tools.json' }, tools: tool }), 'manifest');
  // A package that ships a tools.json, and one where nothing was recovered.
  assert.equal(p({ source: { kind: 'package', origin: 'dir' }, tools: tool }), 'manifest');
  assert.equal(p({ source: { kind: 'package', origin: 'dir' } }), 'static');
  assert.equal(p({ source: { kind: 'package', origin: 'dir' }, tools: tool, toolProvenance: 'static' }), 'static');
  assert.deepEqual(SURFACE_LIMITS, { maxItems: 500, maxText: 8000, maxSchemaBytes: 65536 });
});
