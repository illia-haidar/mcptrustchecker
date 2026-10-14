/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { extractToolsFromSource } from '../src/acquire/toolExtract.js';
import { computeCapabilityProfile, OPEN_DESTINATION_REASON, UNTRUSTED_INPUT_OBSERVATION } from '../src/scoring/capability.js';
import { evaluatePolicy } from '../src/policy.js';
import { renderTerminal } from '../src/report/terminal.js';
import { renderMarkdown } from '../src/report/markdown.js';
import { renderJson } from '../src/report/json.js';
import { makeSurface } from './helpers.js';
import type { JsonSchema, McpTrustCheckerConfig, ScanReport, ServerSurface, ToolDef } from '../src/types.js';

// 1.16.1 — reading external content alone costs no points. The capability axis
// is blast radius: a tool that only brings outside text in can do nothing by
// itself; the combinations that make it harmful (the trifecta, a link to code
// execution) are priced on their own. It still costs points when the MODEL
// chooses where the request goes (SSRF, egress through the URL). The fact itself
// stays on the profile as an observation. Case that started it: Staan 1.0.1
// (web_search / answer against its own fixed API) scored capability moderate, -3.

const str = { type: 'string' };
const tool = (name: string, description: string, properties: Record<string, unknown> = {}, annotations?: ToolDef['annotations']): ToolDef => ({
  name,
  description,
  inputSchema: { type: 'object', properties: properties as Record<string, JsonSchema> },
  ...(annotations ? { annotations } : {}),
});
const scan = (tools: ToolDef[], config?: McpTrustCheckerConfig) => scanSurface(makeSurface({ tools }), config ? { config } : {});
const eCap = (r: ScanReport): number => {
  const line = r.score.vector.find((v) => v.kind === 'client' && v.term === 'capability-exposure');
  assert.ok(line && line.kind === 'client');
  return line.appliedPenalty;
};

const webSearch = tool('web_search', 'Search the web and return the top results.', { query: str });
const fetchUrl = (url: unknown) => tool('fetch_url', 'Return the text of a page.', { url });

// --- the reader alone ----------------------------------------------------------------

test('web_search(query) by keyword, no other role → minimal, E_cap 0, an observation, the tag kept', async () => {
  const r = await scan([webSearch]);
  assert.equal(r.capabilityProfile.level, 'minimal');
  assert.equal(eCap(r), 0);
  assert.deepEqual(r.capabilityProfile.reasons, []);
  assert.deepEqual(r.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
  assert.ok(r.capabilityProfile.tags.includes('untrusted-input'));
  assert.ok(r.capabilities.find((c) => c.tool === 'web_search')!.tags.includes('untrusted-input'), 'the tool keeps its role');
});

test('only openWorldHint: true, no write hint → minimal, the tag kept', async () => {
  const r = await scan([tool('weather_today', 'Return the forecast for a city.', { city: str }, { readOnlyHint: true, openWorldHint: true })]);
  assert.deepEqual(r.capabilities[0]!.tags, ['untrusted-input']);
  assert.equal(r.capabilityProfile.level, 'minimal');
  assert.equal(eCap(r), 0);
  assert.deepEqual(r.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
});

test('openWorldHint: true with a write hint is an external sink → moderate, as before', async () => {
  for (const annotations of [{ openWorldHint: true, destructiveHint: true }, { openWorldHint: true, readOnlyHint: false }]) {
    const r = await scan([tool('sync_remote', 'Synchronise the record.', { id: str }, annotations)]);
    assert.ok(r.capabilityProfile.tags.includes('external-sink'), JSON.stringify(r.capabilityProfile));
    assert.equal(r.capabilityProfile.level, 'moderate');
    assert.equal(eCap(r), 3);
  }
});

// --- the model chooses the destination -------------------------------------------------

test('fetch_url(url) with nothing on url → moderate, the SSRF reason, no observation', async () => {
  const r = await scan([fetchUrl(str)]);
  assert.equal(r.capabilityProfile.level, 'moderate');
  assert.equal(eCap(r), 3);
  assert.deepEqual(r.capabilityProfile.reasons, [OPEN_DESTINATION_REASON]);
  assert.deepEqual(r.capabilityProfile.observations, []);
});

test("fetch_url(url) with pattern '^https?://' → moderate: a prefix pins no host", async () => {
  for (const pattern of ['^https?://', '^https://', '^https://[a-z0-9.-]+', 'example\\.com$', '^https://a\\.example\\.com/x$|^http']) {
    const r = await scan([fetchUrl({ type: 'string', pattern })]);
    assert.equal(r.capabilityProfile.level, 'moderate', pattern);
  }
});

test('fetch_url(url) held by enum, const or a whole-value pattern → minimal', async () => {
  for (const url of [
    { type: 'string', enum: ['https://api.example.com/a', 'https://api.example.com/b'] },
    { type: 'string', const: 'https://api.example.com/feed' },
    { type: 'string', pattern: '^https://api\\.example\\.com/v1/[a-z0-9-]+$' },
    { anyOf: [{ type: 'string', enum: ['https://a.example.com/'] }, { type: 'null' }] },
  ]) {
    const r = await scan([fetchUrl(url)]);
    assert.equal(r.capabilityProfile.level, 'minimal', JSON.stringify(url));
    assert.deepEqual(r.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
  }
});

test('a URL / host parameter by any of its words: targetUrl, base_url, a list of urls, a host, an Optional[str]', async () => {
  for (const [pname, schema] of [
    ['targetUrl', str],
    ['base_url', str],
    ['urls', { type: 'array', items: str }],
    ['host', str],
    ['url', { anyOf: [str, { type: 'null' }] }],
    ['url', {}],
  ] as const) {
    const r = await scan([tool('scrape_page', 'Return the page text.', { [pname]: schema })]);
    assert.equal(r.capabilityProfile.level, 'moderate', pname);
  }
  // Not a destination: a boolean switch, a number, a word that only contains "url".
  for (const [pname, schema] of [
    ['include_url', { type: 'boolean' }],
    ['url_count', { type: 'integer' }],
    ['curly', str],
  ] as const) {
    const r = await scan([tool('scrape_page', 'Return the page text.', { query: str, [pname]: schema })]);
    assert.equal(r.capabilityProfile.level, 'minimal', pname);
  }
});

test('disabling MTC-CAP-007 or the whole capability detector does not move the score', async () => {
  const base = await scan([fetchUrl(str)]);
  assert.ok(base.findings.some((f) => f.ruleId === 'MTC-CAP-007'), 'the SSRF finding fires by default');
  for (const disabledRules of [['MTC-CAP-007'], ['capability']]) {
    const r = await scan([fetchUrl(str)], { disabledRules });
    assert.ok(!r.findings.some((f) => f.ruleId === 'MTC-CAP-007'));
    assert.equal(r.capabilityProfile.level, 'moderate', disabledRules[0]);
    assert.equal(eCap(r), 3);
    assert.equal(r.score.score, base.score.score);
  }
  const suppressed = await scan([fetchUrl(str)], { suppress: [{ rule: 'MTC-CAP-007', reason: 'reviewed' }] });
  assert.equal(suppressed.capabilityProfile.level, 'moderate');
});

test('a handler that fetches a URL taken from its input → moderate (the handler source)', async () => {
  const r = await scanPkg(
    'dist/index.js',
    `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nimport { z } from 'zod';\n` +
      `server.registerTool('grab', { description: 'Return the page.', inputSchema: { target: z.string() } }, async ({ target }) => {\n` +
      `  const page = await fetch(target).then((r) => r.text());\n  return { content: [{ type: 'text', text: page }] };\n});\n`,
  );
  const cap = r.capabilities.find((c) => c.tool === 'grab')!;
  assert.deepEqual(cap.sources?.['untrusted-input'], ['handler'], JSON.stringify(cap.sources));
  assert.equal(r.capabilityProfile.level, 'moderate');
  assert.deepEqual(r.capabilityProfile.reasons, [OPEN_DESTINATION_REASON]);
});

test('a url parameter on a tool whose prose says it fetches → moderate (the param source)', async () => {
  const r = await scan([tool('archive_page', 'Fetch the page at url and keep a copy.', { url: str })]);
  assert.ok(r.capabilities[0]!.sources?.['untrusted-input']?.includes('param'), JSON.stringify(r.capabilities[0]));
  assert.equal(r.capabilityProfile.level, 'moderate');
});

/** A package scan as acquisition builds it: source in, static tools recovered. */
async function scanPkg(path: string, content: string): Promise<ScanReport> {
  const files = [{ path, content }];
  const ex = extractToolsFromSource(files);
  assert.ok(ex.tools.length > 0, 'the registration is recovered');
  return scanSurface({
    id: 'pkg',
    source: { kind: 'package', origin: 'pkg' },
    server: {},
    tools: ex.tools,
    prompts: [],
    resources: [],
    sourceFiles: files,
    toolProvenance: 'static',
    staticTools: ex.origins,
  } as unknown as ServerSurface);
}

test('a statically recovered tool keeps only parameter names: its registration says whether url is free', async () => {
  const zod = (url: string) =>
    `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nimport { z } from 'zod';\n` +
    `server.registerTool('fetch_page', { description: 'Return a page.', inputSchema: { url: ${url} } }, async () => ({ content: [] }));\n`;
  assert.equal((await scanPkg('dist/index.js', zod('z.string()'))).capabilityProfile.level, 'moderate');
  assert.equal((await scanPkg('dist/index.js', zod("z.enum(['https://api.example.com/a', 'https://api.example.com/b'])"))).capabilityProfile.level, 'minimal');

  // A Python decorator keeps no parameters at all: the handler is what shows a URL taken from the input.
  const py = (body: string) =>
    `import httpx\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n@mcp.tool()\nasync def fetch_page(url: str, query: str) -> str:\n    """Fetch a page."""\n    ${body}\n`;
  assert.equal((await scanPkg('src/srv/server.py', py('return httpx.get(url).text'))).capabilityProfile.level, 'moderate');
  const fixed = await scanPkg('src/srv/server.py', py('return httpx.get("https://api.example.com/search", params={"q": query}).text'));
  assert.equal(fixed.capabilityProfile.level, 'minimal');
  assert.deepEqual(fixed.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
});

// --- combinations are priced as before ---------------------------------------------------

test('untrusted-input in one tool + an external sink in another → moderate (from the sink); the reader is an observation', async () => {
  const r = await scan([webSearch, tool('send_email', 'Send an email to a recipient.', { to: str, body: str })]);
  assert.equal(r.capabilityProfile.level, 'moderate');
  assert.ok(r.capabilityProfile.reasons.includes('can send data / act on an external service'));
  assert.ok(!r.capabilityProfile.reasons.includes(OPEN_DESTINATION_REASON));
  assert.deepEqual(r.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
});

test('trifecta across tools → high; in one tool → critical; code-exec linked to untrusted input → critical', async () => {
  const readFile = tool('read_file', 'Read a file from disk.', { path: str });
  const sendEmail = tool('send_email', 'Send an email to a recipient.', { to: str });
  const cross = await scan([webSearch, readFile, sendEmail]);
  assert.equal(cross.capabilityProfile.level, 'high');
  assert.ok(cross.capabilityProfile.reasons.some((x) => x.startsWith('untrusted-input, sensitive-source and egress co-exist')));
  assert.ok(cross.findings.some((f) => f.ruleId === 'MTC-FLOW-002'));

  const one = await scan([
    tool('scrape_and_post', 'Scrape a web page, read_env for local secrets, and post them via http_request.', { query: str, secret: str }),
  ]);
  assert.equal(one.capabilityProfile.level, 'critical');
  assert.ok(one.findings.some((f) => f.ruleId === 'MTC-FLOW-001'));

  const exec = await scan([webSearch, readFile, tool('run_command', 'Run a shell command.', { command: str })]);
  assert.ok(exec.capabilityProfile.tags.includes('code-exec'));
  assert.equal(exec.capabilityProfile.level, 'critical');
  assert.ok(exec.capabilityProfile.reasons.includes('untrusted input can reach code execution'));
});

test('the level is computed with no surface too (the profile never needs findings for it)', () => {
  const caps = [{ tool: 'web_search', tags: ['untrusted-input' as const], reasons: {}, sources: { 'untrusted-input': ['name' as const] } }];
  assert.equal(computeCapabilityProfile(caps, [], []).level, 'minimal');
  const handler = [{ tool: 'grab', tags: ['untrusted-input' as const], reasons: {}, sources: { 'untrusted-input': ['handler' as const] } }];
  assert.equal(computeCapabilityProfile(handler, [], []).level, 'moderate');
  assert.deepEqual(computeCapabilityProfile([], [], []).observations, []);
});

// --- Staan 1.0.1 -----------------------------------------------------------------------

// The shape of its two tools: both read-only and open-world, both against its own
// fixed API; the model sets only the text of the request and its filters.
const staanAnnotations = { readOnlyHint: true, openWorldHint: true, destructiveHint: false };
const staan: ToolDef[] = [
  tool(
    'web_search',
    'Search the web through the Staan index and return ranked results.',
    {
      query: { type: 'string', minLength: 1, maxLength: 400 },
      market: { anyOf: [str, { type: 'array', items: str }] },
      full_content: { type: 'string', enum: ['none', 'markdown', 'html'] },
      offset: { type: 'integer', enum: [0, 10, 20, 30] },
      include_domains: { anyOf: [{ type: 'array', items: str }, { type: 'null' }] },
      exclude_domains: { anyOf: [{ type: 'array', items: str }, { type: 'null' }] },
      simple_response: { type: 'boolean' },
    },
    { ...staanAnnotations, idempotentHint: true },
  ),
  tool(
    'answer',
    'Ask Staan for a grounded answer with cited sources.',
    {
      query: { type: 'string', minLength: 1 },
      filter: { anyOf: [str, { type: 'null' }] },
      language: { type: 'string', enum: ['en', 'fr'] },
      mode: { type: 'string', enum: ['short', 'long'] },
      sources: { anyOf: [{ type: 'array', items: { type: 'object' } }, { type: 'null' }] },
      sources_mode: { type: 'string', enum: ['search', 'context'] },
      simple_response: { type: 'boolean' },
    },
    { ...staanAnnotations, idempotentHint: false },
  ),
];

test('Staan fixture: web_search(query, market, …) and answer(query, …) → minimal, 100', async () => {
  const r = await scan(staan);
  assert.equal(r.findings.length, 0, r.findings.map((f) => f.ruleId).join(','));
  assert.equal(r.capabilityProfile.level, 'minimal');
  assert.deepEqual(r.capabilityProfile.tags, ['untrusted-input']);
  assert.deepEqual(r.capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
  assert.equal(eCap(r), 0);
  assert.equal(r.score.threatScore, 100);
});

// --- policies ------------------------------------------------------------------------

test("policy: maxCapability 'minimal' passes the reader and blocks fetch_url(url); denyCapabilities ['untrusted-input'] blocks both", async () => {
  const reader = await scan(staan);
  const fetcher = await scan([fetchUrl(str)]);
  assert.deepEqual(evaluatePolicy(reader, { maxCapability: 'minimal' }), []);
  assert.deepEqual(evaluatePolicy(fetcher, { maxCapability: 'minimal' }).map((v) => v.policy), ['maxCapability']);
  for (const r of [reader, fetcher]) {
    assert.deepEqual(evaluatePolicy(r, { denyCapabilities: ['untrusted-input'] }).map((v) => v.policy), ['denyCapabilities']);
  }
});

// --- reports -------------------------------------------------------------------------

test('reports show the observation on its own line, never as a finding', async () => {
  const r = await scan([webSearch]);
  assert.ok(!r.findings.some((f) => f.description.includes('prompt-injection entry point')));
  const term = renderTerminal(r);
  const line = term.split('\n').find((l) => l.includes(UNTRUSTED_INPUT_OBSERVATION));
  assert.ok(line, term);
  assert.ok(!line.includes('methodology'), 'its own line, not appended to the reasons');
  const md = renderMarkdown(r);
  assert.ok(md.includes(`> Observed: ${UNTRUSTED_INPUT_OBSERVATION}.`), md);
  assert.deepEqual(JSON.parse(renderJson(r)).capabilityProfile.observations, [UNTRUSTED_INPUT_OBSERVATION]);
  // A server with nothing to observe prints no such line.
  const quiet = await scan([fetchUrl(str)]);
  assert.ok(!renderTerminal(quiet).includes('observed:'));
  assert.ok(!renderMarkdown(quiet).includes('Observed:'));
});

// --- determinism ---------------------------------------------------------------------

test('determinism: the same input gives byte-identical score, vector and profile', async () => {
  for (const tools of [staan, [fetchUrl(str)], [webSearch, tool('send_email', 'Send an email.', { to: str })]]) {
    const a = await scan(tools);
    const b = await scan(structuredClone(tools));
    assert.equal(JSON.stringify(a.score), JSON.stringify(b.score));
    assert.equal(JSON.stringify(a.score.vector), JSON.stringify(b.score.vector));
    assert.equal(JSON.stringify(a.capabilityProfile), JSON.stringify(b.capabilityProfile));
  }
});
