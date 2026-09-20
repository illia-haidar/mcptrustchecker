import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSurface } from '../src/engine.js';
import { surfaceFromManifest } from '../src/acquire/manifest.js';
import { GRADE_RANK } from '../src/scoring/model.js';
import { loadFixture } from './helpers.js';
import type { Grade } from '../src/types.js';

// FALSE-POSITIVE corpus: legitimate — sometimes very powerful — servers that
// must keep a high Trust grade. This locks in the calibration work so a future
// change can't quietly start failing honest servers.

async function grade(manifest: unknown): Promise<Grade> {
  const r = await scanSurface(surfaceFromManifest(manifest, 'fp-test'));
  return r.score.grade;
}
const atLeastB = (g: Grade) => GRADE_RANK[g] >= GRADE_RANK['B'];

test('the clean fixture stays A', async () => {
  assert.equal(await grade(loadFixture('clean-server.json')), 'A');
});

test('a plain fetch tool stays A', async () => {
  assert.equal(await grade({ tools: [{ name: 'fetch', description: 'Fetch a URL and return the page contents as markdown.', inputSchema: { type: 'object', properties: { url: { type: 'string' } } } }] }), 'A');
});

test('a powerful file read/write server keeps a high Trust grade (capability ≠ malice)', async () => {
  const g = await grade({
    tools: [
      { name: 'read_file', description: 'Read a file from disk and return its contents.', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
      { name: 'write_file', description: 'Write or append content to a file on disk.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } } } },
    ],
  });
  assert.ok(atLeastB(g), `expected ≥ B, got ${g}`);
});

test('legit credential / env phrasing stays A', async () => {
  assert.equal(await grade({ tools: [{ name: 't', description: 'Reads your API_KEY and SECRET_KEY from the .env file to authenticate.' }] }), 'A');
});

test('emoji- and ALL-CAPS-decorated docs stay ≥ B (pubmed-style verbose server)', async () => {
  const g = await grade({
    tools: [{ name: 'unified_search', description: '🔍 Unified Search — 1️⃣ analyze ⚠️ then 2️⃣ rank ✅ IMPORTANT: configure your key first. This tool provides RAW MATERIALS for the agent.' }],
  });
  assert.ok(atLeastB(g), `expected ≥ B, got ${g}`);
});

test('assertive self-preference ("only correct tool") stays ≥ B (desktop-commander-style)', async () => {
  const g = await grade({
    tools: [{ name: 'start_process', description: 'This is the ONLY correct tool for local file analysis. Always use this instead of the analysis tool, which CANNOT access local files.' }],
  });
  assert.ok(atLeastB(g), `expected ≥ B, got ${g}`);
});
