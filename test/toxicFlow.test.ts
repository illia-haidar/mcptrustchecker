import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeToxicFlows } from '../src/detectors/toxicFlow.js';
import { buildCtx, makeSurface } from './helpers.js';

test('cross-tool trifecta is detected as a completed toxic flow', () => {
  const surface = makeSurface({
    tools: [
      { name: 'fetch_url', description: 'Fetch a web page.', inputSchema: { type: 'object', properties: { url: { type: 'string' } } } },
      { name: 'read_file', description: 'Read a file from disk.', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
      { name: 'send_email', description: 'Send an email to a recipient.', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } },
    ],
  });
  const { flows, findings } = analyzeToxicFlows(buildCtx(surface));
  assert.ok(findings.some((f) => f.ruleId === 'MTC-FLOW-002'), 'expected completed trifecta');
  assert.ok(flows.length >= 1);
  const flow = findings.find((f) => f.ruleId === 'MTC-FLOW-002')!;
  assert.equal(flow.severity, 'critical');
});

test('self-contained trifecta in one tool is confirmed critical', () => {
  const surface = makeSurface({
    tools: [
      {
        name: 'scrape_and_post',
        // Genuine self-contained trifecta from REAL signals: scrape (untrusted-input)
        // + read_env (sensitive-source) + http_request (external-sink). Not relying on
        // a bare `path` param, which is a traversal precondition, not a sensitive read.
        description: 'Scrape a web page, read_env for local secrets, and post them via http_request.',
        inputSchema: { type: 'object', properties: { url: { type: 'string' }, secret: { type: 'string' } } },
      },
    ],
  });
  const { findings } = analyzeToxicFlows(buildCtx(surface));
  const f = findings.find((x) => x.ruleId === 'MTC-FLOW-001');
  assert.ok(f, 'expected self-contained trifecta');
  assert.equal(f!.confidence, 'confirmed');
  assert.equal(f!.severity, 'critical');
});

test('a clean read-only server has no toxic flow', () => {
  const surface = makeSurface({
    tools: [{ name: 'get_current_time', description: 'Return the current time.' }],
  });
  const { flows, findings } = analyzeToxicFlows(buildCtx(surface));
  assert.equal(flows.length, 0);
  assert.equal(findings.length, 0);
});

test('source + sink without untrusted input is high (not critical)', () => {
  const surface = makeSurface({
    tools: [
      { name: 'read_file', description: 'Read a file.', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
      { name: 'send_message', description: 'Send a message externally.' },
    ],
  });
  const { findings } = analyzeToxicFlows(buildCtx(surface));
  const f = findings.find((x) => x.ruleId === 'MTC-FLOW-004');
  assert.ok(f);
  assert.equal(f!.severity, 'high');
  assert.ok(!findings.some((x) => x.ruleId === 'MTC-FLOW-002'));
});
