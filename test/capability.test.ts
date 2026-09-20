import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractToolCapability } from '../src/util/capabilities.js';
import { capabilityDetector } from '../src/detectors/capability.js';
import { buildCtx, makeSurface } from './helpers.js';

test('read_file → sensitive-source', () => {
  const cap = extractToolCapability({
    name: 'read_file',
    description: 'Read a file from disk.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
  });
  assert.ok(cap.tags.includes('sensitive-source'));
});

test('fetch_url → untrusted-input', () => {
  const cap = extractToolCapability({ name: 'fetch_url', description: 'Fetch a web page.' });
  assert.ok(cap.tags.includes('untrusted-input'));
});

test('run_command → code-exec', () => {
  const cap = extractToolCapability({
    name: 'run_command',
    description: 'Execute a shell command.',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } } },
  });
  assert.ok(cap.tags.includes('code-exec'));
});

test('a benign time tool has no dangerous tags', () => {
  const cap = extractToolCapability({ name: 'get_current_time', description: 'Return the current time.' });
  assert.equal(cap.tags.length, 0);
});

test('code-exec capability produces a high finding', () => {
  const surface = makeSurface({
    tools: [{ name: 'shell', description: 'Run a shell command.', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } }],
  });
  const findings = capabilityDetector.run(buildCtx(surface));
  const exec = findings.find((f) => f.ruleId === 'MTC-CAP-001');
  assert.ok(exec);
  assert.equal(exec!.severity, 'high');
});

test('annotation-vs-behavior mismatch is flagged', () => {
  const surface = makeSurface({
    tools: [
      {
        name: 'delete_file',
        description: 'Delete a file from disk.',
        inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
        annotations: { readOnlyHint: true },
      },
    ],
  });
  const findings = capabilityDetector.run(buildCtx(surface));
  assert.ok(findings.some((f) => f.ruleId === 'MTC-CAP-003'));
});

test('"file system" in a read tool does not trigger code-exec (FP guard)', () => {
  const cap = extractToolCapability({
    name: 'read_text_file',
    description: 'Read the complete contents of a file from the file system as text.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
  });
  assert.ok(!cap.tags.includes('code-exec'));
});

test('a search "query" parameter is not tagged sensitive-source (FP guard)', () => {
  const cap = extractToolCapability({
    name: 'web_search',
    description: 'Search the web and return results.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
  });
  assert.ok(!cap.tags.includes('sensitive-source'));
});
