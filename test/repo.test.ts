/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRepoTarget, repoLabel } from '../src/acquire/repo.js';

test('parseRepoTarget accepts the shapes people actually paste', () => {
  const cases: Array<[string, string]> = [
    ['upstash/context7', 'upstash/context7'],
    ['https://github.com/upstash/context7', 'upstash/context7'],
    ['https://www.github.com/upstash/context7', 'upstash/context7'],
    ['https://github.com/upstash/context7.git', 'upstash/context7'],
    ['git@github.com:upstash/context7.git', 'upstash/context7'],
    ['https://github.com/upstash/context7/tree/main', 'upstash/context7@main'],
    ['owner/repo@v1.2.3', 'owner/repo@v1.2.3'],
  ];
  for (const [input, expected] of cases) {
    const r = parseRepoTarget(input);
    assert.ok(r, `${input} should parse`);
    assert.equal(repoLabel(r), expected, input);
  }
});

test('parseRepoTarget leaves every OTHER target shape alone', () => {
  // Each of these must fall through to its own resolver branch — a repository
  // guess that swallowed one of them would break an existing target.
  for (const notARepo of [
    '@modelcontextprotocol/server-filesystem', // scoped package
    'left-pad', // bare package
    'mcp-server-time', // bare package
    './tools.json', // relative path
    '/abs/path/tools.json', // absolute path
    'https://mcp.example.com/mcp', // live endpoint
    'https://gitlab.com/owner/repo', // another forge
    'https://github.com/owner', // no repo part
    'https://github.com/a/b/c/d/e', // not a repo path
    'file:///tmp/x', // scheme
  ]) {
    assert.equal(parseRepoTarget(notARepo), undefined, `${notARepo} must not parse as a repo`);
  }
});

test('parseRepoTarget rejects owner/repo names GitHub itself would reject', () => {
  for (const bad of ['-lead/repo', 'trail-/repo', 'owner/.hidden', 'owner/re po', 'a'.repeat(40) + '/repo']) {
    assert.equal(parseRepoTarget(bad), undefined, `${bad} must be rejected`);
  }
});
