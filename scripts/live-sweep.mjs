#!/usr/bin/env node
/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Opt-in live integration sweep: boot a set of REAL MCP servers over stdio and
 * scan each. A boot failure (network/registry/deps) is tolerated; a *scanner*
 * crash is a hard failure and exits non-zero.
 *
 *   node scripts/live-sweep.mjs                 # default curated set
 *   node scripts/live-sweep.mjs pkg1 pkg2 ...   # custom npx package list
 *
 * Requires `npm run build` first (imports from dist/). Needs network + npx.
 */
import { acquireStdio } from '../dist/acquire/live.js';
import { scanSurface } from '../dist/engine.js';
import { isCapabilityRule } from '../dist/scoring/model.js';

const DEFAULT = [
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-filesystem /tmp',
  '@playwright/mcp',
  'mcp-shrimp-task-manager',
  '@waldzellai/clear-thought',
];

const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT;
let crashes = 0;
let ok = 0;
let boot = 0;

for (const t of targets) {
  const [name, ...rest] = t.split(' ');
  const args = ['-y', name, ...rest];
  let surface = null;
  try {
    surface = await acquireStdio({ command: 'npx', args, env: {} }, {});
  } catch (e) {
    boot++;
    console.log(`✗ ${name}  (boot) ${String(e?.message ?? e).slice(0, 80)}`);
    continue;
  }
  try {
    const r = await scanSurface(surface);
    const threats = r.findings.filter((f) => !isCapabilityRule(f.ruleId) && f.severity !== 'info').length;
    ok++;
    console.log(`✓ ${name}  Trust ${r.score.grade}(${r.score.score}) · Cap ${r.capabilityProfile.level} · ${r.stats.tools}t · ${threats} threat findings`);
  } catch (e) {
    crashes++;
    console.log(`💥 SCANNER-BUG ${name}: ${String(e?.stack ?? e).split('\n')[0]}`);
  }
}

console.log(`\nok=${ok} boot-fail=${boot} scanner-crashes=${crashes}`);
if (crashes > 0) {
  console.error(`FAIL: ${crashes} scanner crash(es) — the scanner must never crash on a real server.`);
  process.exit(1);
}
