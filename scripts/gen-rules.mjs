#!/usr/bin/env node
/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Generates docs/rules.md from RULE_CATALOG — the single source of truth — so
 * the docs can never drift from the code. Run after adding/renaming a rule:
 *   npm run docs:rules
 * A test (test/rules-doc.test.ts) fails CI if the doc is out of date.
 *
 * Requires `npm run build` first (imports from dist/).
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { RULE_CATALOG } from '../dist/data/ruleCatalog.js';
import { isCapabilityRule } from '../dist/scoring/model.js';

const CATEGORY_TITLES = {
  injection: 'Injection, Unicode & shadowing',
  exfiltration: 'Exfiltration & toxic flow',
  permissions: 'Capability & permissions',
  'supply-chain': 'Supply chain',
  network: 'Transport & network posture',
  hygiene: 'Metadata hygiene',
};
const ORDER = ['injection', 'exfiltration', 'permissions', 'supply-chain', 'network', 'hygiene'];

export function renderRulesDoc() {
  const esc = (s) => String(s).replace(/\|/g, '\\|');
  let out = `# Rule catalogue

Every rule MCP Trust Checker can emit (${RULE_CATALOG.length} total). Run \`mcptrustchecker rules\` for the same list, or \`mcptrustchecker explain <id>\` for one rule.

Rules marked **[capability]** describe blast-radius and raise the Capability level; they do **not** lower the Trust grade. Rules of severity \`info\` carry weight 0 and are filtered out before any penalty — they report a coverage or hygiene fact the reader needs, and deliberately move no points. Everything else is a scored trust threat.

<!-- GENERATED FROM src/data/ruleCatalog.ts — do not edit by hand. Run: npm run docs:rules -->
`;
  for (const cat of ORDER) {
    const rules = RULE_CATALOG.filter((r) => r.category === cat);
    if (!rules.length) continue;
    out += `\n## ${CATEGORY_TITLES[cat] ?? cat}\n\n| Rule | Severity | Title | What it means |\n| --- | --- | --- | --- |\n`;
    for (const r of rules) {
      const cap = isCapabilityRule(r.id) ? ' **[capability]**' : '';
      out += `| \`${r.id}\` | ${r.severity} | ${esc(r.title)} | ${esc(r.summary)}${cap} |\n`;
    }
  }
  return out;
}

// Written only when invoked directly (not when imported by the drift test).
if (process.argv[1] && process.argv[1].endsWith('gen-rules.mjs')) {
  const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'rules.md');
  writeFileSync(out, renderRulesDoc());
  console.log(`wrote ${RULE_CATALOG.length} rules → ${out}`);
}
