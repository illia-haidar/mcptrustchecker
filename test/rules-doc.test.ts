import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { RULE_CATALOG } from '../src/data/ruleCatalog.js';

// docs/rules.md is generated from RULE_CATALOG (npm run docs:rules). This gate
// fails CI if the doc drifts from the code in either direction.

const doc = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'rules.md'), 'utf8');

test('every catalog rule (id + title) is documented in docs/rules.md', () => {
  const missing: string[] = [];
  for (const r of RULE_CATALOG) {
    const idOk = doc.includes(`\`${r.id}\``);
    const titleOk = doc.includes(r.title.replace(/\|/g, '\\|'));
    if (!idOk || !titleOk) missing.push(`${r.id}${idOk ? '' : ' (id)'}${titleOk ? '' : ' (title)'}`);
  }
  assert.deepEqual(missing, [], `stale docs/rules.md — run "npm run docs:rules". Missing: ${missing.join(', ')}`);
});

test('docs/rules.md contains no rule id that is absent from the catalog (no stale entries)', () => {
  const inDoc = [...doc.matchAll(/`(MTC-[A-Z0-9-]+)`/g)].map((m) => m[1]);
  const catalog = new Set(RULE_CATALOG.map((r) => r.id));
  const orphans = [...new Set(inDoc)].filter((id) => !catalog.has(id));
  assert.deepEqual(orphans, [], `docs/rules.md lists rules not in the catalog: ${orphans.join(', ')}`);
});

test('the documented rule count matches the catalog exactly', () => {
  const ids = new Set([...doc.matchAll(/`(MTC-[A-Z0-9-]+)`/g)].map((m) => m[1]));
  assert.equal(ids.size, RULE_CATALOG.length, `doc lists ${ids.size} rules, catalog has ${RULE_CATALOG.length}`);
});
