/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
// Fills in the `v116` column of test/controls-1.16.1.test.ts: the verdict the
// published 1.16.0 engine gives each row. Rows are written with '?' in that
// column; this numbers the placeholders, loads the suite without registering its
// tests, runs every row through the 1.16.0 build and writes the verdicts back as
// literals. Run it once for new rows; the values are frozen from then on.
//
//   node --import tsx test/controls-v116.mts <path to a 1.16.0 build's dist/>

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const dist = process.argv[2];
if (!dist) {
  console.error('usage: node --import tsx test/controls-v116.mts <1.16.0 dist directory>');
  process.exit(2);
}
const base = resolve(dist);
const version = JSON.parse(readFileSync(join(base, '..', 'package.json'), 'utf8')).version;
if (version !== '1.16.0') throw new Error(`${base} is ${version}, not 1.16.0`);

const file = join(import.meta.dirname, 'controls-1.16.1.test.ts');
let n = 0;
const numbered = readFileSync(file, 'utf8').replace(/'\?'/g, () => `'?${++n}'`);
writeFileSync(file, numbered);

process.env.MTC_CONTROLS_DUMP = '1';
const suite = await import(pathToFileURL(file).href);
const load = (p: string) => import(pathToFileURL(join(base, p)).href);
const { injectionDetector } = await load('detectors/injection.js');
const { resolveConfig } = await load('config.js');
const { extractCapabilities } = await load('util/capabilities.js');
const { readRegistrations } = await load('analysis/toolRegistry.js');

const ORDER = ['none', 'info', 'low', 'medium', 'high', 'critical'];
const schemaOf = (names: string[]) => ({ type: 'object', properties: Object.fromEntries(names.map((x) => [x, { type: 'string' }])) });

function prose(r: { rule: string; tool: string; text: string; schema?: string[] | null; siblings?: string[] }): string {
  const tools = [
    { name: r.tool, description: r.text, ...(r.schema ? { inputSchema: schemaOf(r.schema) } : {}) },
    ...(r.siblings ?? []).map((name) => ({ name, description: 'Stores values.', inputSchema: schemaOf(['value']) })),
  ];
  const surface = { id: 's', source: { kind: 'manifest', origin: 'test' }, server: { name: 's' }, tools, prompts: [], resources: [] };
  const config = resolveConfig({});
  let worst = 'none';
  for (const f of injectionDetector.run({ surface, config, capabilities: extractCapabilities(surface, config) })) {
    if (f.ruleId === `MTC-INJ-${r.rule}` && f.location.name === r.tool && ORDER.indexOf(f.severity) > ORDER.indexOf(worst)) worst = f.severity;
  }
  return worst;
}

function code(r: { tool: string; text: string; path: string }): string {
  const reg = readRegistrations({ path: r.path, content: r.text }).find((x: { name: string }) => x.name === r.tool);
  return reg?.behavior?.some((b: { tag: string }) => b.tag === 'external-sink') ? 'sink' : 'none';
}

const values = new Map<string, string>();
for (const list of Object.values(suite)) {
  if (!Array.isArray(list)) continue;
  for (const r of list) {
    if (typeof r?.v116 !== 'string' || !r.v116.startsWith('?')) continue;
    const v = r.rule === 'external-sink' ? code(r) : prose(r);
    const had = values.get(r.v116);
    if (had !== undefined && had !== v) throw new Error(`${r.v116} is shared by rows 1.16.0 reads differently`);
    values.set(r.v116, v);
  }
}
let missing = 0;
const filled = numbered.replace(/'(\?\d+)'/g, (whole, id: string) => {
  const v = values.get(id);
  if (v === undefined) missing++;
  return v === undefined ? "'?'" : `'${v}'`;
});
writeFileSync(file, filled);
console.log(`v116: ${values.size} filled, ${missing} placeholders not reached by any exported row`);
