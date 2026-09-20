/**
 * Embedding MCP Trust Checker as a library — the same deterministic engine that powers
 * the CLI, suitable for a marketplace, a platform gate, or a CI service.
 *
 *   npm i mcptrustchecker
 *   npx tsx examples/programmatic.ts
 */

import {
  surfaceFromManifest,
  scanSurface,
  renderBadge,
  renderMarkdown,
} from 'mcptrustchecker';

// A tools manifest as returned by an MCP `tools/list` (or hand-written).
const manifest = {
  server: { name: 'acme/notes-mcp', version: '1.0.0' },
  tools: [
    {
      name: 'read_note',
      description: 'Read a note by id.',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } } },
    },
    {
      name: 'fetch_url',
      description: 'Fetch a web page and return its text.',
      inputSchema: { type: 'object', properties: { url: { type: 'string' } } },
    },
    {
      name: 'send_email',
      description: 'Send an email to a recipient.',
      inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } } },
    },
  ],
};

async function main(): Promise<void> {
  const surface = surfaceFromManifest(manifest, 'acme/notes-mcp');
  const report = await scanSurface(surface, { config: { includeBuiltins: true } });

  // Headline numbers — deterministic and safe to store next to a listing.
  console.log(`Grade:       ${report.score.grade}`);
  console.log(`Trust Score: ${report.score.score}/100`);
  console.log(`Methodology: ${report.score.methodologyVersion}`);
  console.log(`Digest:      ${report.surfaceDigest.slice(0, 16)}…`);

  // Enumerated exfiltration primitives.
  for (const flow of report.toxicFlows) {
    console.log(`  toxic flow [${flow.severity}] ${flow.description}`);
  }

  // Gate a publication/listing.
  const publishable = report.score.grade <= 'B'; // 'A' or 'B' (string compare works A<B<…)
  console.log(`Publishable at ≥B: ${publishable}`);

  // Artifacts you can persist / display.
  const badge = JSON.parse(renderBadge(report)); // shields.io endpoint JSON
  console.log('Badge:', badge);

  // A Markdown summary (e.g. to attach to the listing or a PR).
  void renderMarkdown(report);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
