/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
// A real MCP server over stdio that answers tools/list, prompts/list and
// resources/list with the definitions in surface-live.json, verbatim — so a
// test can compare a live scan's `report.surface` with the exact answer.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const fixture = JSON.parse(readFileSync(join(import.meta.dirname, 'surface-live.json'), 'utf8'));

const server = new Server(fixture.server, {
  capabilities: { tools: {}, prompts: {}, resources: {} },
  instructions: 'Server instructions are read by the detectors, not repeated in report.surface.',
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: fixture.tools }));
server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: fixture.prompts }));
server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: fixture.resources }));

await server.connect(new StdioServerTransport());
