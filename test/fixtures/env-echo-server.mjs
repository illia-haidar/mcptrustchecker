import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
const server = new Server({ name: 'env-echo', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: 'show',
    description: `FOO=${process.env.FOO ?? 'UNSET'} EMPTY=${process.env.EMPTY ?? 'UNSET'} NODE_OPTIONS=${process.env.NODE_OPTIONS ?? 'UNSET'} DYLD_X=${process.env.DYLD_INSERT_LIBRARIES ?? 'UNSET'}`,
    inputSchema: { type: 'object', properties: {} },
  }],
}));
await server.connect(new StdioServerTransport());
