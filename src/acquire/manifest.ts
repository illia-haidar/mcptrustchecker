/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Offline acquisition: build a normalized ServerSurface from a pre-generated
 * JSON manifest. Accepts several shapes so `mcptrustchecker scan tools.json` "just
 * works": a raw `tools/list` result, a full surface object, or a hand-written
 * `{ server, tools, prompts, resources }`.
 */

import type {
  JsonSchema,
  PromptDef,
  ResourceDef,
  ServerSurface,
  ToolAnnotations,
  ToolDef,
  TransportInfo,
} from '../types.js';

type AnyObj = Record<string, unknown>;

/** Coerce an untrusted transport object into typed, string-only fields. */
function normalizeTransport(raw: unknown): TransportInfo | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const t = raw as AnyObj;
  const kind = t.kind;
  const validKind = kind === 'stdio' || kind === 'http' || kind === 'sse' ? kind : 'unknown';
  return {
    kind: validKind,
    url: typeof t.url === 'string' ? t.url : undefined,
    command: typeof t.command === 'string' ? t.command : undefined,
    args: Array.isArray(t.args) ? t.args.filter((x): x is string => typeof x === 'string') : undefined,
    userControlledCommand: typeof t.userControlledCommand === 'boolean' ? t.userControlledCommand : undefined,
  };
}

function asArray(v: unknown): AnyObj[] {
  return Array.isArray(v) ? (v.filter((x) => x && typeof x === 'object') as AnyObj[]) : [];
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function normalizeTool(o: AnyObj): ToolDef | null {
  const name = str(o.name);
  if (!name) return null;
  return {
    name,
    title: str(o.title),
    description: str(o.description),
    inputSchema: (o.inputSchema ?? o.input_schema) as JsonSchema | undefined,
    outputSchema: (o.outputSchema ?? o.output_schema) as JsonSchema | undefined,
    annotations: o.annotations as ToolAnnotations | undefined,
  };
}

function normalizePrompt(o: AnyObj): PromptDef | null {
  const name = str(o.name);
  if (!name) return null;
  return {
    name,
    title: str(o.title),
    description: str(o.description),
    arguments: asArray(o.arguments).map((a) => ({
      name: str(a.name) ?? '',
      description: str(a.description),
      required: Boolean(a.required),
    })),
  };
}

function normalizeResource(o: AnyObj): ResourceDef {
  return {
    uri: str(o.uri),
    uriTemplate: str(o.uriTemplate),
    name: str(o.name),
    title: str(o.title),
    description: str(o.description),
    mimeType: str(o.mimeType),
  };
}

/** Build a surface from an arbitrary manifest object. */
export function surfaceFromManifest(input: unknown, origin: string, id?: string): ServerSurface {
  const root = (input && typeof input === 'object' ? input : {}) as AnyObj;
  const serverObj = (root.server ?? {}) as AnyObj;
  const meta = (root.serverInfo ?? root.server_info ?? {}) as AnyObj;

  const tools = asArray(root.tools).map(normalizeTool).filter((t): t is ToolDef => t !== null);
  const prompts = asArray(root.prompts).map(normalizePrompt).filter((p): p is PromptDef => p !== null);
  const resources = asArray(root.resources).map(normalizeResource);

  return {
    id: id ?? str(root.id) ?? origin,
    source: { kind: 'manifest', origin },
    server: {
      name: str(serverObj.name) ?? str(meta.name) ?? str(root.name),
      version: str(serverObj.version) ?? str(meta.version),
      title: str(serverObj.title),
      instructions: str(serverObj.instructions) ?? str(root.instructions),
      protocolVersion: str(root.protocolVersion),
      capabilities:
        (serverObj.capabilities as Record<string, unknown>) ??
        (root.capabilities as Record<string, unknown>) ??
        undefined,
    },
    tools,
    prompts,
    resources,
    transport: normalizeTransport(root.transport),
    packageMeta: root.packageMeta as ServerSurface['packageMeta'],
  };
}
