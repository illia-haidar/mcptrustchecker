import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { resolveConfig } from '../src/config.js';
import { extractCapabilities } from '../src/util/capabilities.js';
import type { DetectorContext, ServerSurface, ToolDef, McpTrustCheckerConfig } from '../src/types.js';

export function makeSurface(partial: Partial<ServerSurface> & { tools?: ToolDef[] } = {}): ServerSurface {
  return {
    id: partial.id ?? 'test-server',
    source: partial.source ?? { kind: 'manifest', origin: 'test' },
    server: partial.server ?? { name: 'test-server' },
    tools: partial.tools ?? [],
    prompts: partial.prompts ?? [],
    resources: partial.resources ?? [],
    transport: partial.transport,
    packageMeta: partial.packageMeta,
    sourceFiles: partial.sourceFiles,
    toolProvenance: partial.toolProvenance,
  };
}

export function buildCtx(surface: ServerSurface, config: McpTrustCheckerConfig = {}): DetectorContext {
  const resolved = resolveConfig(config);
  return { surface, config: resolved, capabilities: extractCapabilities(surface, resolved) };
}

/** Encode a string into the Unicode Tags block (the smuggling channel). */
export function toTags(text: string): string {
  return [...text].map((ch) => String.fromCodePoint(0xe0000 + (ch.codePointAt(0)! & 0x7f))).join('');
}

export function loadFixture(name: string): unknown {
  return JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', name), 'utf8'));
}
