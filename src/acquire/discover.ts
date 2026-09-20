/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Zero-config discovery of installed MCP client configs, so `mcptrustchecker` with no
 * arguments "just works" — the same one-command onboarding as the popular
 * scanners. All the supported clients share the `mcpServers`/`servers` map.
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { isClientConfig } from './clientConfig.js';

export interface DiscoveredConfig {
  client: string;
  path: string;
}

/** Candidate config locations across the common MCP clients and OSes. */
function candidates(): DiscoveredConfig[] {
  const home = homedir();
  const cwd = process.cwd();
  const appData = process.env.APPDATA;
  const list: (DiscoveredConfig | null)[] = [
    // Claude Desktop
    { client: 'Claude Desktop', path: join(home, 'Library/Application Support/Claude/claude_desktop_config.json') },
    { client: 'Claude Desktop', path: join(home, '.config/Claude/claude_desktop_config.json') },
    appData ? { client: 'Claude Desktop', path: join(appData, 'Claude/claude_desktop_config.json') } : null,
    // Claude Code
    { client: 'Claude Code', path: join(home, '.claude.json') },
    // Cursor
    { client: 'Cursor', path: join(home, '.cursor/mcp.json') },
    { client: 'Cursor (project)', path: join(cwd, '.cursor/mcp.json') },
    // Windsurf
    { client: 'Windsurf', path: join(home, '.codeium/windsurf/mcp_config.json') },
    // Continue
    { client: 'Continue', path: join(home, '.continue/config.json') },
    // VS Code (project) & generic project configs
    { client: 'VS Code (project)', path: join(cwd, '.vscode/mcp.json') },
    { client: 'project', path: join(cwd, '.mcp.json') },
  ];
  return list.filter((c): c is DiscoveredConfig => c !== null);
}

/** Return config files that exist AND parse as an MCP client config. */
export function discoverClientConfigs(): DiscoveredConfig[] {
  const found: DiscoveredConfig[] = [];
  const seen = new Set<string>();
  for (const c of candidates()) {
    if (seen.has(c.path) || !existsSync(c.path)) continue;
    seen.add(c.path);
    try {
      if (isClientConfig(JSON.parse(readFileSync(c.path, 'utf8')))) found.push(c);
    } catch {
      /* unreadable / not JSON — skip */
    }
  }
  return found;
}
