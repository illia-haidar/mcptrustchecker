/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Config resolution. MCP Trust Checker runs with sensible zero-config defaults; a
 * `mcptrustchecker.config.json` (or `.mcptrustcheckerrc.json`) can override any of them.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ResolvedConfig, McpTrustCheckerConfig } from './types.js';

export const DEFAULT_CONFIG: ResolvedConfig = {
  disabledRules: [],
  allowlist: [],
  failUnder: 0,
  includeBuiltins: false,
  protectedPackages: [],
  invisibleCharThreshold: 5,
  suppress: [],
  minGrade: undefined,
  lockfile: undefined,
  policy: undefined,
  publishToken: undefined,
  publishUrl: undefined,
  publishCategory: undefined,
};

const CONFIG_FILENAMES = ['mcptrustchecker.config.json', '.mcptrustcheckerrc.json', '.mcptrustcheckerrc'];
const IGNORE_FILE = '.mtcignore';

/** Load a config object from the first config file found in `cwd`, if any. */
export function loadConfigFile(cwd: string = process.cwd()): McpTrustCheckerConfig {
  let cfg: McpTrustCheckerConfig = {};
  for (const name of CONFIG_FILENAMES) {
    const path = join(cwd, name);
    if (existsSync(path)) {
      try {
        cfg = JSON.parse(readFileSync(path, 'utf8')) as McpTrustCheckerConfig;
      } catch (err) {
        throw new Error(`Failed to parse config file ${path}: ${(err as Error).message}`);
      }
      break;
    }
  }
  // A standalone .mtcignore baseline merges into (and extends) config suppressions.
  const ignore = loadIgnoreFile(cwd);
  if (ignore && ignore.length) cfg = { ...cfg, suppress: [...(cfg.suppress ?? []), ...ignore] };
  return cfg;
}

/** Load a config from an explicit file path (errors clearly if missing/malformed). */
export function loadConfigFromPath(path: string): McpTrustCheckerConfig {
  if (!existsSync(path)) throw new Error(`Config file not found: ${path}`);
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as McpTrustCheckerConfig;
  } catch (err) {
    throw new Error(`Failed to parse config file ${path}: ${(err as Error).message}`);
  }
}

/** Merge a partial config over the defaults into a fully-resolved config. */
export function resolveConfig(partial: McpTrustCheckerConfig = {}): ResolvedConfig {
  return {
    disabledRules: partial.disabledRules ?? DEFAULT_CONFIG.disabledRules,
    allowlist: partial.allowlist ?? DEFAULT_CONFIG.allowlist,
    failUnder: partial.failUnder ?? DEFAULT_CONFIG.failUnder,
    includeBuiltins: partial.includeBuiltins ?? DEFAULT_CONFIG.includeBuiltins,
    protectedPackages: partial.protectedPackages ?? DEFAULT_CONFIG.protectedPackages,
    invisibleCharThreshold: partial.invisibleCharThreshold ?? DEFAULT_CONFIG.invisibleCharThreshold,
    suppress: partial.suppress ?? DEFAULT_CONFIG.suppress,
    minGrade: partial.minGrade,
    lockfile: partial.lockfile,
    policy: partial.policy,
    publishToken: partial.publishToken,
    publishUrl: partial.publishUrl,
    publishCategory: partial.publishCategory,
  };
}

/** Load a standalone `.mtcignore` baseline file (JSON array of suppressions), if present. */
export function loadIgnoreFile(cwd: string = process.cwd()): McpTrustCheckerConfig['suppress'] {
  const path = join(cwd, IGNORE_FILE);
  if (!existsSync(path)) return [];
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    throw new Error(`Failed to parse ${IGNORE_FILE}: ${(err as Error).message}`);
  }
}
