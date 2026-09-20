/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The curated "protected" MCP package list. Typosquatting is checked only
 * against this anchor set (never all-pairs), which is both fast and precise.
 * Weekly-download figures feed the download-anomaly gate: a near-miss on a
 * high-traffic name with near-zero downloads of its own is malicious, not a
 * coincidence.
 */

export interface ProtectedPackage {
  name: string;
  registry: 'npm' | 'pypi';
  /** Approximate weekly downloads (order of magnitude, for the anomaly gate). */
  weeklyDownloads?: number;
  official?: boolean;
}

export const PROTECTED_PACKAGES: ProtectedPackage[] = [
  // --- Official @modelcontextprotocol npm scope ---
  { name: '@modelcontextprotocol/sdk', registry: 'npm', weeklyDownloads: 42_800_000, official: true },
  { name: '@modelcontextprotocol/inspector', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/create-server', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-filesystem', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-memory', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-sequential-thinking', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-everything', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-github', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-gitlab', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-slack', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-postgres', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-puppeteer', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-brave-search', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-google-maps', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-google-drive', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-redis', registry: 'npm', official: true },
  { name: '@modelcontextprotocol/server-sentry', registry: 'npm', official: true },
  { name: 'mcp-remote', registry: 'npm', official: true },

  // --- Official PyPI ---
  { name: 'mcp', registry: 'pypi', official: true },
  { name: 'mcp-server-git', registry: 'pypi', official: true },
  { name: 'mcp-server-fetch', registry: 'pypi', official: true },
  { name: 'mcp-server-time', registry: 'pypi', official: true },
  { name: 'mcp-server-sqlite', registry: 'pypi', official: true },

  // --- Popular community / vendor (npm) with download weights ---
  { name: '@playwright/mcp', registry: 'npm', weeklyDownloads: 5_990_000 },
  { name: '@upstash/context7-mcp', registry: 'npm', weeklyDownloads: 524_000 },
  { name: '@notionhq/notion-mcp-server', registry: 'npm', weeklyDownloads: 126_000 },
  { name: 'firecrawl-mcp', registry: 'npm', weeklyDownloads: 93_000 },
  { name: '@sentry/mcp-server', registry: 'npm', weeklyDownloads: 85_000 },
  { name: 'figma-developer-mcp', registry: 'npm', weeklyDownloads: 76_000 },
  { name: '@supabase/mcp-server-supabase', registry: 'npm', weeklyDownloads: 65_000 },
  { name: '@wonderwhy-er/desktop-commander', registry: 'npm', weeklyDownloads: 43_000 },
  { name: 'tavily-mcp', registry: 'npm', weeklyDownloads: 28_000 },
  { name: 'exa-mcp-server', registry: 'npm', weeklyDownloads: 18_000 },
  { name: '@executeautomation/playwright-mcp-server', registry: 'npm', weeklyDownloads: 17_000 },
  { name: '@brave/brave-search-mcp-server', registry: 'npm', weeklyDownloads: 15_000 },
  { name: '@21st-dev/magic', registry: 'npm', weeklyDownloads: 13_000 },
  { name: '@stripe/mcp', registry: 'npm', weeklyDownloads: 11_000 },
  { name: '@browsermcp/mcp', registry: 'npm', weeklyDownloads: 9_000 },
  { name: '@heroku/mcp-server', registry: 'npm', weeklyDownloads: 6_000 },
  { name: '@cloudflare/mcp-server-cloudflare', registry: 'npm', weeklyDownloads: 2_000 },
];

/**
 * Fake official-scope / homoglyph scope patterns. Any package whose scope
 * matches one of these is impersonating the official namespace.
 */
export const FAKE_SCOPE_PATTERNS: RegExp[] = [
  /^@modlecontextprotocol\//i,
  /^@model-context-protocol\//i,
  /^@modelcontextprotocal\//i,
  /^@modelcontext-protocol\//i,
  /^@modelcontextprotocol-/i, // unscoped hyphen shadow of the scope
];

/** Bare (unscoped) names that shadow official *scoped* packages. */
export const UNSCOPED_SHADOWS = new Set<string>([
  'server-filesystem',
  'server-github',
  'server-memory',
  'server-slack',
  'server-postgres',
  'modelcontextprotocol-sdk',
]);

/**
 * Pre-computed known squats mapping a malicious/confusable name to the real
 * package it imitates (collapses several matchers to an instant hit).
 */
export const KNOWN_SQUATS: Record<string, string> = {
  'playwright-mcp': '@playwright/mcp',
  'playwright-mcp-server': '@playwright/mcp',
  'mcp-playwright': '@playwright/mcp',
  '@playwright/mcp-server': '@playwright/mcp',
  '@playwrite/mcp': '@playwright/mcp',
  'context7-mcp': '@upstash/context7-mcp',
  'notion-mcp-server': '@notionhq/notion-mcp-server',
  'firecrawl-mcp-server': 'firecrawl-mcp',
};

/** Combosquat suffixes stripped before comparison (e.g. `foo-js` ≈ `foo`). */
export const COMBOSQUAT_SUFFIXES = ['-js', '-py', '-core', '-utils', '-mcp', '-server', '-official', '-cli'];

/** Generic ecosystem tokens that can never be a squat BASE — `@vendor/mcp-server`
 *  strips to "mcp", which is not an impersonation of anyone. A combosquat residue
 *  matching one of these (or shorter than 5 chars) is ignored. */
export const GENERIC_COMBO_TOKENS = new Set([
  'mcp', 'server', 'client', 'sdk', 'api', 'core', 'tools', 'tool', 'app', 'cli', 'lib', 'utils', 'common', 'agent',
]);
