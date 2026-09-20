/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Known-CVE / advisory version matcher for MCP client / proxy / server
 * packages. A cheap, high-signal check that pure content scanners lack:
 * if a config pins a package to a version in a known-vulnerable range, say so.
 *
 * Ranges are intentionally simple (`< x` or `<= x`). Keep this list current;
 * it is data, not logic.
 */

import type { Severity } from '../types.js';

export interface KnownVuln {
  id: string;
  package: string;
  registry: 'npm' | 'pypi';
  /** Vulnerable when installed version < this (exclusive). */
  ltExclusive?: string;
  /** Vulnerable when installed version <= this (inclusive). */
  leInclusive?: string;
  severity: Severity;
  cvss?: number;
  title: string;
  reference: string;
}

export const KNOWN_VULNS: KnownVuln[] = [
  {
    id: 'CVE-2025-6514',
    package: 'mcp-remote',
    registry: 'npm',
    ltExclusive: '0.1.16',
    severity: 'critical',
    cvss: 9.6,
    title: 'mcp-remote OS command injection via crafted authorization endpoint',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-6514',
  },
  {
    id: 'CVE-2025-49596',
    package: '@modelcontextprotocol/inspector',
    registry: 'npm',
    ltExclusive: '0.14.1',
    severity: 'critical',
    cvss: 9.4,
    title: 'MCP Inspector DNS-rebinding leads to RCE on the developer host',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-49596',
  },
  {
    id: 'GHSA-git-mcp-cyanheads',
    package: '@cyanheads/git-mcp-server',
    registry: 'npm',
    leInclusive: '2.1.4',
    severity: 'high',
    title: 'git-mcp-server argument injection in git commands',
    reference: 'https://github.com/advisories',
  },
  {
    id: 'GHSA-mcp-server-git',
    package: 'mcp-server-git',
    registry: 'pypi',
    ltExclusive: '2025.12.18',
    severity: 'high',
    title: 'mcp-server-git path traversal / argument injection',
    reference: 'https://github.com/advisories',
  },
];
