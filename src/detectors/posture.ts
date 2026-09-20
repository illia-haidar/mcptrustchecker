/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 6 — Transport / host posture + known-CVE version matcher.
 * Cheap, high-value checks that content-only scanners miss.
 */

import type { Detector, DetectorContext, Finding, PackageMeta } from '../types.js';
import { KNOWN_VULNS } from '../data/knownCves.js';
import { compareVersions } from '../util/distance.js';

/** Match package metadata against the known-vuln table. Exported for tests. */
export function matchKnownVulns(meta: PackageMeta): Finding[] {
  const findings: Finding[] = [];
  if (typeof meta.name !== 'string' || typeof meta.version !== 'string') return findings;
  for (const v of KNOWN_VULNS) {
    if (v.package !== meta.name) continue;
    const version = meta.version;
    // Only compare a CONCRETE version. "latest", "*", "^1.2.0", ranges etc. would
    // otherwise parse to [0] and be flagged as vulnerable — a false CVE.
    if (!/^v?\d/.test(version)) continue;
    const vulnerable =
      (v.ltExclusive !== undefined && compareVersions(version, v.ltExclusive) < 0) ||
      (v.leInclusive !== undefined && compareVersions(version, v.leInclusive) <= 0);
    if (!vulnerable) continue;
    findings.push({
      ruleId: 'MTC-NET-001',
      title: `Known-vulnerable version: ${v.package}@${version} (${v.id})`,
      category: 'supply-chain',
      severity: v.severity,
      confidence: 'confirmed',
      description:
        `${v.package}@${version} is in the vulnerable range for ${v.id}${v.cvss ? ` (severity ${v.cvss})` : ''}: ` +
        `${v.title}.`,
      remediation: `Upgrade ${v.package} to a fixed release.`,
      location: { kind: 'package', name: v.package },
      references: [v.reference],
      owasp: 'LLM03:2025 Supply Chain',
      data: { cve: v.id, version },
    });
  }
  return findings;
}

export const postureDetector: Detector = {
  id: 'posture',
  stage: 6,
  title: 'Transport & host posture',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const t = ctx.surface.transport;

    if (t) {
      if (t.userControlledCommand) {
        findings.push({
          ruleId: 'MTC-NET-002',
          title: 'stdio command is user/metadata-controlled without an allowlist',
          category: 'network',
          severity: 'critical',
          confidence: 'confirmed',
          description:
            'The stdio transport spawns a command taken from untrusted configuration/metadata without an ' +
            'executable allowlist. This is the systemic MCP stdio-RCE class: launching the server runs arbitrary code.',
          remediation: 'Allowlist the executable to {npx,uvx,python,python3,node,docker,deno} and never spawn names taken verbatim from untrusted metadata.',
          location: { kind: 'transport' },
          owasp: 'LLM05:2025 Improper Output Handling',
        });
      }

      if (t.kind === 'http' && typeof t.url === 'string' && t.url.startsWith('http://')) {
        findings.push({
          ruleId: 'MTC-NET-003',
          title: 'Server reached over plaintext HTTP',
          category: 'network',
          severity: 'medium',
          confidence: 'confirmed',
          description: `The endpoint ${t.url} uses plaintext HTTP; tool traffic and any tokens are exposed on the wire.`,
          remediation: 'Use HTTPS for all remote MCP transports.',
          location: { kind: 'transport' },
          owasp: 'LLM03:2025 Supply Chain',
        });
      }

      if (typeof t.url === 'string') {
        try {
          const host = new URL(t.url).hostname;
          const isLocal = ['localhost', '127.0.0.1', '::1'].includes(host);
          if (isLocal) {
            findings.push({
              ruleId: 'MTC-NET-006',
              title: 'Local HTTP/SSE MCP server — verify Origin validation (DNS rebinding)',
              category: 'network',
              severity: 'low',
              confidence: 'heuristic',
              description:
                `A browser-reachable local MCP server (${host}) is exposed to DNS-rebinding attacks unless it ` +
                `validates the Host/Origin header — which static analysis cannot confirm.`,
              remediation: 'Ensure the server allowlists Origin/Host, or use the SDK version that adds rebinding protection.',
              location: { kind: 'transport' },
            });
          }
          if (host === '0.0.0.0') {
            findings.push({
              ruleId: 'MTC-NET-004',
              title: 'Server bound to 0.0.0.0',
              category: 'network',
              severity: 'medium',
              confidence: 'strong',
              description: 'Binding to 0.0.0.0 exposes the MCP server on all interfaces; ensure authentication is enforced.',
              remediation: 'Bind to localhost for local servers, or require auth for remote exposure.',
              location: { kind: 'transport' },
            });
          } else if (!isLocal) {
            // Remote host — worth a hygiene note about auth being out-of-scope for static analysis.
            findings.push({
              ruleId: 'MTC-NET-005',
              title: 'Remote HTTP MCP endpoint',
              category: 'network',
              severity: 'info',
              confidence: 'strong',
              description: `Remote endpoint ${host}. MCP Trust Checker does not test server-side authentication/authorization; verify the endpoint requires auth.`,
              location: { kind: 'transport' },
            });
          }
        } catch {
          /* not a parseable URL — ignore */
        }
      }
    }

    if (ctx.surface.packageMeta) findings.push(...matchKnownVulns(ctx.surface.packageMeta));

    return findings;
  },
};
