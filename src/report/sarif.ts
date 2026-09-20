/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * SARIF 2.1.0 output for GitHub code scanning ("Security" tab) and any SARIF
 * consumer. Each unique rule becomes a reportingDescriptor; each finding a result.
 */

import type { Finding, ScanReport, Severity } from '../types.js';
import { TOOL_VERSION } from '../version.js';

function level(sev: Severity): 'error' | 'warning' | 'note' | 'none' {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    case 'info':
      return 'none';
  }
}

function securitySeverity(sev: Severity): string {
  // GitHub uses a 0-10 scale to sort the Security tab.
  switch (sev) {
    case 'critical':
      return '9.5';
    case 'high':
      return '8.0';
    case 'medium':
      return '5.0';
    case 'low':
      return '3.0';
    case 'info':
      return '0.0';
  }
}

export function renderSarif(report: ScanReport): string {
  const rulesById = new Map<string, Finding>();
  for (const f of report.findings) if (!rulesById.has(f.ruleId)) rulesById.set(f.ruleId, f);

  const rules = [...rulesById.values()].map((f) => ({
    id: f.ruleId,
    name: f.ruleId,
    shortDescription: { text: f.title },
    fullDescription: { text: f.description.split('\n')[0] },
    helpUri: f.references?.[0],
    defaultConfiguration: { level: level(f.severity) },
    properties: {
      category: f.category,
      'security-severity': securitySeverity(f.severity),
      tags: ['security', 'mcp', f.category, ...(f.owasp ? [f.owasp] : [])],
    },
  }));

  const results = report.findings.map((f) => ({
    ruleId: f.ruleId,
    level: level(f.severity),
    message: {
      text:
        `${f.title}. ${f.description.split('\n')[0]}` +
        (f.evidence ? ` [evidence: ${f.evidence.slice(0, 120)}]` : '') +
        (f.remediation ? ` Remediation: ${f.remediation}` : ''),
    },
    locations: [
      {
        logicalLocations: [
          {
            name: f.location?.name ?? report.target.id,
            kind: f.location?.kind ?? 'server',
            fullyQualifiedName: [report.target.id, f.location?.kind, f.location?.name, f.location?.field]
              .filter(Boolean)
              .join('/'),
          },
        ],
      },
    ],
    properties: {
      confidence: f.confidence,
      category: f.category,
      owasp: f.owasp,
    },
  }));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'MCP Trust Checker',
            version: TOOL_VERSION,
            informationUri: 'https://github.com/illia-haidar/mcptrustchecker',
            rules,
          },
        },
        results,
        properties: {
          trustScore: report.score.score,
          grade: report.score.grade,
          capabilityLevel: report.capabilityProfile.level,
          coverageLevel: report.coverage.level,
          coverageCaveats: report.coverage.caveats,
          methodologyVersion: report.score.methodologyVersion,
          surfaceDigest: report.surfaceDigest,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
