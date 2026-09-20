/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Shields.io "endpoint" badge JSON. Host the output somewhere and point a
 * shields.io endpoint badge at it, or let the marketplace render it directly:
 *   ![trust](https://img.shields.io/endpoint?url=<raw-json-url>)
 */

import type { Grade, ScanReport } from '../types.js';

function color(grade: Grade): string {
  return { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' }[grade];
}

export interface ShieldsBadge {
  schemaVersion: 1;
  label: string;
  message: string;
  color: string;
}

export function renderBadge(report: ScanReport, label = 'mcptrustchecker'): string {
  const badge: ShieldsBadge = {
    schemaVersion: 1,
    label,
    message: `${report.score.grade} (${report.score.score})`,
    color: color(report.score.grade),
  };
  return JSON.stringify(badge);
}
