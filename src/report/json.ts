/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import type { ScanReport } from '../types.js';

/** Pretty JSON report (the machine-readable canonical form). */
export function renderJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
