/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Cross-server tool-name collision / shadowing. When a scan covers several
 * servers (e.g. a whole client config), a malicious server can register a tool
 * whose name collides with — or is a homoglyph/near-miss of — a trusted
 * server's tool, hijacking selection by connection order or embedding rank
 * (SAFE-T1004 / T1008). This complements description-level shadowing
 * (MTC-INJ-SHADOW-1) with name-level collision across the server set.
 */

import type { Detector, DetectorContext, Finding } from '../types.js';
import { skeleton } from '../data/confusables.js';
import { damerauLevenshtein } from '../util/distance.js';

export const collisionDetector: Detector = {
  id: 'collision',
  stage: 4,
  title: 'Cross-server tool-name collision',
  run(ctx: DetectorContext): Finding[] {
    const siblings = ctx.siblingTools ?? [];
    if (siblings.length === 0) return [];
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const tool of ctx.surface.tools) {
      if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string') continue;
      const nameLower = tool.name.toLowerCase();
      const skel = skeleton(tool.name);
      for (const sib of siblings) {
        const sibLower = sib.name.toLowerCase();
        const key = [tool.name, sib.server, sib.name].join('|');
        if (seen.has(key)) continue;

        let hit: { severity: Finding['severity']; confidence: Finding['confidence']; why: string } | null = null;
        if (nameLower === sibLower) {
          hit = { severity: 'high', confidence: 'strong', why: 'an identical name' };
        } else if (skel === skeleton(sib.name)) {
          hit = { severity: 'high', confidence: 'strong', why: 'a homoglyph/confusable name' };
        } else if (tool.name.length >= 4 && damerauLevenshtein(nameLower, sibLower) <= 1) {
          hit = { severity: 'medium', confidence: 'heuristic', why: 'a near-identical name (edit distance 1)' };
        }
        if (!hit) continue;
        seen.add(key);
        findings.push({
          ruleId: 'MTC-INJ-SHADOW-2',
          title: `Tool "${tool.name}" collides with a tool on server "${sib.server}"`,
          category: 'injection',
          severity: hit.severity,
          confidence: hit.confidence,
          description:
            `This server's tool "${tool.name}" shares ${hit.why} with "${sib.name}" on server "${sib.server}". ` +
            `Colliding tool names let a server hijack tool selection (by connection order or embedding rank) and ` +
            `shadow a trusted tool.`,
          remediation: 'Namespace tools per server and require the user to confirm which server a tool belongs to; distrust duplicate names.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM01:2025 Prompt Injection',
          data: { collidesWith: sib },
        });
      }
    }
    return findings;
  },
};
