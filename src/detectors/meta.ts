/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Meta / hygiene checks about the scan itself — most importantly, flagging when
 * a surface is empty so a malformed or wrong-shape manifest is never mistaken
 * for a clean, safe server.
 */

import type { Detector, DetectorContext, Finding } from '../types.js';

export const metaDetector: Detector = {
  id: 'meta',
  stage: 0,
  title: 'Scan metadata',
  run(ctx: DetectorContext): Finding[] {
    const { surface } = ctx;
    const empty = surface.tools.length === 0 && surface.prompts.length === 0 && surface.resources.length === 0;
    // A package-only scan legitimately has no live surface; don't warn there.
    if (empty && surface.source.kind !== 'package') {
      return [
        {
          ruleId: 'MTC-META-001',
          title: 'Empty surface — nothing to analyze',
          category: 'hygiene',
          severity: 'info',
          confidence: 'strong',
          description:
            'No tools, prompts, or resources were found on this surface. This may mean the server exposes ' +
            'nothing, or that the input was not a recognizable MCP manifest. An empty surface is NOT a clean ' +
            'bill of health — there was simply nothing to score.',
          remediation: 'Confirm the target is the right manifest/endpoint and that the server actually advertises tools.',
          location: { kind: 'server' },
        },
      ];
    }
    return [];
  },
};
