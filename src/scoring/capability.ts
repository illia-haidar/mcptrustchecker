/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability (blast-radius) rating — the second axis, independent of the trust
 * grade. It answers "how much could this server do if the model driving it were
 * prompt-injected?" A legitimate, well-behaved server can still be high- or
 * critical-capability; that is not a mark against its trustworthiness, it is
 * information for deciding how much access to grant.
 */

import type { CapabilityLevel, CapabilityProfile, CapabilityTag, Finding, ToolCapability, ToxicFlow } from '../types.js';

const ORDER: CapabilityLevel[] = ['minimal', 'moderate', 'high', 'critical'];

function atLeast(current: CapabilityLevel, candidate: CapabilityLevel): CapabilityLevel {
  return ORDER.indexOf(candidate) > ORDER.indexOf(current) ? candidate : current;
}

export function computeCapabilityProfile(
  capabilities: ToolCapability[],
  flows: ToxicFlow[],
  findings: Finding[] = [],
): CapabilityProfile {
  const tagSet = new Set<CapabilityTag>(capabilities.flatMap((c) => c.tags));
  // The source scan sees what the implementation DOES even when the tool
  // metadata under-declares it: code that spawns processes is code-exec
  // capability, a hardcoded endpoint is an external sink, a credential-path
  // read is a sensitive source. Feeding these into the same tag set keeps one
  // capability model for both axes of evidence.
  const ruleTag: Record<string, CapabilityTag> = {
    'MTC-SRC-001': 'code-exec',
    'MTC-SRC-002': 'code-exec',
    // SRC-010 (dynamic eval of a non-literal) is code-exec capability, same as
    // SRC-001 — moved off the threat axis (see CAPABILITY_RULES); it must still
    // raise the blast radius here or the eval sink would vanish from both axes.
    'MTC-SRC-010': 'code-exec',
    'MTC-SRC-003': 'external-sink',
    'MTC-SRC-006': 'sensitive-source',
  };
  for (const f of findings) {
    // A source finding downgraded to packaging/dev tooling (non-runtime) ships,
    // but it is not the server's request-handling surface — it must NOT inflate
    // the client's blast radius. Without this the tooling downgrade is cosmetic:
    // the finding still buys the full -6/-10 capability penalty.
    if (f.data?.nonRuntime) continue;
    const tag = ruleTag[f.ruleId];
    if (tag) tagSet.add(tag);
  }
  const has = (t: CapabilityTag): boolean => tagSet.has(t);
  const reasons: string[] = [];
  let level: CapabilityLevel = 'minimal';

  const bump = (candidate: CapabilityLevel, reason: string): void => {
    level = atLeast(level, candidate);
    reasons.push(reason);
  };

  if (has('untrusted-input')) bump('moderate', 'ingests untrusted external content (a prompt-injection entry point)');
  if (has('external-sink')) bump('moderate', 'can send data / act on an external service');
  if (has('file-write')) bump('moderate', 'can create, modify or delete files');
  if (has('sensitive-source')) bump('moderate', 'reads sensitive or local data');

  if (has('sensitive-source') && (has('external-sink') || has('code-exec'))) {
    bump('high', 'has a read → egress path (a data-exfiltration surface)');
  }
  if (has('code-exec')) bump('high', 'can execute shell commands or code');

  const roleComplete = (f: ToxicFlow): boolean =>
    f.untrustedInput.length > 0 && f.sensitiveSource.length > 0 && f.externalSink.length > 0;
  const selfContained = flows.some((f) => f.selfContained && roleComplete(f));
  const crossTrifecta = flows.some((f) => !f.selfContained && roleComplete(f));

  if (crossTrifecta) bump('high', 'untrusted-input, sensitive-source and egress co-exist across tools (toxic-flow surface)');
  if (selfContained) bump('critical', 'a single tool completes the exfiltration trifecta by itself');
  // CRITICAL from code-exec + untrusted-input requires an actual LINKAGE, not mere
  // co-occurrence: a real toxic flow connecting the two, or a runtime assembled-
  // command finding (MTC-SRC-009). Co-presence alone stays at `high` (-6) — else
  // ~700 packages eat an extra -4 for two unrelated tools existing in one server.
  const assembledCommand = findings.some((f) => f.ruleId === 'MTC-SRC-009' && !f.data?.nonRuntime);
  if (has('code-exec') && has('untrusted-input') && (selfContained || crossTrifecta || assembledCommand)) {
    bump('critical', 'untrusted input can reach code execution');
  }

  // De-duplicate reasons while preserving order.
  const seen = new Set<string>();
  const uniqueReasons = reasons.filter((r) => (seen.has(r) ? false : (seen.add(r), true)));

  return { level, reasons: uniqueReasons, tags: [...tagSet] };
}
