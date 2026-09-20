/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 4 — Toxic-flow graph (the flagship analysis).
 *
 * The "lethal trifecta": an agent session that can reach
 *   UNTRUSTED_INPUT  →  SENSITIVE_DATA_SOURCE  →  EXTERNAL_SINK
 * holds an exfiltration primitive, whether those roles live in one tool or are
 * composed across several tools and the client's built-ins.
 *
 * Honesty contract: static analysis proves the primitive *exists* (capability
 * co-presence), not that a runtime chain *will* execute. Findings are worded
 * accordingly, and only a single-tool completed trifecta is `confirmed`.
 */

import type {
  DetectorContext,
  Finding,
  ServerSurface,
  ToolCapability,
  ToxicFlow,
} from '../types.js';
import { CLIENT_BUILTINS } from '../data/capabilityLexicon.js';
import { representativeTrifectaPath, representativeExfilPath, renderPath, type FlowPath } from './flowGraph.js';

interface FlowAnalysis {
  flows: ToxicFlow[];
  findings: Finding[];
}

const FLOW_REFS: string[] = [];

function isSinkCap(c: ToolCapability): boolean {
  return c.tags.includes('external-sink') || c.tags.includes('code-exec');
}

export function analyzeToxicFlows(ctx: DetectorContext): FlowAnalysis {
  const caps: ToolCapability[] = [...ctx.capabilities];
  if (ctx.config.includeBuiltins) {
    for (const b of CLIENT_BUILTINS) caps.push({ tool: b.tool, tags: b.tags, reasons: {} });
  }

  const untrusted = caps.filter((c) => c.tags.includes('untrusted-input')).map((c) => c.tool);
  const sources = caps.filter((c) => c.tags.includes('sensitive-source')).map((c) => c.tool);
  const sinks = caps.filter(isSinkCap).map((c) => c.tool);

  const selfTrifecta = caps.filter(
    (c) => c.tags.includes('untrusted-input') && c.tags.includes('sensitive-source') && isSinkCap(c),
  );
  const selfTrifectaNames = new Set(selfTrifecta.map((c) => c.tool));
  const selfExfil = caps.filter(
    (c) =>
      !selfTrifectaNames.has(c.tool) &&
      c.tags.includes('sensitive-source') &&
      isSinkCap(c) &&
      !c.tags.includes('untrusted-input'),
  );

  const fullTrifectaPresent = untrusted.length > 0 && sources.length > 0 && sinks.length > 0;
  const flows: ToxicFlow[] = [];
  const findings: Finding[] = [];
  let flowSeq = 0;
  const nextId = (): string => `flow-${++flowSeq}`;

  // 1) Self-contained completed trifecta — one tool ingests, reads, and exfiltrates.
  for (const c of selfTrifecta) {
    const id = nextId();
    flows.push({
      id,
      severity: 'critical',
      confidence: 'confirmed',
      untrustedInput: [c.tool],
      sensitiveSource: [c.tool],
      externalSink: [c.tool],
      selfContained: true,
      description: `Tool "${c.tool}" alone ingests untrusted input, reads sensitive data, and can send it out.`,
    });
    findings.push({
      ruleId: 'MTC-FLOW-001',
      title: `Self-contained exfiltration primitive: "${c.tool}"`,
      category: 'exfiltration',
      severity: 'critical',
      confidence: 'confirmed',
      description:
        `Tool "${c.tool}" holds all three trifecta roles by itself (untrusted-input + sensitive-source + ` +
        `external-sink). A single call can pull attacker-controlled content, read private data, and exfiltrate ` +
        `it — no composition required.`,
      remediation: 'Split responsibilities across separate, individually-consented tools; never combine untrusted input, secret reads, and egress in one tool.',
      location: { kind: 'flow', name: c.tool },
      owasp: 'LLM02:2025 Sensitive Information Disclosure',
      references: FLOW_REFS,
      data: { tags: c.tags },
    });
  }

  // 2) Cross-tool completed trifecta (only if no single tool already completes it).
  if (fullTrifectaPresent && selfTrifecta.length === 0) {
    const id = nextId();
    const p: FlowPath | null = representativeTrifectaPath(caps, ctx.surface.tools);
    const chain = p ? renderPath(p) : `[${untrusted.join(', ')}] → [${sources.join(', ')}] → [${sinks.join(', ')}]`;
    flows.push({
      id,
      severity: 'critical',
      confidence: 'strong',
      untrustedInput: untrusted,
      sensitiveSource: sources,
      externalSink: sinks,
      selfContained: false,
      path: p?.path,
      pathWired: p?.wired,
      description: `A cross-tool exfiltration chain exists: ${chain}.`,
    });
    findings.push({
      ruleId: 'MTC-FLOW-002',
      title: 'Completed toxic-flow trifecta across tools',
      category: 'exfiltration',
      severity: 'critical',
      confidence: 'strong',
      description:
        `This server (with${ctx.config.includeBuiltins ? '' : 'out'} client built-ins) exposes a complete ` +
        `data-exfiltration chain: ${chain}. Untrusted input is ingested, private data is read, and it can be sent ` +
        `to an external sink` +
        (p?.wired
          ? ` — and at least one leg is a direct schema wire (⇒), where a producer's output drops straight into a ` +
            `free-text parameter of the next tool, so the chain needs little agent cooperation.`
          : ` via the agent composing the tools (→).`) +
        ` Static analysis proves the primitive exists, not that a specific run will occur.`,
      remediation: 'Remove one leg of the trifecta: isolate untrusted-input tools from secret-reading tools and from egress tools, or require human approval between them.',
      location: { kind: 'flow', name: p?.path?.join(' → ') },
      owasp: 'LLM02:2025 Sensitive Information Disclosure',
      references: FLOW_REFS,
      data: { untrusted, sources, sinks, path: p?.path, edges: p?.edges, wired: p?.wired },
    });
  }

  // 3) Self-contained exfil (reads secrets + can egress, no untrusted input leg).
  for (const c of selfExfil) {
    const id = nextId();
    flows.push({
      id,
      severity: 'high',
      confidence: 'strong',
      untrustedInput: [],
      sensitiveSource: [c.tool],
      externalSink: [c.tool],
      selfContained: true,
      description: `Tool "${c.tool}" both reads sensitive data and can send it externally.`,
    });
    findings.push({
      ruleId: 'MTC-FLOW-003',
      title: `Read-and-egress in one tool: "${c.tool}"`,
      category: 'exfiltration',
      severity: 'high',
      confidence: 'strong',
      description:
        `Tool "${c.tool}" can both read sensitive data and send data to an external destination. Even without an ` +
        `explicit untrusted-input leg, this is a single-call data-exfiltration path if the model is ever ` +
        `manipulated.`,
      remediation: 'Separate reading from sending; require explicit user confirmation before egress of file/secret contents.',
      location: { kind: 'flow', name: c.tool },
      owasp: 'LLM02:2025 Sensitive Information Disclosure',
      references: FLOW_REFS,
      data: { tags: c.tags },
    });
  }

  // 4) Cross-tool data-out path: a source tool and a *different* sink tool exist.
  const crossExfil = !fullTrifectaPresent && sources.some((s) => sinks.some((k) => k !== s));
  if (crossExfil) {
    const id = nextId();
    const p = representativeExfilPath(caps, ctx.surface.tools);
    flows.push({
      id,
      severity: 'high',
      confidence: 'strong',
      untrustedInput: [],
      sensitiveSource: sources,
      externalSink: sinks,
      selfContained: false,
      path: p?.path,
      pathWired: p?.wired,
      description: `A sensitive-source → external-sink chain exists: ${p ? renderPath(p) : ''}.`,
    });
    findings.push({
      ruleId: 'MTC-FLOW-004',
      title: 'Sensitive-source and external-sink co-exist',
      category: 'exfiltration',
      severity: 'high',
      confidence: 'strong',
      description:
        `Tools that read sensitive data ([${sources.join(', ')}]) and tools that can send data out ` +
        `([${sinks.join(', ')}]) are exposed together. An agent can move private data to the sink.`,
      remediation: 'Keep secret-reading and egress capabilities on separate, separately-approved servers.',
      location: { kind: 'flow', name: `${sources[0] ?? '?'} → ${sinks.find((k) => !sources.includes(k)) ?? sinks[0] ?? '?'}` },
      evidence: `sources [${sources.join(', ')}] → sinks [${sinks.join(', ')}]`.slice(0, 160),
      owasp: 'LLM02:2025 Sensitive Information Disclosure',
      references: FLOW_REFS,
      data: { sources, sinks },
    });
  }

  // 5) Untrusted input reaching an action sink (no sensitive source involved).
  if (!fullTrifectaPresent && untrusted.length > 0 && sinks.length > 0 && sources.length === 0) {
    const id = nextId();
    flows.push({
      id,
      severity: 'medium',
      confidence: 'strong',
      untrustedInput: untrusted,
      sensitiveSource: [],
      externalSink: sinks,
      selfContained: false,
      description: 'Untrusted input can drive an external action even though no sensitive source is exposed.',
    });
    findings.push({
      ruleId: 'MTC-FLOW-005',
      title: 'Untrusted input can drive an external action',
      category: 'exfiltration',
      severity: 'medium',
      confidence: 'strong',
      description:
        `Untrusted-input tools ([${untrusted.join(', ')}]) co-exist with external-action tools ([${sinks.join(', ')}]). ` +
        `A prompt injection could cause unwanted external actions, though no direct sensitive-data leak path was found.`,
      remediation: 'Require confirmation for state-changing/egress actions triggered after processing untrusted content.',
      location: { kind: 'flow', name: `${untrusted[0] ?? '?'} → ${sinks[0] ?? '?'}` },
      evidence: `untrusted [${untrusted.join(', ')}] → sinks [${sinks.join(', ')}]`.slice(0, 160),
      owasp: 'LLM06:2025 Excessive Agency',
      references: FLOW_REFS,
      data: { untrusted, sinks },
    });
  }

  return { flows, findings };
}

/** Convenience wrapper matching the pipeline stage description. */
export function toxicFlowStage(surface: ServerSurface, capabilities: ToolCapability[], config: DetectorContext['config']): FlowAnalysis {
  return analyzeToxicFlows({ surface, capabilities, config });
}
