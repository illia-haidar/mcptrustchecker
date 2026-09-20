/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 3 — Capability findings. The capability *tags* are computed by the
 * engine and shared via context; here we turn them into findings:
 *  - dangerous capabilities (command/code execution, filesystem mutation);
 *  - annotation-vs-behavior mismatch, open-world + sensitive read, and missing
 *    destructiveHint (the annotation-truthfulness story);
 *  - schema-level injection preconditions (unconstrained command / URL / path
 *    parameters — the advertised half of command-injection / SSRF / traversal);
 *  - declared server capabilities that are high-signal on their own (sampling,
 *    elicitation) — static proxies for classes rivals only catch at runtime.
 */

import type { CapabilityTag, Detector, DetectorContext, Finding, JsonSchema, ToolCapability, ToolDef } from '../types.js';
import {
  CAPABILITY_SIGNALS,
  COMMAND_PARAM_NAMES,
  PARAM_NAME_SIGNALS,
  PATH_PARAM_NAMES,
  SECRET_FIELD_NAMES,
  SSRF_PARAM_NAMES,
} from '../data/capabilityLexicon.js';
import { normalizeForMatch } from '../util/text.js';

function capFor(caps: ToolCapability[], tool: string): ToolCapability | undefined {
  return caps.find((c) => c.tool === tool);
}

const MUTATION_TAGS = new Set<CapabilityTag>(['code-exec', 'file-write']);

/**
 * Is a tool's state-mutating capability (code-exec / file-write) evidenced
 * *operatively* — by its NAME or a PARAMETER — rather than only by a keyword
 * that happens to appear in its prose description? A read-only getter like
 * `get_config` whose description merely lists "defaultShell" / "blockedCommands"
 * picks up a `code-exec` tag from the word "shell", but it does not execute
 * anything. Only name/param evidence is strong enough to call an annotation a
 * lie (MTC-CAP-003), so a description-only mention must not trip that rule.
 */
function mutationOperativelyEvidenced(tool: ToolDef): boolean {
  const nameNorm = normalizeForMatch(typeof tool.name === 'string' ? tool.name : '');
  const nameTokens = new Set(nameNorm.split(' ').filter(Boolean));
  for (const sig of CAPABILITY_SIGNALS) {
    if (!MUTATION_TAGS.has(sig.tag)) continue;
    for (const kw of sig.keywords) {
      const k = normalizeForMatch(kw);
      if (k.includes(' ') ? nameNorm.includes(k) : nameTokens.has(k)) return true;
    }
  }
  const pTokens = new Set(
    Object.keys(tool.inputSchema?.properties ?? {}).flatMap((n) =>
      n.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean),
    ),
  );
  for (const sig of PARAM_NAME_SIGNALS) {
    if (!MUTATION_TAGS.has(sig.tag)) continue;
    for (const pn of sig.names) if (pTokens.has(pn)) return true;
  }
  return false;
}

/** True if a string-typed property has no enum/pattern constraint. */
function isUnconstrainedString(prop: JsonSchema | undefined): boolean {
  if (!prop || typeof prop !== 'object') return true;
  const t = prop.type;
  const stringy = t === undefined || t === 'string' || (Array.isArray(t) && t.includes('string'));
  if (!stringy) return false;
  return !prop.enum && !prop.pattern;
}

function nameMatches(paramName: string, list: string[]): boolean {
  const tokens = paramName.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean);
  return list.some((n) => tokens.includes(n));
}

export const capabilityDetector: Detector = {
  id: 'capability',
  stage: 3,
  title: 'Capability & annotation analysis',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    for (const tool of ctx.surface.tools) {
      if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string') continue;
      const cap = capFor(ctx.capabilities, tool.name);
      if (!cap) continue;
      const tags = cap.tags;
      const reasons = cap.reasons;
      const has = (t: CapabilityTag): boolean => tags.includes(t);

      if (has('code-exec')) {
        findings.push({
          ruleId: 'MTC-CAP-001',
          title: `Tool "${tool.name}" exposes command/code execution`,
          category: 'permissions',
          severity: 'high',
          confidence: 'strong',
          description:
            `Tool "${tool.name}" appears to run shell commands or evaluate code ` +
            `(${(reasons['code-exec'] ?? []).join(', ')}). Arbitrary execution driven by model input is one of ` +
            `the most dangerous MCP capabilities; combined with any untrusted input it becomes RCE.`,
          remediation: 'Sandbox execution, allowlist commands/arguments, and never pass model output to a shell unescaped.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM05:2025 Improper Output Handling',
          data: { tags },
        });
      }

      if (has('file-write')) {
        findings.push({
          ruleId: 'MTC-CAP-002',
          title: `Tool "${tool.name}" can modify the filesystem`,
          category: 'permissions',
          severity: 'medium',
          confidence: 'strong',
          description:
            `Tool "${tool.name}" can write, overwrite or delete files ` +
            `(${(reasons['file-write'] ?? []).join(', ')}). Verify it is scoped to a safe directory.`,
          remediation: 'Constrain file operations to an explicit, non-sensitive root; reject path traversal.',
          location: { kind: 'tool', name: tool.name },
          data: { tags },
        });
      }

      // Annotation-vs-behavior mismatch. Only a tool that genuinely MODIFIES
      // state (file-write / code-exec) contradicts readOnly/non-destructive — a
      // tool that merely makes an outbound request (e.g. fetch/scrape) can be
      // legitimately read-only, so external-sink alone is NOT a contradiction.
      const claimsReadOnly = tool.annotations?.readOnlyHint === true;
      const claimsNonDestructive = tool.annotations?.destructiveHint === false;
      // Require OPERATIVE evidence (name/param), not a description-only keyword,
      // before calling the annotation a lie — else a read-only getter that merely
      // describes shell/exec config (get_config, get_prompts) is a false positive.
      const actuallyMutates = (has('file-write') || has('code-exec')) && mutationOperativelyEvidenced(tool);
      if ((claimsReadOnly || claimsNonDestructive) && actuallyMutates) {
        findings.push({
          ruleId: 'MTC-CAP-003',
          title: `Annotation contradicts behavior on "${tool.name}"`,
          category: 'permissions',
          severity: 'medium',
          confidence: 'strong',
          description:
            `Tool "${tool.name}" advertises ${claimsReadOnly ? 'readOnlyHint=true' : 'destructiveHint=false'} but its ` +
            `derived capabilities include state-modifying actions (${tags.join(', ')}). Tool annotations are ` +
            `attacker-controllable and must never be trusted; a mismatch like this is exactly how a hostile server ` +
            `hides a destructive tool.`,
          remediation: 'Ignore server-provided annotations for security decisions; gate destructive tools on explicit user consent.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM06:2025 Excessive Agency',
          data: { tags, annotations: tool.annotations },
        });
      }

      // open-world hint + sensitive read = a lethal-trifecta signal from annotations.
      if (tool.annotations?.openWorldHint === true && has('sensitive-source')) {
        findings.push({
          ruleId: 'MTC-CAP-004',
          title: `Open-world tool "${tool.name}" also reads sensitive data`,
          category: 'exfiltration',
          severity: 'medium',
          confidence: 'heuristic',
          description:
            `Tool "${tool.name}" declares openWorldHint=true — it interacts with entities outside the trust boundary — ` +
            `while also reading sensitive data. That combination is a canonical lethal-trifecta indicator.`,
          remediation: 'Separate outward-facing tools from sensitive-data reads; require confirmation between them.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM02:2025 Sensitive Information Disclosure',
          data: { tags },
        });
      }

      // Missing destructiveHint on a genuinely destructive tool (write/exec only,
      // to avoid flagging the very common annotation-less "send" tool).
      const noDestructiveHint = !tool.annotations || tool.annotations.destructiveHint === undefined;
      const genuinelyDestructive = has('file-write') || has('code-exec');
      if (genuinelyDestructive && noDestructiveHint) {
        findings.push({
          ruleId: 'MTC-CAP-005',
          title: `Mutating tool "${tool.name}" declares no destructiveHint`,
          category: 'hygiene',
          severity: 'low',
          confidence: 'heuristic',
          description:
            `Tool "${tool.name}" can mutate/egress but declares no destructiveHint. Clients that don't default to ` +
            `spec-safe behavior may not prompt before running it.`,
          remediation: 'Declare accurate annotations, and gate destructive tools on user confirmation regardless.',
          location: { kind: 'tool', name: tool.name },
          data: { tags },
        });
      }

      // Schema-level injection preconditions (only on the relevant capability).
      const props = tool.inputSchema?.properties ?? {};
      for (const [pname, pschema] of Object.entries(props)) {
        if (!isUnconstrainedString(pschema)) continue;
        const field = `inputSchema.properties.${pname}`;
        if (has('code-exec') && nameMatches(pname, COMMAND_PARAM_NAMES)) {
          findings.push({
            ruleId: 'MTC-CAP-006',
            title: `Unconstrained command parameter "${pname}" on "${tool.name}"`,
            category: 'permissions',
            severity: 'medium',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" takes a command-shaped parameter "${pname}" with no enum/pattern constraint. ` +
              `Free-form, model- or attacker-controlled arguments reaching a shell is the command-injection precondition.`,
            remediation: 'Constrain the parameter (enum/pattern), or build the command from a fixed template with escaped args.',
            location: { kind: 'tool', name: tool.name, field },
            owasp: 'LLM05:2025 Improper Output Handling',
            data: { param: pname },
          });
        } else if ((has('external-sink') || has('untrusted-input')) && nameMatches(pname, SSRF_PARAM_NAMES)) {
          findings.push({
            ruleId: 'MTC-CAP-007',
            title: `Unconstrained URL/host parameter "${pname}" on "${tool.name}"`,
            category: 'network',
            severity: 'medium',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" takes a URL/host parameter "${pname}" with no allowlist/pattern. An outbound-request ` +
              `tool with an unbounded destination enables SSRF and cloud-metadata access (e.g. 169.254.169.254).`,
            remediation: 'Allowlist destinations or constrain the parameter; block private/link-local addresses server-side.',
            location: { kind: 'tool', name: tool.name, field },
            owasp: 'LLM06:2025 Excessive Agency',
            data: { param: pname },
          });
        } else if ((has('file-write') || has('sensitive-source')) && nameMatches(pname, PATH_PARAM_NAMES)) {
          findings.push({
            ruleId: 'MTC-CAP-008',
            title: `Unconstrained path parameter "${pname}" on "${tool.name}"`,
            category: 'permissions',
            severity: 'low',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" takes a path parameter "${pname}" with no constraint. Without a canonicalize-and-` +
              `contain check (not visible statically), this permits ../ traversal outside the intended root.`,
            remediation: 'Resolve and verify the path stays within an allowed root; reject traversal sequences.',
            location: { kind: 'tool', name: tool.name, field },
            data: { param: pname },
          });
        }
      }
    }

    // --- Server-capability pass (declared capabilities are facts, not guesses) ---
    const rawCaps = ctx.surface.server.capabilities;
    const caps = rawCaps && typeof rawCaps === 'object' ? rawCaps : {};
    if ('sampling' in caps) {
      findings.push({
        ruleId: 'MTC-CAP-009',
        title: 'Server declares the sampling capability',
        category: 'permissions',
        severity: 'medium',
        confidence: 'strong',
        description:
          'This server declares the MCP `sampling` capability, letting it drive the client\'s own LLM with ' +
          'server-authored prompts. That reverse-trust channel enables token/resource drain, conversation hijack, ' +
          'and covert tool invocation. Most benign servers do not need sampling.',
        remediation: 'Only grant sampling to servers you fully trust; review what the server does with completions.',
        location: { kind: 'server', field: 'capabilities.sampling' },
        owasp: 'LLM06:2025 Excessive Agency',
      });
    }
    if ('elicitation' in caps) {
      // Plain declared elicitation is a CAPABILITY (MTC-CAP-010, not scored). Only
      // when it also solicits a secret is it a trust THREAT (MTC-CAP-011, scored).
      const secretField = findSecretSeekingField(ctx);
      findings.push({
        ruleId: secretField ? 'MTC-CAP-011' : 'MTC-CAP-010',
        title: 'Server declares the elicitation capability' + (secretField ? ' and solicits secrets' : ''),
        category: secretField ? 'exfiltration' : 'permissions',
        severity: secretField ? 'high' : 'medium',
        confidence: 'strong',
        description:
          'This server declares the MCP `elicitation` capability (it can pop mid-session input requests). This ' +
          'enables consent-fatigue conditioning and phishing.' +
          (secretField
            ? ` It also exposes a secret-seeking field ("${secretField}") — the spec forbids collecting secrets via elicitation.`
            : ''),
        remediation: 'Treat elicitation prompts as untrusted UI; never enter credentials into an elicitation request.',
        location: { kind: 'server', field: 'capabilities.elicitation' },
        owasp: 'LLM02:2025 Sensitive Information Disclosure',
        ...(secretField ? { evidence: secretField } : {}),
      });
    }

    return findings;
  },
};

/** Find the first param/prompt-arg name that solicits a secret, if any. */
function findSecretSeekingField(ctx: DetectorContext): string | undefined {
  const check = (name: string): boolean =>
    name.toLowerCase().split(/[^a-z0-9]+/i).some((tok) => SECRET_FIELD_NAMES.includes(tok));
  for (const tool of ctx.surface.tools) {
    if (!tool || typeof tool !== 'object') continue;
    for (const p of Object.keys(tool.inputSchema?.properties ?? {})) if (check(p)) return p;
  }
  for (const prompt of ctx.surface.prompts) {
    const args = Array.isArray(prompt?.arguments) ? prompt.arguments : [];
    for (const a of args) if (a && typeof a === 'object' && typeof a.name === 'string' && check(a.name)) return a.name;
  }
  return undefined;
}
