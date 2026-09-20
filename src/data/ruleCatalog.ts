/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Human-readable catalogue of every rule MCP Trust Checker can emit. Powers
 * `mcptrustchecker rules` / `mcptrustchecker explain <id>` and docs/rules.md. Keep in sync
 * with the detectors (tested by rules.test.ts).
 */

import type { Category, Severity } from '../types.js';

export interface RuleDoc {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  summary: string;
}

export const RULE_CATALOG: RuleDoc[] = [
  // Stage 1 — Unicode
  { id: 'MTC-UNI-001', title: 'Tags-block smuggling channel', category: 'injection', severity: 'critical', summary: 'Invisible U+E0000 Tags characters decode to hidden ASCII instructions read by the model.' },
  { id: 'MTC-UNI-002', title: 'Variation-selector byte channel', category: 'injection', severity: 'high', summary: 'Variation selectors used as a 256-value side channel to smuggle a payload.' },
  { id: 'MTC-UNI-003', title: 'Bidirectional override', category: 'injection', severity: 'high', summary: 'BiDi override characters can reorder how text is displayed vs. how it is read.' },
  { id: 'MTC-UNI-004', title: 'Bidirectional isolate/mark', category: 'injection', severity: 'medium', summary: 'BiDi isolates/marks in metadata; can be used to hide or reorder content.' },
  { id: 'MTC-UNI-005', title: 'Zero-width / invisible-math run', category: 'injection', severity: 'medium', summary: 'Zero-width or invisible-math characters, above threshold, indicate an encoded payload.' },
  { id: 'MTC-UNI-006', title: 'Default-ignorable characters', category: 'injection', severity: 'medium', summary: 'Default-ignorable characters (soft hyphen, interlinear annotation, etc.) in metadata.' },
  { id: 'MTC-UNI-007', title: 'Unusual whitespace', category: 'injection', severity: 'low', summary: 'Non-breaking / ideographic / thin spaces used in place of normal spaces.' },
  { id: 'MTC-UNI-008', title: 'Control characters', category: 'injection', severity: 'high', summary: 'C0/C1 control characters (excluding tab/newline/CR) are abnormal in metadata.' },
  { id: 'MTC-UNI-009', title: 'Mixed-script / homoglyph text', category: 'injection', severity: 'high', summary: 'A single token mixes scripts (e.g. Latin + Cyrillic) — a homoglyph impersonation signal.' },
  { id: 'MTC-UNI-010', title: 'ANSI terminal escape sequence', category: 'injection', severity: 'high', summary: 'ANSI/CSI/OSC escapes in metadata can hide or rewrite what a terminal user sees (consent phishing).' },

  // Stage 2 — Injection
  { id: 'MTC-INJ-AUTH-1', title: 'Authority framing', category: 'injection', severity: 'low', summary: '"IMPORTANT"/"ATTENTION"-style authority framing in tool metadata (weak signal on its own).' },
  { id: 'MTC-INJ-AUTH-2', title: 'Instruction-override directive', category: 'injection', severity: 'high', summary: '"ignore previous instructions"-style override aimed at the model.' },
  { id: 'MTC-INJ-SECRECY-1', title: 'Secrecy directive', category: 'injection', severity: 'high', summary: 'Metadata instructs the model to conceal an action from the user.' },
  { id: 'MTC-INJ-SECRECY-2', title: 'Fabricated policy framing', category: 'injection', severity: 'medium', summary: 'Fake "compliance"/"policy" justification for an instruction.' },
  { id: 'MTC-INJ-SEQ-1', title: 'Forced-sequencing (line jumping)', category: 'injection', severity: 'medium', summary: '"before using any tool"/"always call this first" — line-jumping directive.' },
  { id: 'MTC-INJ-SEQ-2', title: 'Conditional behavior directive', category: 'injection', severity: 'low', summary: 'Conditional "when you…"/"every time…" behavior instruction.' },
  { id: 'MTC-INJ-TARGET-1', title: 'Sensitive file/credential reference', category: 'injection', severity: 'high', summary: 'Metadata references ~/.ssh, .env, credentials, API keys, etc.' },
  { id: 'MTC-INJ-TARGET-2', title: 'Context/history solicitation', category: 'injection', severity: 'high', summary: 'Metadata asks for system prompt, chat history, or environment details.' },
  { id: 'MTC-INJ-EXFIL-1', title: 'Exfil-shaped parameter description', category: 'injection', severity: 'high', summary: 'A parameter description tells the model to include/append context or file contents.' },
  { id: 'MTC-INJ-SHADOW-1', title: 'Cross-tool redirection of a recipient/credential', category: 'injection', severity: 'high', summary: 'Description reroutes an email/message/credential/token to another destination (exfiltration/hijack).' },
  { id: 'MTC-INJ-ENC-1', title: 'Encoded-payload decode/execute', category: 'injection', severity: 'high', summary: 'Instruction to decode base64/hex and execute the result.' },
  { id: 'MTC-INJ-ENC-2', title: 'Encoded blob + decode instruction', category: 'injection', severity: 'high', summary: 'A long base64 blob paired with a decode/execute instruction.' },
  { id: 'MTC-INJ-CMD-1', title: 'Shell command in metadata', category: 'injection', severity: 'high', summary: 'A shell command (rm -rf, curl|sh, etc.) embedded in tool metadata.' },
  { id: 'MTC-INJ-CAPS', title: 'Excessive ALL-CAPS', category: 'injection', severity: 'low', summary: 'A run of shouted words used to give injected instructions false authority.' },
  { id: 'MTC-INJ-PARAM', title: 'Suspicious hidden-channel parameter', category: 'injection', severity: 'medium', summary: 'A parameter named like a known exfil channel (side_note, context, feedback…).' },
  { id: 'MTC-INJ-POISON', title: 'Compound tool-poisoning pattern', category: 'injection', severity: 'critical', summary: 'Multiple poisoning signals co-occur in one field — the canonical poisoning shape.' },
  { id: 'MTC-INJ-SHADOW-2', title: 'Cross-server tool-name collision', category: 'injection', severity: 'high', summary: 'A tool name collides with (or is a homoglyph/near-miss of) a tool on another scanned server.' },
  { id: 'MTC-INJ-SHADOW-3', title: 'Tool-selection hijack (suppress other tools)', category: 'injection', severity: 'high', summary: '"Do not use / ignore the other tools"-style text that suppresses all sibling tools in model selection.' },
  { id: 'MTC-INJ-SHADOW-4', title: 'Assertive tool self-preference', category: 'injection', severity: 'low', summary: 'Comparative self-promotion ("only correct tool", "use this instead of the X tool") — common in legit docs; a confidence-axis nudge that escalates only with secrecy/override.' },
  { id: 'MTC-INJ-SECRET-1', title: 'Embedded credential value', category: 'exfiltration', severity: 'high', summary: 'A live-looking secret (AWS/GitHub/Slack/JWT/PEM…) is hardcoded in server metadata.' },
  { id: 'MTC-INJ-URL-1', title: 'Suspicious external URL in tool metadata', category: 'exfiltration', severity: 'medium', summary: 'A hardcoded webhook/paste/exfil endpoint or raw IP in a tool description — a data-exfiltration channel.' },
  { id: 'MTC-INJ-SEM-1', title: 'Concealment directive (language-agnostic)', category: 'injection', severity: 'medium', summary: 'A negation/stealth marker, a disclosure verb and a user referent co-occur — "keep this from the person" detected as a shape, so paraphrase and non-English wording are still caught.' },
  { id: 'MTC-INJ-SCHEMA-1', title: 'Description names an unreachable credential store', category: 'injection', severity: 'medium', summary: 'Tool prose references SSH keys, cloud credentials or a keychain that nothing in its input schema can address — the interface contradicts the description.' },

  // Stage 3 — Capability
  { id: 'MTC-CAP-001', title: 'Command/code execution capability', category: 'permissions', severity: 'high', summary: 'Tool runs shell commands or evaluates code.' },
  { id: 'MTC-CAP-002', title: 'Filesystem mutation capability', category: 'permissions', severity: 'medium', summary: 'Tool can write, overwrite, or delete files.' },
  { id: 'MTC-CAP-003', title: 'Annotation-vs-behavior mismatch', category: 'permissions', severity: 'medium', summary: 'Tool claims read-only/non-destructive but its behavior mutates/egresses.' },
  { id: 'MTC-CAP-004', title: 'Open-world tool reads sensitive data', category: 'exfiltration', severity: 'medium', summary: 'openWorldHint=true plus a sensitive-data read is a lethal-trifecta indicator.' },
  { id: 'MTC-CAP-005', title: 'Mutating tool without destructiveHint', category: 'hygiene', severity: 'low', summary: 'A tool that mutates/egresses declares no destructiveHint, so some clients may not prompt.' },
  { id: 'MTC-CAP-006', title: 'Unconstrained command parameter', category: 'permissions', severity: 'medium', summary: 'A command-shaped param with no enum/pattern — the command-injection precondition.' },
  { id: 'MTC-CAP-007', title: 'Unconstrained URL/host parameter', category: 'network', severity: 'medium', summary: 'An outbound tool takes an unbounded URL/host — the SSRF / cloud-metadata precondition.' },
  { id: 'MTC-CAP-008', title: 'Unconstrained path parameter', category: 'permissions', severity: 'low', summary: 'A file tool takes an unconstrained path — the path-traversal precondition.' },
  { id: 'MTC-CAP-009', title: 'Declared sampling capability', category: 'permissions', severity: 'medium', summary: 'Server can drive the client LLM with its own prompts (reverse-trust / resource drain).' },
  { id: 'MTC-CAP-010', title: 'Declared elicitation capability', category: 'permissions', severity: 'medium', summary: 'Server can pop mid-session input requests (capability; blast-radius only).' },
  { id: 'MTC-CAP-011', title: 'Elicitation solicits secrets', category: 'exfiltration', severity: 'high', summary: 'Declared elicitation + a secret-seeking field — a consent-phishing threat.' },

  // Stage 4 — Toxic flow
  { id: 'MTC-FLOW-001', title: 'Self-contained exfiltration primitive', category: 'exfiltration', severity: 'critical', summary: 'One tool ingests untrusted input, reads sensitive data, and can exfiltrate it.' },
  { id: 'MTC-FLOW-002', title: 'Completed trifecta across tools', category: 'exfiltration', severity: 'critical', summary: 'Untrusted-input, sensitive-source and external-sink roles co-exist across tools.' },
  { id: 'MTC-FLOW-003', title: 'Read-and-egress in one tool', category: 'exfiltration', severity: 'high', summary: 'A single tool both reads sensitive data and can send it out.' },
  { id: 'MTC-FLOW-004', title: 'Source + sink co-exist', category: 'exfiltration', severity: 'high', summary: 'A sensitive-data source and an external sink are exposed together.' },
  { id: 'MTC-FLOW-005', title: 'Untrusted input drives an action', category: 'exfiltration', severity: 'medium', summary: 'Untrusted input can reach an external-action sink (no sensitive source found).' },

  // Stage 5 — Supply chain
  { id: 'MTC-SUP-001', title: 'Known typosquat', category: 'supply-chain', severity: 'high', summary: 'Name matches a known impersonation of a popular package.' },
  { id: 'MTC-SUP-002', title: 'Impersonated official scope', category: 'supply-chain', severity: 'high', summary: 'Scope crafted to look like @modelcontextprotocol.' },
  { id: 'MTC-SUP-003', title: 'Unscoped shadow', category: 'supply-chain', severity: 'high', summary: 'Unscoped name shadowing an official scoped package.' },
  { id: 'MTC-SUP-004', title: 'Homoglyph squat', category: 'supply-chain', severity: 'high', summary: 'Confusable skeleton identical to a protected package.' },
  { id: 'MTC-SUP-005', title: 'Edit-distance near-miss', category: 'supply-chain', severity: 'medium', summary: 'Damerau-Levenshtein 1–2 from a protected package, download-anomaly gated.' },
  { id: 'MTC-SUP-006', title: 'Combosquat', category: 'supply-chain', severity: 'medium', summary: 'Protected name plus a decorative suffix (-js, -server, …).' },
  { id: 'MTC-SUP-010', title: 'Install-time scripts', category: 'supply-chain', severity: 'high', summary: 'Package runs pre/post/install scripts — the dominant malware vector.' },
  { id: 'MTC-SUP-011', title: 'No source repository', category: 'supply-chain', severity: 'low', summary: 'Published artifact cannot be compared against reviewable source.' },
  { id: 'MTC-SUP-012', title: 'No license', category: 'hygiene', severity: 'info', summary: 'Package declares no license — a legal/reuse concern, recorded but never scored.' },
  { id: 'MTC-SUP-013', title: 'Package not version-pinned', category: 'supply-chain', severity: 'low', summary: 'Installed with @latest/floating spec — the rug-pull enabler; pinning is the recommended control.' },
  { id: 'MTC-SUP-014', title: 'Dependency squat / advisory match', category: 'supply-chain', severity: 'medium', summary: 'A declared dependency resembles a protected package or matches a known advisory by name.' },
  { id: 'MTC-SUP-015', title: 'Pinned version is not published in the registry', category: 'supply-chain', severity: 'medium', summary: 'An exact pinned version is not listed by the registry; the scanner refuses to substitute latest and flags the gap.' },

  // Stage 6 — Posture / CVE
  { id: 'MTC-NET-001', title: 'Known-vulnerable version', category: 'supply-chain', severity: 'critical', summary: 'Installed version is in a known-CVE range. Severity and confidence come from the advisory itself — a critical CVE is reported confirmed-critical and gates the grade at F.' },
  { id: 'MTC-NET-002', title: 'User-controlled stdio command', category: 'network', severity: 'critical', summary: 'stdio command from untrusted config without an allowlist — stdio RCE class.' },
  { id: 'MTC-NET-003', title: 'Plaintext HTTP transport', category: 'network', severity: 'medium', summary: 'Server reached over http:// — traffic and tokens exposed.' },
  { id: 'MTC-NET-004', title: 'Bound to 0.0.0.0', category: 'network', severity: 'medium', summary: 'Server exposed on all interfaces; verify authentication.' },
  { id: 'MTC-NET-005', title: 'Remote HTTP endpoint', category: 'network', severity: 'info', summary: 'Remote endpoint; server-side auth is out of scope for static analysis.' },
  { id: 'MTC-NET-006', title: 'Local HTTP/SSE — verify Origin (DNS rebinding)', category: 'network', severity: 'low', summary: 'A browser-reachable local MCP server is exposed to DNS rebinding unless it validates Host/Origin.' },

  // Stage 7 — Integrity
  { id: 'MTC-TOFU-001', title: 'Surface drift since pin (rug pull)', category: 'supply-chain', severity: 'high', summary: 'Canonical fingerprint no longer matches the pinned value.' },
  { id: 'MTC-TOFU-002', title: 'Package republished with different content at the same version', category: 'supply-chain', severity: 'critical', summary: 'The verified artifact hash for the pinned version changed — same version, different published bytes (byte-level rug pull).' },
  { id: 'MTC-TOFU-003', title: 'Published artifact failed integrity verification', category: 'supply-chain', severity: 'critical', summary: 'The downloaded artifact did not match the registry-declared hash, or was redirected off the registry host — tamper evidence; the bytes were not trusted.' },
  { id: 'MTC-TOFU-004', title: 'Published-source byte check did not run', category: 'supply-chain', severity: 'info', summary: 'An online scan could not download the artifact; results reflect registry metadata only and are not source-verified.' },
  { id: 'MTC-TOFU-005', title: 'Pin predates the current methodology — drift not evaluated', category: 'supply-chain', severity: 'info', summary: 'The lockfile entry was pinned under an older methodology version whose fingerprint covered different fields, so surface drift could not be compared; re-pin to restore the check.' },

  // Meta
  { id: 'MTC-META-001', title: 'Empty surface — nothing to analyze', category: 'hygiene', severity: 'info', summary: 'No tools/prompts/resources found; an empty surface is not a clean bill of health.' },

  // Stage 4b — Implementation-level source analysis (what the code DOES, not what the tool claims)
  { id: 'MTC-SRC-001', title: 'Dynamic code execution in server code', category: 'permissions', severity: 'high', summary: 'eval / new Function / vm / exec(compile) — arbitrary-code-execution primitive in the implementation.' },
  { id: 'MTC-SRC-002', title: 'Shell/command execution in server code', category: 'permissions', severity: 'high', summary: 'child_process / os.system / subprocess(shell=True) — command-execution sink; RCE with unsanitized input.' },
  { id: 'MTC-SRC-003', title: 'Hardcoded egress to an external endpoint', category: 'exfiltration', severity: 'medium', summary: 'A fixed outbound http(s) call to a non-local host in the code — an exfiltration/telemetry channel.' },
  { id: 'MTC-SRC-004', title: 'Obfuscated / encoded payload in server code', category: 'injection', severity: 'high', summary: 'Decode-and-execute of an encoded blob, or \\x-escaped / fromCharCode runs hiding logic from review.' },
  { id: 'MTC-SRC-005', title: 'Dynamic module load from a non-literal', category: 'permissions', severity: 'medium', summary: 'require()/import()/__import__ from a variable — loads runtime-chosen (attacker-influenced) code.' },
  { id: 'MTC-SRC-006', title: 'Credential-path read or environment dump in code', category: 'exfiltration', severity: 'high', summary: 'Reads ~/.ssh / .aws/credentials / .netrc, or serializes the whole environment — a sensitive-data source.' },
  { id: 'MTC-SRC-007', title: 'Unsafe deserialization', category: 'permissions', severity: 'medium', summary: 'pickle.loads / yaml.load / node-serialize / marshal.loads — a classic deserialization RCE gadget.' },
  { id: 'MTC-SRC-008', title: 'Hardcoded credential value in server code', category: 'exfiltration', severity: 'high', summary: 'A live-looking secret (AWS/GitHub/Slack/JWT/PEM…) embedded in the source, shipped to every install.' },
  { id: 'MTC-SRC-009', title: 'Untrusted input concatenated into a command sink', category: 'injection', severity: 'medium', summary: 'A shell/process command assembled by concatenation or interpolation — the command-injection flow, not mere presence of a sink.' },
  { id: 'MTC-SRC-010', title: 'Dynamic evaluation of a non-literal value', category: 'injection', severity: 'high', summary: 'eval / new Function applied to a variable or expression rather than a fixed literal — a direct RCE primitive.' },
  { id: 'MTC-SRC-011', title: 'Assembled command execution and dynamic evaluation in the same server', category: 'injection', severity: 'high', summary: 'Runtime code both builds shell commands from values and evaluates values as code — two execution primitives in one server.' },
];

export function findRule(id: string): RuleDoc | undefined {
  return RULE_CATALOG.find((r) => r.id.toLowerCase() === id.toLowerCase());
}
