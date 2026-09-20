# Rule catalogue

Every rule MCP Trust Checker can emit (84 total). Run `mcptrustchecker rules` for the same list, or `mcptrustchecker explain <id>` for one rule.

Rules marked **[capability]** describe blast-radius and raise the Capability level; they do **not** lower the Trust grade. Rules of severity `info` carry weight 0 and are filtered out before any penalty — they report a coverage or hygiene fact the reader needs, and deliberately move no points. Everything else is a scored trust threat.

<!-- GENERATED FROM src/data/ruleCatalog.ts — do not edit by hand. Run: npm run docs:rules -->

## Injection, Unicode & shadowing

| Rule | Severity | Title | What it means |
| --- | --- | --- | --- |
| `MTC-UNI-001` | critical | Tags-block smuggling channel | Invisible U+E0000 Tags characters decode to hidden ASCII instructions read by the model. |
| `MTC-UNI-002` | high | Variation-selector byte channel | Variation selectors used as a 256-value side channel to smuggle a payload. |
| `MTC-UNI-003` | high | Bidirectional override | BiDi override characters can reorder how text is displayed vs. how it is read. |
| `MTC-UNI-004` | medium | Bidirectional isolate/mark | BiDi isolates/marks in metadata; can be used to hide or reorder content. |
| `MTC-UNI-005` | medium | Zero-width / invisible-math run | Zero-width or invisible-math characters, above threshold, indicate an encoded payload. |
| `MTC-UNI-006` | medium | Default-ignorable characters | Default-ignorable characters (soft hyphen, interlinear annotation, etc.) in metadata. |
| `MTC-UNI-007` | low | Unusual whitespace | Non-breaking / ideographic / thin spaces used in place of normal spaces. |
| `MTC-UNI-008` | high | Control characters | C0/C1 control characters (excluding tab/newline/CR) are abnormal in metadata. |
| `MTC-UNI-009` | high | Mixed-script / homoglyph text | A single token mixes scripts (e.g. Latin + Cyrillic) — a homoglyph impersonation signal. |
| `MTC-UNI-010` | high | ANSI terminal escape sequence | ANSI/CSI/OSC escapes in metadata can hide or rewrite what a terminal user sees (consent phishing). |
| `MTC-INJ-AUTH-1` | low | Authority framing | "IMPORTANT"/"ATTENTION"-style authority framing in tool metadata (weak signal on its own). |
| `MTC-INJ-AUTH-2` | high | Instruction-override directive | "ignore previous instructions"-style override aimed at the model. |
| `MTC-INJ-SECRECY-1` | high | Secrecy directive | Metadata instructs the model to conceal an action from the user. |
| `MTC-INJ-SECRECY-2` | medium | Fabricated policy framing | Fake "compliance"/"policy" justification for an instruction. |
| `MTC-INJ-SEQ-1` | medium | Forced-sequencing (line jumping) | "before using any tool"/"always call this first" — line-jumping directive. |
| `MTC-INJ-SEQ-2` | low | Conditional behavior directive | Conditional "when you…"/"every time…" behavior instruction. |
| `MTC-INJ-TARGET-1` | high | Sensitive file/credential reference | Metadata references ~/.ssh, .env, credentials, API keys, etc. |
| `MTC-INJ-TARGET-2` | high | Context/history solicitation | Metadata asks for system prompt, chat history, or environment details. |
| `MTC-INJ-EXFIL-1` | high | Exfil-shaped parameter description | A parameter description tells the model to include/append context or file contents. |
| `MTC-INJ-SHADOW-1` | high | Cross-tool redirection of a recipient/credential | Description reroutes an email/message/credential/token to another destination (exfiltration/hijack). |
| `MTC-INJ-ENC-1` | high | Encoded-payload decode/execute | Instruction to decode base64/hex and execute the result. |
| `MTC-INJ-ENC-2` | high | Encoded blob + decode instruction | A long base64 blob paired with a decode/execute instruction. |
| `MTC-INJ-CMD-1` | high | Shell command in metadata | A shell command (rm -rf, curl\|sh, etc.) embedded in tool metadata. |
| `MTC-INJ-CAPS` | low | Excessive ALL-CAPS | A run of shouted words used to give injected instructions false authority. |
| `MTC-INJ-PARAM` | medium | Suspicious hidden-channel parameter | A parameter named like a known exfil channel (side_note, context, feedback…). |
| `MTC-INJ-POISON` | critical | Compound tool-poisoning pattern | Multiple poisoning signals co-occur in one field — the canonical poisoning shape. |
| `MTC-INJ-SHADOW-2` | high | Cross-server tool-name collision | A tool name collides with (or is a homoglyph/near-miss of) a tool on another scanned server. |
| `MTC-INJ-SHADOW-3` | high | Tool-selection hijack (suppress other tools) | "Do not use / ignore the other tools"-style text that suppresses all sibling tools in model selection. |
| `MTC-INJ-SHADOW-4` | low | Assertive tool self-preference | Comparative self-promotion ("only correct tool", "use this instead of the X tool") — common in legit docs; a confidence-axis nudge that escalates only with secrecy/override. |
| `MTC-INJ-SEM-1` | medium | Concealment directive (language-agnostic) | A negation/stealth marker, a disclosure verb and a user referent co-occur — "keep this from the person" detected as a shape, so paraphrase and non-English wording are still caught. |
| `MTC-INJ-SCHEMA-1` | medium | Description names an unreachable credential store | Tool prose references SSH keys, cloud credentials or a keychain that nothing in its input schema can address — the interface contradicts the description. |
| `MTC-SRC-004` | high | Obfuscated / encoded payload in server code | Decode-and-execute of an encoded blob, or \x-escaped / fromCharCode runs hiding logic from review. |
| `MTC-SRC-009` | medium | Untrusted input concatenated into a command sink | A shell/process command assembled by concatenation or interpolation — the command-injection flow, not mere presence of a sink. |
| `MTC-SRC-010` | high | Dynamic evaluation of a non-literal value | eval / new Function applied to a variable or expression rather than a fixed literal — a direct RCE primitive. **[capability]** |
| `MTC-SRC-011` | high | Assembled command execution and dynamic evaluation in the same server | Runtime code both builds shell commands from values and evaluates values as code — two execution primitives in one server. |

## Exfiltration & toxic flow

| Rule | Severity | Title | What it means |
| --- | --- | --- | --- |
| `MTC-INJ-SECRET-1` | high | Embedded credential value | A live-looking secret (AWS/GitHub/Slack/JWT/PEM…) is hardcoded in server metadata. |
| `MTC-INJ-URL-1` | medium | Suspicious external URL in tool metadata | A hardcoded webhook/paste/exfil endpoint or raw IP in a tool description — a data-exfiltration channel. |
| `MTC-CAP-004` | medium | Open-world tool reads sensitive data | openWorldHint=true plus a sensitive-data read is a lethal-trifecta indicator. **[capability]** |
| `MTC-CAP-011` | high | Elicitation solicits secrets | Declared elicitation + a secret-seeking field — a consent-phishing threat. |
| `MTC-FLOW-001` | critical | Self-contained exfiltration primitive | One tool ingests untrusted input, reads sensitive data, and can exfiltrate it. |
| `MTC-FLOW-002` | critical | Completed trifecta across tools | Untrusted-input, sensitive-source and external-sink roles co-exist across tools. **[capability]** |
| `MTC-FLOW-003` | high | Read-and-egress in one tool | A single tool both reads sensitive data and can send it out. **[capability]** |
| `MTC-FLOW-004` | high | Source + sink co-exist | A sensitive-data source and an external sink are exposed together. **[capability]** |
| `MTC-FLOW-005` | medium | Untrusted input drives an action | Untrusted input can reach an external-action sink (no sensitive source found). **[capability]** |
| `MTC-SRC-003` | medium | Hardcoded egress to an external endpoint | A fixed outbound http(s) call to a non-local host in the code — an exfiltration/telemetry channel. **[capability]** |
| `MTC-SRC-006` | high | Credential-path read or environment dump in code | Reads ~/.ssh / .aws/credentials / .netrc, or serializes the whole environment — a sensitive-data source. **[capability]** |
| `MTC-SRC-008` | high | Hardcoded credential value in server code | A live-looking secret (AWS/GitHub/Slack/JWT/PEM…) embedded in the source, shipped to every install. |

## Capability & permissions

| Rule | Severity | Title | What it means |
| --- | --- | --- | --- |
| `MTC-CAP-001` | high | Command/code execution capability | Tool runs shell commands or evaluates code. **[capability]** |
| `MTC-CAP-002` | medium | Filesystem mutation capability | Tool can write, overwrite, or delete files. **[capability]** |
| `MTC-CAP-003` | medium | Annotation-vs-behavior mismatch | Tool claims read-only/non-destructive but its behavior mutates/egresses. |
| `MTC-CAP-006` | medium | Unconstrained command parameter | A command-shaped param with no enum/pattern — the command-injection precondition. **[capability]** |
| `MTC-CAP-008` | low | Unconstrained path parameter | A file tool takes an unconstrained path — the path-traversal precondition. **[capability]** |
| `MTC-CAP-009` | medium | Declared sampling capability | Server can drive the client LLM with its own prompts (reverse-trust / resource drain). **[capability]** |
| `MTC-CAP-010` | medium | Declared elicitation capability | Server can pop mid-session input requests (capability; blast-radius only). **[capability]** |
| `MTC-SRC-001` | high | Dynamic code execution in server code | eval / new Function / vm / exec(compile) — arbitrary-code-execution primitive in the implementation. **[capability]** |
| `MTC-SRC-002` | high | Shell/command execution in server code | child_process / os.system / subprocess(shell=True) — command-execution sink; RCE with unsanitized input. **[capability]** |
| `MTC-SRC-005` | medium | Dynamic module load from a non-literal | require()/import()/__import__ from a variable — loads runtime-chosen (attacker-influenced) code. **[capability]** |
| `MTC-SRC-007` | medium | Unsafe deserialization | pickle.loads / yaml.load / node-serialize / marshal.loads — a classic deserialization RCE gadget. |

## Supply chain

| Rule | Severity | Title | What it means |
| --- | --- | --- | --- |
| `MTC-SUP-001` | high | Known typosquat | Name matches a known impersonation of a popular package. |
| `MTC-SUP-002` | high | Impersonated official scope | Scope crafted to look like @modelcontextprotocol. |
| `MTC-SUP-003` | high | Unscoped shadow | Unscoped name shadowing an official scoped package. |
| `MTC-SUP-004` | high | Homoglyph squat | Confusable skeleton identical to a protected package. |
| `MTC-SUP-005` | medium | Edit-distance near-miss | Damerau-Levenshtein 1–2 from a protected package, download-anomaly gated. |
| `MTC-SUP-006` | medium | Combosquat | Protected name plus a decorative suffix (-js, -server, …). |
| `MTC-SUP-010` | high | Install-time scripts | Package runs pre/post/install scripts — the dominant malware vector. |
| `MTC-SUP-011` | low | No source repository | Published artifact cannot be compared against reviewable source. |
| `MTC-SUP-013` | low | Package not version-pinned | Installed with @latest/floating spec — the rug-pull enabler; pinning is the recommended control. |
| `MTC-SUP-014` | medium | Dependency squat / advisory match | A declared dependency resembles a protected package or matches a known advisory by name. |
| `MTC-SUP-015` | medium | Pinned version is not published in the registry | An exact pinned version is not listed by the registry; the scanner refuses to substitute latest and flags the gap. |
| `MTC-NET-001` | critical | Known-vulnerable version | Installed version is in a known-CVE range. Severity and confidence come from the advisory itself — a critical CVE is reported confirmed-critical and gates the grade at F. |
| `MTC-TOFU-001` | high | Surface drift since pin (rug pull) | Canonical fingerprint no longer matches the pinned value. |
| `MTC-TOFU-002` | critical | Package republished with different content at the same version | The verified artifact hash for the pinned version changed — same version, different published bytes (byte-level rug pull). |
| `MTC-TOFU-003` | critical | Published artifact failed integrity verification | The downloaded artifact did not match the registry-declared hash, or was redirected off the registry host — tamper evidence; the bytes were not trusted. |
| `MTC-TOFU-004` | info | Published-source byte check did not run | An online scan could not download the artifact; results reflect registry metadata only and are not source-verified. |
| `MTC-TOFU-005` | info | Pin predates the current methodology — drift not evaluated | The lockfile entry was pinned under an older methodology version whose fingerprint covered different fields, so surface drift could not be compared; re-pin to restore the check. |

## Transport & network posture

| Rule | Severity | Title | What it means |
| --- | --- | --- | --- |
| `MTC-CAP-007` | medium | Unconstrained URL/host parameter | An outbound tool takes an unbounded URL/host — the SSRF / cloud-metadata precondition. **[capability]** |
| `MTC-NET-002` | critical | User-controlled stdio command | stdio command from untrusted config without an allowlist — stdio RCE class. |
| `MTC-NET-003` | medium | Plaintext HTTP transport | Server reached over http:// — traffic and tokens exposed. |
| `MTC-NET-004` | medium | Bound to 0.0.0.0 | Server exposed on all interfaces; verify authentication. |
| `MTC-NET-005` | info | Remote HTTP endpoint | Remote endpoint; server-side auth is out of scope for static analysis. **[capability]** |
| `MTC-NET-006` | low | Local HTTP/SSE — verify Origin (DNS rebinding) | A browser-reachable local MCP server is exposed to DNS rebinding unless it validates Host/Origin. |

## Metadata hygiene

| Rule | Severity | Title | What it means |
| --- | --- | --- | --- |
| `MTC-CAP-005` | low | Mutating tool without destructiveHint | A tool that mutates/egresses declares no destructiveHint, so some clients may not prompt. **[capability]** |
| `MTC-SUP-012` | info | No license | Package declares no license — a legal/reuse concern, recorded but never scored. |
| `MTC-META-001` | info | Empty surface — nothing to analyze | No tools/prompts/resources found; an empty surface is not a clean bill of health. |
