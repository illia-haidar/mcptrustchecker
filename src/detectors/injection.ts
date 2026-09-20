/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 2 — Content injection heuristics (tool poisoning / line jumping /
 * shadowing). Runs the pattern lexicon across four channels, then escalates
 * when multiple poisoning signals co-occur in one field — the shape of a real
 * tool-poisoning attack rather than an incidental keyword.
 */

import type { Detector, DetectorContext, Finding, Severity, ToolDef } from '../types.js';
import { collectTextFields } from '../util/text.js';
import { compiledInjectionPatterns, longestAllCapsRun, hasBase64Blob } from '../util/text.js';
import { decodeLayers, describeChain } from '../util/decode.js';
import { analyzeSemanticShapes, type SemanticShape } from '../data/semanticClasses.js';
import {
  ALLCAPS_RUN_WORDS,
  SECRET_PATTERNS,
  SUSPICIOUS_PARAM_NAMES,
  SUSPICIOUS_URL_HOST,
  SUSPICIOUS_URL_PATH,
  URL_IP_LITERAL,
} from '../data/injectionPatterns.js';

const PATTERNS = compiledInjectionPatterns();

function firstMatch(regex: RegExp, text: string): string | undefined {
  const m = text.match(regex);
  return m ? m[0] : undefined;
}

// Kinds whose match is a real accusation in a functional tool but only a
// DOCUMENTED example in a detector/guard tool or behind a defensive caveat.
// In that mention-vs-use context, and absent corroboration by a second injection
// kind, they are downgraded to a low heuristic rather than a high accusation —
// a scanner that flags "tool poisoning" on a legitimate injection-detector or a
// safety warning destroys client trust.
const MENTION_VS_USE_KINDS = new Set<string>(['override', 'command-in-prose', 'sensitive-target']);

// A tool whose very PURPOSE is to detect / scan / guard against malicious text:
// an override phrase in its metadata is its subject matter, not a planted payload.
const DEFENSIVE_TOOL_NAME =
  /detect|scan|guard|vet|sentinel|audit|complian|firewall|sanitiz|moderat|classif|injection|malicious|threat|is[_-]?safe|check[_-]?command|shield|policy/i;
// The phrase is framed as an example / quotation, or an explicit "do not obey" caveat.
// The `e.g.` alternative REQUIRES its first period. Written as `e\.?g\.?` it also
// matched the bare letters `eg`, anywhere, case-insensitively — so `region`,
// `legacy`, `delegate`, `integration`, `segment` and `negative` all declared a
// defensive context, silently downgrading override / command / sensitive-target
// findings and (since 1.11) suppressing the semantic layer outright. Any base64
// blob containing `eg` did the same.
const DEFENSIVE_FRAME =
  /such as|\be\.\s?g\.?|for example|for instance|patterns? like|examples?\s*:|do not (obey|follow|execute|act on|comply)|ignore any (instructions|prompts?|text)|may (contain|include)|might contain|treat [^.]* as (untrusted|data)/i;

function isDefensiveContext(toolName: string | undefined, text: string): boolean {
  return DEFENSIVE_TOOL_NAME.test(toolName ?? '') || DEFENSIVE_FRAME.test(text);
}

// A nearby verb that turns a credential-path reference into actual access/exfil.
const EXFIL_VERB = /send|include|append|attach|paste|upload|exfiltrat|leak|return|reveal|copy|forward|\bread(s|ing)?\b|\baccess(es|ing)?\b|\bdump\b|\bopen\b|\bcat /i;
// A tool that legitimately operates ON ssh/credentials/config as its own subject.
const SELF_CREDENTIAL_TOOL = /ssh|known_hosts|credential|config|keychain|dotfile|\benv\b/i;
// The model is being TOLD to run the command — what makes a prose command an
// accusation rather than a documented example.
const MODEL_RUN_DIRECTIVE = /before (answer|respond)|you (must|should) (run|execute)|execute this (first|command)|run this (first|before|command)|silently (run|execute)|then run/i;
// A tool whose own function is running/deleting on a shell — a "rm -rf" in its
// description is documenting itself, not injecting.
// Destructive verbs are matched with an UNDERSCORE-aware boundary ([_\W]), so an
// MCP tool named `adb_rm` / `file_del` / `force_unlink` is recognised as a
// delete tool documenting itself — while `transform`/`confirm`/`alarm` (rm inside
// a word, preceded by a letter) never match.
const SHELL_TOOL_NAME = /command|shell|\bexec|terminal|bash|\brun_|process|delete|(?:^|[_\W])(?:rm|rmdir|del|unlink)(?:[_\W]|$)|uninstall|cleanup/i;

// --- Description ↔ schema coherence ----------------------------------------
// A tool's INTERFACE is the honest statement of what it touches. When the prose
// names a credential store that nothing in the interface can address, the prose
// is talking to the model, not documenting the tool. These targets are literal
// identifiers, so the check works regardless of what language the prose is in.
const CREDENTIAL_TARGET =
  /~\/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|\.npmrc\b|\.git-credentials\b|\/etc\/(?:passwd|shadow)\b|~\/\.config\/[^\s]*\/credentials|~\/\.docker\/config\.json|\.kube\/config\b|%APPDATA%|\bkeychain\b/i;
// A parameter that could legitimately carry such a target. Matched loosely (as a
// token inside the name) so `key_path`, `configFile` and `credentialsDir` count.
const TARGET_PARAM_TOKEN =
  /path|file|dir|folder|url|uri|key|secret|credential|token|env|profile|config|identity|account|host|location|target|source|destination/i;

/** True when the prose names a credential store the tool's own schema cannot reach. */
function referencesUnreachableCredential(tool: ToolDef | undefined, text: string): boolean {
  if (!CREDENTIAL_TARGET.test(text)) return false;
  // A tool whose subject legitimately IS the credential store documents itself.
  if (SELF_CREDENTIAL_TOOL.test(tool?.name ?? '')) return false;
  const props = tool?.inputSchema?.properties;
  if (props && typeof props === 'object') {
    for (const name of Object.keys(props)) if (TARGET_PARAM_TOKEN.test(name)) return false;
  }
  return true;
}

export const injectionDetector: Detector = {
  id: 'injection',
  stage: 2,
  title: 'Prompt-injection / tool-poisoning heuristics',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const toolByName = new Map<string, ToolDef>();
    for (const t of ctx.surface.tools) {
      if (t && typeof t === 'object' && typeof t.name === 'string') toolByName.set(t.name, t);
    }

    for (const field of collectTextFields(ctx.surface)) {
      const kindsHit = new Set<string>();
      // Every field is scanned in its literal form AND in each form recovered by
      // the decode ladder. A payload written in base64, percent-escapes, HTML
      // entities or an invisible Unicode channel is read by the model exactly as
      // if it were plain text, so the detector has to read it that way too.
      // Order is [raw, …breadth-first layers], which makes the shallowest
      // explanation of a hit the one that gets reported.
      const views: { text: string; via: string[] }[] = [
        { text: field.text, via: [] },
        ...decodeLayers(field.text),
      ];

      // PASS 1 — detect every signal (populate kindsHit) and collect the ones
      // eligible to raise their own finding. Weak single-token shapes (emphasis,
      // self-ordering, context nouns, self-preference — `standalone: false`)
      // register their kind for the compound rule but are never collected here.
      const hits: { p: (typeof PATTERNS)[number]; match: string; via: string[] }[] = [];
      const seenPattern = new Set<string>();
      /** Kinds legible without decoding anything — the pre-ladder baseline. */
      const rawKinds = new Set<string>();
      for (const view of views) {
        for (const p of PATTERNS) {
          if (!p.meta.channels.includes(field.channel as never)) continue;
          const match = firstMatch(p.regex, view.text);
          if (!match) continue;
          kindsHit.add(p.kind);
          if (view.via.length === 0) rawKinds.add(p.kind);
          // One finding per pattern per field: the first (shallowest) view wins,
          // so a payload visible in three derived views is charged once.
          if (p.meta.standalone !== false && !seenPattern.has(p.id)) {
            seenPattern.add(p.id);
            hits.push({ p, match, via: view.via });
          }
        }

        // ALL-CAPS shouting is a CORROBORATING signal only — standalone it fired
        // ~100% FP on acronyms, section headers ("PATTERN EXAMPLES:") and safety
        // warnings ("IMPORTANT: DO NOT …"). Feed the compound rule, never accuse.
        if (
          (field.channel === 'tool-description' ||
            field.channel === 'param-description' ||
            field.channel === 'server-instructions') &&
          longestAllCapsRun(view.text) >= ALLCAPS_RUN_WORDS
        ) {
          kindsHit.add('authority');
        }
      }

      const toolName = field.location.name;
      const defensive = isDefensiveContext(toolName, field.text);

      // SEMANTIC SHAPES. The phrase lexicon above matches exact English wordings;
      // this layer matches the *shape* of a model-directed instruction from
      // multilingual word classes, so a paraphrase or a translation is still
      // seen. These are soft: they are suppressed entirely in a defensive
      // context, and a LONE shape never feeds the compound rule — legitimate
      // tools do say "do not notify the user". Two independent shapes in one
      // field is the poisoning silhouette.
      // Only the channels the MODEL reads carry instructions; a bare name or
      // title cannot be a directive, and skipping them keeps the class scan off
      // the hot path for the majority of fields on a large surface.
      const instructionChannel =
        field.channel === 'tool-description' ||
        field.channel === 'param-description' ||
        field.channel === 'server-instructions';
      const rawSemantic = instructionChannel
        ? analyzeSemanticShapes(field.text)
        : { shapes: [] as SemanticShape[], hasUserRef: false };
      // Shapes and the human referent are both collected across EVERY view, not
      // just the literal text. Reading `hasUserRef` from the raw field alone made
      // MTC-INJ-SEM-1 unreachable for a payload that was encoded — which is the
      // payload it exists to catch, since an attacker who paraphrases to dodge
      // the English lexicon will also encode.
      const extraShapes: SemanticShape[] = [];
      let hasUserRef = rawSemantic.hasUserRef;
      for (const view of instructionChannel ? views : []) {
        if (view.via.length === 0) continue;
        const s = analyzeSemanticShapes(view.text);
        if (s.hasUserRef) hasUserRef = true;
        for (const shape of s.shapes) {
          if (!rawSemantic.shapes.some((x) => x.id === shape.id) && !extraShapes.some((x) => x.id === shape.id)) {
            extraShapes.push(shape);
          }
        }
      }
      const shapes = defensive ? [] : [...rawSemantic.shapes, ...extraShapes];

      // CONCEALMENT — computed from BOTH halves of the evidence, and computed
      // before the semantic kinds are merged in so the two are not confused.
      //
      // A signal that only became legible after peeling an encoding is worth more
      // than the same signal in plain sight: nobody base64-encodes their
      // documentation. Registering it as its own kind lets the compound rule treat
      // hiding as corroboration, which is what keeps the score MONOTONE — a
      // payload can never score better obfuscated than in the clear.
      //
      // The second clause is not optional. With only the lexicon clause, a payload
      // whose signals are ALL semantic — i.e. every non-English poisoning, which is
      // exactly what that layer exists for — was never marked concealed, and
      // base64-encoding a Russian payload moved its grade from F up to D.
      const concealed =
        [...kindsHit].some((k) => !rawKinds.has(k)) || (!defensive && extraShapes.length > 0);

      if (shapes.length >= 2) for (const s of shapes) kindsHit.add(s.kind);
      if (concealed) kindsHit.add('concealed');

      // PASS 2 — raise each standalone finding, applying mention-vs-use downgrades
      // now that kindsHit is complete (so corroboration can be judged).
      for (const { p, match, via } of hits) {
        let severity: Severity = p.meta.baseSeverity;
        let confidence = p.meta.baseConfidence;
        const corroborated = [...kindsHit].some((k) => k !== p.kind);

        // A hit recovered from an encoded layer is never an incidental mention:
        // documentation is not written in base64. The mention-vs-use downgrades
        // exist to protect tools that DOCUMENT these shapes in plain prose, so
        // they do not apply to something that had to be decoded first.
        if (MENTION_VS_USE_KINDS.has(p.kind) && !corroborated && via.length === 0) {
          if (p.kind === 'sensitive-target') {
            // A credential-path reference is only HIGH when a read/exfil verb sits
            // near it AND the tool is not itself an ssh/credentials/config utility
            // (whose subject legitimately IS that path).
            if (!EXFIL_VERB.test(field.text) || SELF_CREDENTIAL_TOOL.test(toolName ?? '')) {
              severity = 'low';
              confidence = 'heuristic';
            }
          } else if (p.kind === 'command-in-prose') {
            // A shell command is a HIGH accusation only when the model is told to
            // RUN it. In a shell/exec/delete tool documenting its own behaviour,
            // or a scanner, a bare "rm -rf" is an example — downgrade.
            if (!MODEL_RUN_DIRECTIVE.test(field.text) && (defensive || SHELL_TOOL_NAME.test(toolName ?? ''))) {
              severity = 'low';
              confidence = 'heuristic';
            }
          } else if (defensive) {
            // An override phrase documented in a detector/guard tool or guarded by
            // a "do not obey" caveat is being described, not planted.
            severity = 'low';
            confidence = 'heuristic';
          }
        }

        const hiddenIn = via.length > 0 ? describeChain(via) : undefined;
        findings.push({
          ruleId: p.id,
          title: hiddenIn ? `${p.meta.title} (hidden in ${hiddenIn})` : p.meta.title,
          category: 'injection',
          severity,
          confidence,
          description:
            `${p.meta.title} detected in the ${field.location.field ?? 'text'} of ` +
            `${field.location.kind}${field.location.name ? ` "${field.location.name}"` : ''}. ` +
            (hiddenIn
              ? `It is not visible in the literal text — it was recovered by decoding ${hiddenIn}. A human ` +
                `reviewing this metadata sees nothing; the model reads the decoded instruction. `
              : '') +
            `Instruction-like content in tool metadata is executed by the model, not the human, and is the ` +
            `primary tool-poisoning vector.`,
          remediation:
            'Tool descriptions should describe behavior, not instruct the assistant. Treat imperative / ' +
            'secrecy / sequencing language in metadata as hostile.',
          location: field.location,
          evidence: match.slice(0, 160),
          owasp: 'LLM01:2025 Prompt Injection',
          data: via.length > 0 ? { kind: p.kind, decodedVia: via } : { kind: p.kind },
        });
      }

      // Semantic secrecy directed at a human referent, in any language.
      //
      // Three conditions, each removing a distinct false positive:
      //  - a SECOND shape must corroborate. A lone "don't tell the user" is
      //    ordinary configuration prose — an audit over legitimate multilingual
      //    metadata found "do not notify the user audibly", "не сообщайте
      //    пользователю внутренние идентификаторы" and their German/French/
      //    Spanish equivalents all matching the shape with nothing behind it.
      //  - a human referent must be present, or the concealment has no victim.
      //  - the phrase lexicon must NOT already have charged this field. This
      //    rule exists for what the English regexes CANNOT see — a paraphrase or
      //    another language — so it never double-charges a plain English hit.
      const secrecyShape = shapes.find((s) => s.id === 'secrecy-shape');
      const alreadyLexical = rawKinds.has('secrecy') || rawKinds.has('override');
      if (secrecyShape && shapes.length >= 2 && hasUserRef && !alreadyLexical) {
        findings.push({
          ruleId: 'MTC-INJ-SEM-1',
          title: 'Concealment directive aimed at the assistant (language-agnostic)',
          category: 'injection',
          severity: 'medium',
          confidence: 'strong',
          description:
            `The ${field.location.field ?? 'text'} of ${field.location.kind}` +
            `${field.location.name ? ` "${field.location.name}"` : ''} combines a negation or stealth marker with ` +
            `a disclosure verb and a reference to the user — "keep this from the person" expressed as a shape ` +
            `rather than a fixed phrase, so it is detected regardless of wording or language. Metadata that ` +
            `tells the assistant what to withhold from its operator is not documentation.`,
          remediation:
            'Tool metadata must not instruct the assistant to withhold anything from the user. Describe what the ' +
            'tool does; leave disclosure to the client.',
          location: field.location,
          evidence: secrecyShape.evidence.slice(0, 160),
          owasp: 'LLM01:2025 Prompt Injection',
          data: { shape: secrecyShape.id },
        });
      }

      // Description ↔ schema coherence: prose that names a credential store the
      // tool's own interface cannot address. Language-neutral (it keys on literal
      // path identifiers), and it is the corroboration that separates a tool
      // legitimately documenting a path it accepts from one narrating a target
      // it has no parameter for.
      if (field.location.kind === 'tool' && field.location.field === 'description' && !defensive) {
        const tool = field.location.name ? toolByName.get(field.location.name) : undefined;
        const incoherentView = views.find((v) => referencesUnreachableCredential(tool, v.text));
        if (incoherentView) {
          const hiddenIn = incoherentView.via.length > 0 ? describeChain(incoherentView.via) : undefined;
          findings.push({
            ruleId: 'MTC-INJ-SCHEMA-1',
            title: 'Description names a credential store the tool cannot reach',
            category: 'injection',
            severity: 'medium',
            confidence: 'strong',
            description:
              `Tool "${field.location.name}" describes a credential store (SSH keys, cloud credentials, a ` +
              `keychain or an equivalent) that nothing in its input schema can address` +
              (hiddenIn ? `, and the reference only appears after decoding ${hiddenIn}` : '') +
              `. A tool's interface is the honest statement of what it touches; prose that reaches past it is ` +
              `addressed to the model, not to a reader.`,
            remediation:
              'Remove the reference, or expose the target as an explicit, validated parameter so the client can ' +
              'see and consent to what the tool reads.',
            location: field.location,
            evidence: (CREDENTIAL_TARGET.exec(incoherentView.text)?.[0] ?? '').slice(0, 120),
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
            data: incoherentView.via.length > 0 ? { decodedVia: incoherentView.via } : {},
          });
        }
      }

      // Escalation to CRITICAL requires a genuinely malicious signal — secrecy
      // (conceal from the user) or an instruction override — co-occurring with
      // at least one other poisoning signal (now including the weak shapes and
      // ALL-CAPS that no longer accuse on their own). A mere sensitive-target
      // reference or plain emphasis is not enough.
      const strongSignal = kindsHit.has('secrecy') || kindsHit.has('override');
      // When the strong signal exists ONLY inside an encoded layer, a tool whose
      // subject matter is prompt injection could be carrying a red-team fixture
      // rather than a payload. Ask one extra corroborating signal of it — and
      // only of it; nothing else about this gate changes.
      const strongOnlyFromDecode = strongSignal && !rawKinds.has('secrecy') && !rawKinds.has('override');
      const kindsNeeded = defensive && strongOnlyFromDecode ? 3 : 2;
      if (strongSignal && kindsHit.size >= kindsNeeded) {
        // Show what the model actually reads: the shallowest decoded recovery.
        const decodedPayload = concealed ? views.find((v) => v.via.length > 0)?.text : undefined;
        findings.push({
          ruleId: 'MTC-INJ-POISON',
          title: concealed ? 'Compound tool-poisoning pattern (concealed)' : 'Compound tool-poisoning pattern',
          category: 'injection',
          severity: 'critical',
          // Plain-text compounds stay `strong`: assembling the shape from prose
          // is an inference, and assertive documentation can imitate it. Once a
          // leg of that shape had to be DECODED out of the field, the inference
          // is gone — nobody encodes documentation — so the concealed variant is
          // `confirmed`. (A package scan still caps this back to `strong` via the
          // static-provenance rule in the engine, so an inferred tool surface can
          // never F-gate on a parser slip.)
          confidence: concealed ? 'confirmed' : 'strong',
          description:
            `Multiple tool-poisoning signals co-occur in a single field (${[...kindsHit].join(', ')}), including a ` +
            `concealment / override / sensitive-target directive. Together they form an instruction aimed at the ` +
            `model — the canonical tool-poisoning shape, not ordinary documentation.` +
            (concealed
              ? ` At least one of these signals is not present in the literal text and was recovered by decoding ` +
                `a hidden layer, so a human reviewing this metadata would not see it at all.`
              : ''),
          remediation: 'Do not install this server; the metadata is engineered to manipulate the assistant.',
          location: field.location,
          evidence: (decodedPayload ?? field.text).slice(0, 200),
          owasp: 'LLM01:2025 Prompt Injection',
          data: { kinds: [...kindsHit], ...(concealed ? { concealed: true } : {}) },
        });
      }

      // Base64 blob in prose paired with an explicit decode/execute verb.
      // Requires an actual DECODE verb near a blob — "execute"/"eval" describing
      // a tool's normal function (e.g. "execute batched operations") must not match.
      if (
        field.channel !== 'other' &&
        hasBase64Blob(field.text) &&
        /\b(decode|base64|atob|b64decode|un-?base64)\b/i.test(field.text)
      ) {
        findings.push({
          ruleId: 'MTC-INJ-ENC-2',
          title: 'Encoded blob paired with a decode/execute instruction',
          category: 'injection',
          severity: 'high',
          confidence: 'strong',
          description: 'A long base64-looking blob appears alongside a decode/execute instruction — a common way to hide a payload from reviewers.',
          location: field.location,
          evidence: field.text.slice(0, 160),
          owasp: 'LLM01:2025 Prompt Injection',
        });
      }

      // Embedded secret VALUE (a real credential, not merely a reference).
      for (const sp of SECRET_PATTERNS) {
        const m = field.text.match(sp.pattern);
        if (m) {
          findings.push({
            ruleId: 'MTC-INJ-SECRET-1',
            title: `Embedded ${sp.label} in ${field.location.field ?? 'metadata'}`,
            category: 'exfiltration',
            severity: 'high',
            confidence: 'confirmed',
            description:
              `A live-looking ${sp.label} is embedded in the ${field.location.field ?? 'metadata'} of ` +
              `${field.location.kind}${field.location.name ? ` "${field.location.name}"` : ''}. Hardcoded ` +
              `credentials in server metadata leak to every client that lists this server.`,
            remediation: 'Remove the credential and rotate it; never ship secrets in tool metadata.',
            location: field.location,
            evidence: `${sp.label}: ${m[0]!.slice(0, 4)}…(redacted)`,
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
            data: { secretType: sp.id },
          });
        }
      }

      // Suspicious external URL in metadata — a hardcoded webhook/paste/exfil
      // endpoint or raw IP in a tool description is a data-exfiltration channel
      // (the malicious-URL tool-poisoning move: "send the result to …").
      for (const um of field.text.matchAll(/\bhttps?:\/\/([^\s/"'`)\]]+)(\/[^\s"'`)]*)?/gi)) {
        const host = (um[1] ?? '').toLowerCase();
        const rest = um[2] ?? '';
        if (SUSPICIOUS_URL_HOST.test(host) || URL_IP_LITERAL.test(host) || SUSPICIOUS_URL_PATH.test(host + rest)) {
          findings.push({
            ruleId: 'MTC-INJ-URL-1',
            title: 'Suspicious external URL in tool metadata',
            category: 'exfiltration',
            severity: 'medium',
            confidence: 'strong',
            description:
              `A hardcoded link to a request/paste/webhook sink (or raw IP) appears in the ` +
              `${field.location.field ?? 'metadata'} of ${field.location.kind}` +
              `${field.location.name ? ` "${field.location.name}"` : ''}. Tool metadata pointing the model at a ` +
              `fixed external endpoint is a data-exfiltration channel — the classic "send the output to …" poisoning.`,
            remediation: 'A legitimate tool takes its destination as a validated parameter; it does not hardcode a webhook/paste sink in its description.',
            location: field.location,
            evidence: um[0].slice(0, 120),
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
          });
          break; // one per field is enough
        }
      }
    }

    // Suspicious hidden-parameter names.
    for (const tool of ctx.surface.tools) {
      if (!tool || typeof tool !== 'object') continue;
      const props = tool.inputSchema?.properties ?? {};
      for (const paramName of Object.keys(props)) {
        if (SUSPICIOUS_PARAM_NAMES.includes(paramName.toLowerCase())) {
          findings.push({
            ruleId: 'MTC-INJ-PARAM',
            title: `Suspicious hidden-channel parameter "${paramName}"`,
            category: 'injection',
            severity: 'medium',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" exposes a parameter named "${paramName}", a name frequently used as a ` +
              `hidden exfiltration channel (the model is told to stuff context/history/secrets into it).`,
            remediation: 'Verify what this parameter is actually used for; hidden "context"/"note" params are a red flag.',
            location: { kind: 'tool', name: tool.name, field: `inputSchema.properties.${paramName}` },
            owasp: 'LLM01:2025 Prompt Injection',
            data: { param: paramName },
          });
        }
      }
    }

    return findings;
  },
};
