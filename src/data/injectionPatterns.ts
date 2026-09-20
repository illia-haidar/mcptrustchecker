/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Prompt-injection / tool-poisoning pattern lexicon.
 *
 * These regexes model the *linguistic shape* of instructions aimed at the model
 * rather than the human — the signature of tool poisoning and "line jumping".
 * Keyword matching alone is deliberately weak (euphemism-based phrasing evades
 * it); it is only one signal. The heavy lifting for real exfiltration is
 * done by the capability / toxic-flow graph. These patterns catch the blatant
 * cases and raise the *confidence* axis, never the whole grade on their own.
 */

import type { Confidence, Severity } from '../types.js';

/** Which text channel a pattern is meaningful in. */
export type InjectionChannel = 'tool-description' | 'param-description' | 'server-instructions';

export type InjectionKind =
  | 'authority' // "IMPORTANT", "ATTENTION" — weak emphasis, common in legit docs
  | 'secrecy' // "do not tell the user" — concealment, a strong poisoning signal
  | 'override' // "ignore previous instructions" — a strong poisoning signal
  | 'sequencing' // "before executing any tool", "as the first step"
  | 'sensitive-target' // references ~/.ssh, .env, system prompt, chat history
  | 'exfil-param' // param whose description solicits context/environment
  | 'shadowing' // description names/redirects another tool or recipient
  | 'encoded-payload' // base64/hex blob paired with decode/execute
  | 'command-in-prose' // shell command embedded in prose
  | 'concealed'; // the signal was only readable after decoding a hidden layer

export interface InjectionPattern {
  id: string;
  kind: InjectionKind;
  /** Source regex (compiled case-insensitive, global by the detector). */
  pattern: RegExp;
  baseSeverity: Severity;
  baseConfidence: Confidence;
  title: string;
  channels: InjectionChannel[];
  /**
   * Whether a match may raise its OWN finding. Weak single-token shapes
   * (emphasis, self-ordering, context nouns, self-preference) are `false`: they
   * still register their `kind` toward the compound {@link INJECTION_PATTERNS}
   * tool-poisoning escalation, but never accuse a package on their own — a
   * precision audit found these fired ~100% on legitimate documentation
   * (acronyms, "IMPORTANT", "resolve the id first"). Defaults to `true`.
   */
  standalone?: boolean;
}

const ALL_CHANNELS: InjectionChannel[] = [
  'tool-description',
  'param-description',
  'server-instructions',
];

export const INJECTION_PATTERNS: InjectionPattern[] = [
  // --- Authority / secrecy / instruction-override ---
  {
    id: 'MTC-INJ-AUTH-1',
    kind: 'authority',
    pattern: /<?\bIMPORTANT\b>?|VERY IMPORTANT|\bATTENTION\b|\bMANDATORY\b/,
    baseSeverity: 'low',
    baseConfidence: 'heuristic',
    title: 'Authority framing in tool metadata',
    channels: ALL_CHANNELS,
    // Bare emphasis ("IMPORTANT", "ATTENTION") is ~100% FP standalone — it is
    // ordinary doc emphasis and often introduces a SAFETY warning to the model.
    // Kept only as a corroborating signal for the compound poisoning rule.
    standalone: false,
  },
  {
    id: 'MTC-INJ-AUTH-2',
    kind: 'override',
    pattern: /(ignore|disregard|forget) (all |your |the |any )?(previous|prior|above|earlier)( instructions| directions| context)?|override (all|previous|any|the) (instructions|directives)/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Instruction-override directive',
    channels: ALL_CHANNELS,
  },
  {
    id: 'MTC-INJ-SECRECY-1',
    kind: 'secrecy',
    pattern: /do not (tell|mention|inform|notify|reveal|show|display|print|log|output)( this| it)?( to)? the user|without (telling|informing|notifying) the user|do not mention this|never (tell|mention|reveal|present|inform|display)( the user| this)|(hide|conceal|keep)( this| it)? (hidden |secret )?from the user|concealed from the user/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Secrecy directive (conceal action from the user)',
    channels: ALL_CHANNELS,
  },
  // MTC-INJ-SECRECY-2 (policy/compliance framing) removed: it fired only on
  // literal compliance/audit tools where "for compliance" / "per policy" is
  // definitional. Genuine concealment is caught by SECRECY-1 (a hide verb + a
  // user referent), so the policy-framing variant added noise with no signal.
  // --- Sequencing / "do this first" line-jumping ---
  {
    id: 'MTC-INJ-SEQ-1',
    kind: 'sequencing',
    // "before using ANY/OTHER tool" is line-jumping; "before using THIS tool"
    // is legitimate self-documentation of a prerequisite and must not match.
    pattern: /before (executing|calling|using|running) (any|another|the other|other) (tool|command|function)|as the (first|very first) step,? (call|invoke|use)|always (consult|call|invoke) this tool( first| immediately)?|you must (also |always |first )?(call|invoke) (this|the )/,
    // Assertive "call X first" language is overwhelmingly legitimate self-ordering
    // of a server's OWN tools ("resolve the library id first", "authenticate
    // first"). Only dangerous as a corroborating signal alongside secrecy/override
    // (a genuinely hidden step), so it feeds the compound rule but never accuses
    // on its own.
    baseSeverity: 'medium',
    baseConfidence: 'strong',
    title: 'Forced-sequencing directive (line jumping)',
    channels: ALL_CHANNELS,
    standalone: false,
  },
  // MTC-INJ-SEQ-2 (the "when invoked / every time you" conditional) removed: it
  // matched ordinary "When to use this tool…" documentation at 0% precision and
  // is subsumed by SEQ-1's forced-sequencing shape.
  // --- Sensitive targets referenced in metadata ---
  {
    id: 'MTC-INJ-TARGET-1',
    kind: 'sensitive-target',
    // Only genuine credential-exfil paths (rare in legit tool docs). Bare
    // mentions of API_KEY/.env/SECRET_KEY are ubiquitous in legit auth/env tools
    // and were removed to avoid false trust hits.
    pattern: /~\/\.ssh|\bid_rsa\b|~\/\.aws\/credentials|\.aws\/credentials|~\/\.cursor\/mcp\.json|~\/\.config\/[^\s]*\/credentials/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Reference to a credential-exfiltration path in metadata',
    channels: ALL_CHANNELS,
  },
  {
    id: 'MTC-INJ-TARGET-2',
    kind: 'sensitive-target',
    // Soft signal: legitimate chat/agent/registry tools reference these as their
    // literal subject (clear_conversation, harden_system_prompt, get_config). A
    // bare context noun is not solicitation, so it never accuses on its own — it
    // only matters when it co-occurs with a steering/exfil directive (compound).
    pattern: /system prompt|conversation history|chat history|previous messages|environment details|list of (all )?(available )?tools/,
    baseSeverity: 'medium',
    baseConfidence: 'heuristic',
    title: 'Solicitation of model context / history',
    channels: ALL_CHANNELS,
    standalone: false,
  },
  // --- Exfil-shaped parameters (evaluated against param descriptions) ---
  {
    id: 'MTC-INJ-EXFIL-1',
    kind: 'exfil-param',
    // Must reference a genuinely sensitive object — not just "include all"
    // (which is ubiquitous in legit params like "include all commits").
    pattern: /(append|include|attach|paste|send|add) (the )?(full |entire |complete )?(value|contents?) of (the )?(environment|system prompt|secret|credential|\.env|ssh key|api key|private key|access token)/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Parameter description solicits secrets/environment to be sent along',
    channels: ['param-description'],
  },
  // --- Cross-tool shadowing (3 tiers by real threat, not just linguistic shape) ---
  {
    id: 'MTC-INJ-SHADOW-1',
    kind: 'shadowing',
    // HIGH: genuine redirection of a recipient/destination/credential — the
    // exfiltration/hijack primitive. This is the only form that reroutes data
    // through an attacker-chosen path.
    pattern: /redirect (all|the|any) (email|message|credential|token)|route (all|the|any) (email|message) (to|through)/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Cross-tool redirection of a recipient/credential',
    channels: ALL_CHANNELS,
  },
  {
    id: 'MTC-INJ-SHADOW-3',
    kind: 'shadowing',
    // HIGH: blanket SUPPRESSION of *all* sibling tools — a genuine tool-selection
    // hijack that crowds out legitimate (incl. security) tools.
    pattern: /do not (use|call) (the |any )?other tool|use this tool instead of (all )?other|ignore (the )?other tools/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Tool-selection hijack (suppress all other tools)',
    channels: ALL_CHANNELS,
  },
  {
    id: 'MTC-INJ-SHADOW-4',
    kind: 'shadowing',
    // LOW: self-promotion / comparative preference ("this is the only correct
    // tool", "use this instead of the analysis tool"). Ubiquitous in legitimate
    // assertive docs — the disparaged claim is often factually true and points at
    // the server's OWN tool with no sink. A confidence-axis nudge only; it still
    // escalates to critical via the compound-poisoning rule when it co-occurs
    // with a secrecy/override signal (e.g. "…and do not tell the user").
    pattern: /prefer (this|the following) tool|(this is the )?only (correct|valid|safe|right) tool|always prefer this tool|use this (tool )?instead of the \w+ (tool|function|server)|replaces? the \w+ (tool|function|server)|instead of (calling|using|invoking) the \w+ (tool|function|server)/,
    baseSeverity: 'low',
    baseConfidence: 'heuristic',
    title: 'Assertive tool self-preference (comparative)',
    channels: ALL_CHANNELS,
    // A standard intra-server doc idiom ("this is the main tool"); a whole
    // server's tools routinely carry it. Corroborating signal only.
    standalone: false,
  },
  // --- Encoded payloads ---
  {
    id: 'MTC-INJ-ENC-1',
    kind: 'encoded-payload',
    // Require a decode PAIRED with execution — a plain base64 utility only
    // decodes and must not be flagged.
    pattern: /decode (this|the following|the base64)[^.]{0,40}(execute|eval|run it|then run)|(base64|from base64)[^.]{0,25}(execute|eval|then run)|execute the (result|decoded|following)|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){2,}/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Encoded-payload decode/execute instruction',
    channels: ALL_CHANNELS,
  },
  // --- Shell commands embedded in prose ---
  {
    id: 'MTC-INJ-CMD-1',
    kind: 'command-in-prose',
    pattern: /\b(rm -rf|chmod -R|curl [^\s]+ ?\| ?(sh|bash)|wget [^\s]+ ?\| ?(sh|bash)|cat ~\/|\/bin\/(sh|bash)\b|nc -e|bash -c)\b/,
    baseSeverity: 'high',
    baseConfidence: 'strong',
    title: 'Shell command embedded in tool metadata',
    channels: ALL_CHANNELS,
  },
];

/**
 * Parameter *names* that front for hidden exfiltration channels. Kept
 * high-precision: generic names like `context`/`metadata`/`feedback`/`notes`
 * are excluded because they are overwhelmingly used legitimately.
 */
export const SUSPICIOUS_PARAM_NAMES = [
  'side_note',
  'sidenote',
  'sidechannel',
  'summary_of_environment_details',
  'environment_details',
];

/** ALL-CAPS run detector: >= this many consecutive shouted words is suspicious. */
export const ALLCAPS_RUN_WORDS = 3;

/**
 * Hosts that are almost never a legitimate destination inside tool metadata —
 * one-shot request/paste/webhook/exfil sinks and URL shorteners. A hardcoded
 * link to one of these in a tool description is a data-exfiltration channel
 * ("send the result to …"), the classic malicious-URL tool-poisoning move.
 */
export const SUSPICIOUS_URL_HOST =
  /(?:^|\.)(?:webhook\.site|requestbin\.(?:net|com)|requestbin\.io|hookb\.in|pipedream\.net|beeceptor\.com|ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|pastebin\.com|hastebin\.com|dpaste\.(?:com|org)|ix\.io|0x0\.st|transfer\.sh|file\.io|bit\.ly|tinyurl\.com|is\.gd|t\.co|interactsh\.com|oast\.(?:fun|site|live|pro|me)|canarytokens\.com|burpcollaborator\.net)$/i;

/** Webhook/bot endpoints whose PATH marks them as an exfil sink. */
export const SUSPICIOUS_URL_PATH = /discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot|hooks\.slack\.com\/services\//i;

/** A bare IPv4/IPv6 literal as a URL host — a link to a raw address, not a name. */
export const URL_IP_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$|^\[[0-9a-f:]+\]$/i;

/**
 * High-precision secret-value patterns. A match is an actual embedded
 * credential (not merely a reference to one), so it is `confirmed`. Evidence is
 * always redacted to a short prefix — never echo the secret.
 */
export const SECRET_PATTERNS: { id: string; label: string; pattern: RegExp }[] = [
  { id: 'aws-access-key', label: 'AWS access key id', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'github-token', label: 'GitHub token', pattern: /\bgh[posru]_[0-9A-Za-z]{36}\b/ },
  { id: 'slack-token', label: 'Slack token', pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'google-api-key', label: 'Google API key', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'stripe-secret', label: 'Stripe secret key', pattern: /\bsk_live_[0-9A-Za-z]{24,}\b/ },
  { id: 'openai-key', label: 'OpenAI key', pattern: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/ },
  // The header alone is not a key: security tooling (redaction filters, secret
  // scanners, docs) legitimately contains that literal in order to FIND keys.
  // A real embedded key is the header followed by its base64 body, so require
  // one — that is what separates a leaked secret from a pattern that hunts it.
  { id: 'private-key', label: 'PEM private key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{100,}/ },
  { id: 'jwt', label: 'JSON Web Token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/ },
];
