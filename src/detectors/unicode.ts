/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 1 — Lexical / Unicode integrity.
 *
 * Scans every text field for the invisible-character families used to smuggle
 * instructions past human review, and **decodes** the two families that carry a
 * payload (Tags block, variation-selector channel) so the recovered text is
 * surfaced as evidence. Also runs a mixed-script (homoglyph) check using Unicode
 * script properties — a codepoint blocklist cannot catch visible confusables.
 */

import type { Detector, DetectorContext, Finding } from '../types.js';
import { collectTextFields } from '../util/text.js';
import {
  classifyCodepoint,
  decodeTagCodepoint,
  decodeVariationSelectorByte,
  FAMILY_LABELS,
  type InvisibleFamily,
} from '../data/unicode.js';

// ESC (U+001B) then a CSI ([ ... final byte) or OSC (] ... BEL/ST) sequence —
// or the same with its 8-bit introducer, U+009B (CSI) or U+009D (OSC), which a
// terminal honours just the same. The 8-bit forms are bounded and allow no space
// before the final byte, so mojibake ("›" decoded as U+009B, then " Advanced")
// does not read as a cursor command.
const ANSI_ESCAPE =
  /\u001b(?:\[[0-9;?]*[ -\/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\))|\u009b[0-9;?]{0,16}[!-\/]{0,2}[@-~]|\u009d[^\u0007\u001b\u009c]{0,512}(?:\u0007|\u001b\\|\u009c)/;

interface FamilyHit {
  family: InvisibleFamily;
  count: number;
  decoded?: string;
  /** Every control character in the field is a lone C1 left by a broken re-encoding. */
  mojibake?: boolean;
}

function bytesToReadable(bytes: number[]): string {
  const printable = bytes.every((b) => b >= 0x20 && b <= 0x7e);
  if (printable) return Buffer.from(bytes).toString('latin1');
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

const EMOJI_BASE = /\p{Extended_Pictographic}/u;

function isVariationSelector(cp: number | undefined): boolean {
  return cp !== undefined && classifyCodepoint(cp) === 'variation-selector';
}

/**
 * Is a variation selector at index `i` part of a genuine smuggling channel
 * rather than a legitimate emoji-presentation / keycap selector?
 *
 *  - U+E0100–U+E01EF (supplementary selectors) encode bytes 16–255 and have no
 *    legitimate use in tool metadata → always a channel.
 *  - Otherwise (VS1–VS16, U+FE00–U+FE0F): a LONE selector is a legitimate
 *    presentation selector (⚠️) or keycap sequence (1️⃣) and must NOT be flagged.
 *    Only a RUN of ≥2 consecutive selectors — the one-selector-per-payload-byte
 *    signature of emoji smuggling — counts.
 */
function vsIsSmuggling(chars: string[], i: number, cp: number): boolean {
  if (cp >= 0xe0100 && cp <= 0xe01ef) return true;
  const prev = i > 0 ? chars[i - 1]?.codePointAt(0) : undefined;
  const next = chars[i + 1]?.codePointAt(0);
  return isVariationSelector(prev) || isVariationSelector(next);
}

/** Is the neighbor in direction `dir` (skipping variation selectors) an emoji? */
function neighborIsEmoji(chars: string[], from: number, dir: number): boolean {
  for (let j = from; j >= 0 && j < chars.length; j += dir) {
    const c = chars[j]?.codePointAt(0);
    if (isVariationSelector(c)) continue; // skip presentation selectors in the sequence
    return c !== undefined && EMOJI_BASE.test(String.fromCodePoint(c));
  }
  return false;
}

/**
 * A ZERO-WIDTH JOINER (U+200D) flanked by emoji is a legitimate emoji ZWJ
 * sequence (👨‍💻, 🧑‍🔬) — not smuggling. Only exempt that exact shape.
 */
function zwjIsEmojiSequence(chars: string[], i: number, cp: number): boolean {
  if (cp !== 0x200d) return false;
  return neighborIsEmoji(chars, i - 1, -1) && neighborIsEmoji(chars, i + 1, 1);
}

// Scripts whose orthography itself uses ZWNJ / ZWJ between letters: Persian
// "mi + ZWNJ + konad" (U+200C) keeps the prefix from joining, and Indic conjuncts are
// shaped with a joiner beside the virama. Script_Extensions, so the combining
// marks those letters carry (Inherited harakat, viramas) count with their script.
// The first two (Arabic, Syriac) spell only with ZWNJ: Persian and Urdu do not
// put a ZWJ between letters, and between letters that already join it changes
// nothing a reader sees.
const JOINER_ORTHOGRAPHY: RegExp[] = [
  /\p{scx=Arabic}/u,
  /\p{scx=Syriac}/u,
  /\p{scx=Devanagari}/u,
  /\p{scx=Bengali}/u,
  /\p{scx=Gurmukhi}/u,
  /\p{scx=Gujarati}/u,
  /\p{scx=Oriya}/u,
  /\p{scx=Tamil}/u,
  /\p{scx=Telugu}/u,
  /\p{scx=Kannada}/u,
  /\p{scx=Malayalam}/u,
  /\p{scx=Sinhala}/u,
];
const ZWNJ_ONLY_SCRIPTS = 2;
const LETTER_OR_MARK = /^[\p{L}\p{M}]$/u;
const LETTER = /^\p{L}$/u;
const MARK = /^\p{M}$/u;
// The Indic viramas (and Sinhala al-lakuna) a conjunct joiner stands beside.
const VIRAMA = /^[\u094D\u09CD\u0A4D\u0ACD\u0B4D\u0BCD\u0C4D\u0CCD\u0D4D\u0DCA]$/u;
/** Spelling uses joiners sparingly: past one per this many letters of the script, they are a channel. */
const LETTERS_PER_JOINER = 4;

/**
 * The joiner script (index into {@link JOINER_ORTHOGRAPHY}) whose spelling
 * explains the ZWNJ / ZWJ at `i`, or -1. Its neighbours must be letters of that
 * script — a mark counts with the letter it sits on, so Arabic fatha around a
 * LATIN letter does not make "ign\u064E\u200D\u064Eore" Arabic. In Arabic and
 * Syriac only ZWNJ is spelling; in the Indic scripts a joiner is spelling only
 * beside a virama (क्‍ष, ක්‍ය, Bengali র‍্য).
 */
function orthographicScript(chars: string[], i: number, cp: number): number {
  if (cp !== 0x200c && cp !== 0x200d) return -1;
  const prev = chars[i - 1];
  const next = chars[i + 1];
  if (!prev || !next || !LETTER_OR_MARK.test(prev) || !LETTER_OR_MARK.test(next)) return -1;
  // A mark after the joiner sits on nothing but a virama's conjunct.
  if (MARK.test(next) && !VIRAMA.test(next)) return -1;
  let b = i - 1;
  for (let k = 0; b > 0 && k < 6 && MARK.test(chars[b]!); k++) b--;
  const base = chars[b]!;
  if (!LETTER.test(base)) return -1;
  const script = JOINER_ORTHOGRAPHY.findIndex((re) => re.test(base) && re.test(prev) && re.test(next));
  if (script < 0) return -1;
  if (script < ZWNJ_ONLY_SCRIPTS) return cp === 0x200c ? script : -1;
  return VIRAMA.test(prev) || VIRAMA.test(next) ? script : -1;
}

/**
 * The joiners that are spelling: those {@link orthographicScript} explains, in a
 * script where they stay sparse. Persian runs at a few per hundred letters
 * (hamravesh: 93 ZWNJ in 2,856 Arabic letters); a joiner after every letter is
 * a bit channel, and then none of them is excused.
 */
function orthographicJoiners(chars: string[]): Set<number> {
  const byScript = new Map<number, number[]>();
  for (let i = 0; i < chars.length; i++) {
    const cp = chars[i]!.codePointAt(0)!;
    if (cp !== 0x200c && cp !== 0x200d) continue;
    const script = orthographicScript(chars, i, cp);
    if (script < 0) continue;
    const list = byScript.get(script) ?? [];
    list.push(i);
    byScript.set(script, list);
  }
  const out = new Set<number>();
  for (const [script, joiners] of byScript) {
    const re = JOINER_ORTHOGRAPHY[script]!;
    let letters = 0;
    for (const ch of chars) if (LETTER.test(ch) && re.test(ch)) letters++;
    if (joiners.length * LETTERS_PER_JOINER <= letters) for (const i of joiners) out.add(i);
  }
  return out;
}

// Punctuation and symbols outside ASCII — the characters whose UTF-8 bytes a
// mis-decode most often splits, leaving one stray C1 control behind ("—" + U+009D).
const MULTIBYTE_PUNCT = /^[\p{P}\p{S}]$/u;

function isC1(cp: number | undefined): boolean {
  return cp !== undefined && cp >= 0x80 && cp <= 0x9f;
}

/**
 * The C1 code points a Windows-1252 mis-decode can leave behind: the five bytes
 * cp1252 does not define. Every other C1 (U+009B CSI above all) is a control a
 * terminal acts on, not debris.
 */
const CP1252_UNDEFINED = new Set([0x81, 0x8d, 0x8f, 0x90, 0x9d]);

/**
 * A lone C1 control straight after non-ASCII punctuation is mojibake — debris
 * of a broken re-encoding — not a channel: it carries no payload and a run of
 * them is not formed. Only a byte cp1252 leaves undefined qualifies, and only
 * when no escape-sequence parameter follows it (a space, the end, or non-ASCII
 * text does; "8m", "2J", "?25l" do not).
 */
function c1IsMojibake(chars: string[], i: number, cp: number): boolean {
  if (!isC1(cp) || !CP1252_UNDEFINED.has(cp)) return false;
  const prev = chars[i - 1];
  const prevCp = prev?.codePointAt(0);
  if (!prev || prevCp === undefined || prevCp < 0x80 || !MULTIBYTE_PUNCT.test(prev)) return false;
  const next = chars[i + 1];
  return !isC1(next?.codePointAt(0)) && !/^[\x21-\x7e]$/.test(next ?? ' ');
}

/** Group invisible-character hits by family, decoding payload channels. */
export function analyzeText(text: string): FamilyHit[] {
  if (typeof text !== 'string') return [];
  const acc = new Map<InvisibleFamily, { count: number; tagChars: string[]; vsBytes: number[]; mojibake: number }>();
  const chars = [...text];
  // Only a field that carries a joiner pays for the orthography pass.
  const spelling = /[\u200c\u200d]/.test(text) ? orthographicJoiners(chars) : undefined;
  for (let i = 0; i < chars.length; i++) {
    const cp = chars[i]!.codePointAt(0);
    if (cp === undefined) continue;
    const fam = classifyCodepoint(cp);
    if (!fam) continue;
    // Skip legitimate emoji constructs that reuse smuggling-family codepoints.
    if (fam === 'variation-selector' && !vsIsSmuggling(chars, i, cp)) continue;
    if (fam === 'zero-width' && zwjIsEmojiSequence(chars, i, cp)) continue;
    // …and the joiners that Persian, Arabic, Syriac and Indic spelling require.
    if (fam === 'zero-width' && spelling?.has(i)) continue;
    const entry = acc.get(fam) ?? { count: 0, tagChars: [], vsBytes: [], mojibake: 0 };
    entry.count += 1;
    if (fam === 'control' && c1IsMojibake(chars, i, cp)) entry.mojibake += 1;
    if (fam === 'tags') {
      const d = decodeTagCodepoint(cp);
      if (d) entry.tagChars.push(d);
    } else if (fam === 'variation-selector') {
      const b = decodeVariationSelectorByte(cp);
      if (b !== null) entry.vsBytes.push(b);
    }
    acc.set(fam, entry);
  }

  const hits: FamilyHit[] = [];
  for (const [family, entry] of acc) {
    const hit: FamilyHit = { family, count: entry.count };
    if (entry.mojibake > 0 && entry.mojibake === entry.count) hit.mojibake = true;
    if (family === 'tags' && entry.tagChars.length > 0) hit.decoded = entry.tagChars.join('');
    if (family === 'variation-selector' && entry.vsBytes.length > 2) hit.decoded = bytesToReadable(entry.vsBytes);
    hits.push(hit);
  }
  return hits;
}

/**
 * Resolve the Unicode script names (Latin, Cyrillic, …) that a single token of
 * the string mixes, and the tokens that mix them.
 */
function mixedScriptTokens(text: string): { scripts: Set<string>; tokens: string[] } {
  const scripts = new Set<string>();
  const mixed: string[] = [];
  const named: [string, RegExp][] = [
    ['Latin', /\p{Script=Latin}/u],
    ['Cyrillic', /\p{Script=Cyrillic}/u],
    // Greek only counts when the character is genuinely Latin-CONFUSABLE (Α Β Ε
    // Κ Μ Ν Ο Ρ Τ Υ Χ ο ρ …) — not math symbols like Δ Ω Σ Φ Ψ Π μ, which appear
    // constantly in legitimate technical metadata ("ΔT", "kΩ") and are not a
    // homoglyph attack.
    ['Greek', /[ΑΒΕΖΗΙΚΜΝΟΡΤΥΧκνορυχ]/u],
    ['Armenian', /\p{Script=Armenian}/u],
    ['Hebrew', /\p{Script=Hebrew}/u],
  ];
  // Evaluate per token so a legitimately multilingual description isn't flagged;
  // only a single token that mixes scripts is confusable. Tokenize on LETTER RUNS
  // (split on every non-letter, incl. hyphens/underscores/digits) not whitespace,
  // so a bilingual COMPOUND like "MCP-сервер" or "voximplant_клиент" splits into
  // separate single-script runs instead of one mixed token — a real homoglyph
  // ("pаypal", "gоogle") has no separator and still stays one mixed run.
  for (const token of text.split(/[^\p{L}]+/u)) {
    if (token.length < 2) continue;
    const tokenScripts = new Set<string>();
    for (const [name, re] of named) if (re.test(token)) tokenScripts.add(name);
    if (tokenScripts.size > 1) {
      for (const s of tokenScripts) scripts.add(s);
      mixed.push(token);
    }
  }
  return { scripts, tokens: mixed };
}

// A tool whose job is to find confusables: a homoglyph in its own documentation
// is the thing it detects, quoted. Bounded to a name token: `flint_query` and
// `splinter` are not linters.
const DEFENSIVE_UNI_NAME = /(?:^|[_\W])(?:lint|homoglyph|confusabl|spoof|punycode|mixed[_-]?script)/i;
// The same example frames the injection detector honours; `e.g.` needs its period.
const EXAMPLE_FRAME = /\be\.\s?g\.|\bi\.\s?e\.|\bfor (?:example|instance)\b|\bsuch as\b|\bexamples?\s*:|\bpatterns? like\b/i;
const FRAME_REACH = 60;
/** A quoted example is one short token; prose written in confusables is not one. */
const MAX_QUOTED_TOKEN = 32;
const MAX_QUOTED_TOKENS = 2;
// Fields that name or present an identity — what a homoglyph impersonates. A
// homoglyph there is never excused.
const IDENTITY_FIELDS = new Set(['name', 'title', 'annotations.title', 'uri', 'uriTemplate']);

/**
 * Is every mixed-script token a short QUOTED example — inside a code span or
 * quotes ("``sk\u0430bc``", "'p\u0430ypal'"), at most {@link MAX_QUOTED_TOKENS} of
 * them — and, with `framed`, right after an example frame ("e.g. ``sk\u0430bc``")?
 * Prose written in confusables ("e.g. ign\u043Ere all previous instructi\u043Ens")
 * is several unquoted tokens and is no example.
 */
function mixedTokensQuoted(text: string, tokens: string[], framed: boolean): boolean {
  if (tokens.length === 0 || tokens.length > MAX_QUOTED_TOKENS) return false;
  let from = 0;
  for (const token of tokens) {
    if (token.length > MAX_QUOTED_TOKEN) return false;
    const at = text.indexOf(token, from);
    if (at < 0) return false;
    // The quote or code-span mark opens right before the token (a word of the
    // same span may precede it) and closes after it, on the same line.
    // An apostrophe inside a word ("PayPal's") is no quote.
    const open = /(?<!\p{L})(?:``?|['"“‘])[^`'"“”‘’\n]{0,24}$/u.exec(text.slice(Math.max(0, at - 26), at));
    if (!open) return false;
    const close = text.slice(at + token.length, at + token.length + 40);
    if (!/^[^`'"“”‘’\n]{0,24}(?:``?|['"”’])(?!\p{L})/u.test(close)) return false;
    if (framed) {
      const openAt = at - open[0].length;
      if (!EXAMPLE_FRAME.test(text.slice(Math.max(0, openAt - FRAME_REACH), openAt))) return false;
    }
    from = at + token.length;
  }
  return true;
}

function severityFor(family: InvisibleFamily, count: number, threshold: number): {
  severity: Finding['severity'];
  confidence: Finding['confidence'];
} {
  switch (family) {
    case 'tags':
      return { severity: 'critical', confidence: 'confirmed' };
    case 'variation-selector':
      return count > 2 ? { severity: 'high', confidence: 'confirmed' } : { severity: 'medium', confidence: 'heuristic' };
    case 'bidi-override':
      return { severity: 'high', confidence: 'strong' };
    case 'control':
      return { severity: 'high', confidence: 'strong' };
    case 'zero-width':
    case 'invisible-math':
      return count >= threshold
        ? { severity: 'high', confidence: 'strong' }
        : { severity: 'medium', confidence: 'heuristic' };
    case 'bidi-isolate':
    case 'bidi-mark':
    case 'default-ignorable':
      return { severity: 'medium', confidence: 'heuristic' };
    case 'unusual-whitespace':
      return { severity: 'low', confidence: 'heuristic' };
    default:
      return { severity: 'low', confidence: 'speculative' };
  }
}

const FAMILY_RULE: Record<InvisibleFamily, string> = {
  tags: 'MTC-UNI-001',
  'variation-selector': 'MTC-UNI-002',
  'bidi-override': 'MTC-UNI-003',
  'bidi-isolate': 'MTC-UNI-004',
  'bidi-mark': 'MTC-UNI-004',
  'zero-width': 'MTC-UNI-005',
  'invisible-math': 'MTC-UNI-005',
  'default-ignorable': 'MTC-UNI-006',
  'unusual-whitespace': 'MTC-UNI-007',
  control: 'MTC-UNI-008',
};

/**
 * Are the control characters of a statically recovered tool's field absent from
 * its source file as written? Then an escape sequence in a non-raw string literal
 * (`"\1"`, `"\x01"`) put them there — the language decodes it, and the running
 * server sends the decoded character.
 */
function controlFromEscape(ctx: DetectorContext, kind: string, name: string | undefined, text: string): boolean {
  const tools = ctx.surface.staticTools;
  const origin = kind === 'tool' && name && ctx.surface.toolProvenance === 'static' && tools && Object.hasOwn(tools, name) ? tools[name] : undefined;
  const files = Array.isArray(ctx.surface.sourceFiles) ? ctx.surface.sourceFiles : [];
  const file = origin && files.find((f) => f && f.path === origin.file);
  if (!file || typeof file.content !== 'string') return false;
  const controls = new Set([...text].filter((ch) => classifyCodepoint(ch.codePointAt(0)!) === 'control'));
  return controls.size > 0 && [...controls].every((ch) => !file.content.includes(ch));
}

export const unicodeDetector: Detector = {
  id: 'unicode',
  stage: 1,
  title: 'Lexical / Unicode integrity',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const threshold = ctx.config.invisibleCharThreshold;

    for (const field of collectTextFields(ctx.surface)) {
      for (const hit of analyzeText(field.text)) {
        const { severity, confidence } = hit.mojibake
          ? { severity: 'low' as const, confidence: 'heuristic' as const }
          : severityFor(hit.family, hit.count, threshold);
        const label = FAMILY_LABELS[hit.family];
        const decodedNote = hit.decoded
          ? ` Decoded hidden payload: "${hit.decoded}".`
          : hit.mojibake
            ? ' Each one sits alone right after non-ASCII punctuation — the debris of a broken re-encoding (mojibake) rather than a hidden channel.'
            : hit.family === 'control' && controlFromEscape(ctx, field.location.kind, field.location.name, field.text)
              ? ' They are not in the source file as written: an escape sequence in a non-raw string literal ' +
                '(such as "\\1" or "\\x01") decodes to them, and the running server sends the decoded characters. If the ' +
                'backslash was meant literally, use a raw string or escape the backslash.'
              : '';
        findings.push({
          ruleId: FAMILY_RULE[hit.family],
          title: `Hidden ${label} in ${field.location.field ?? field.location.kind}`,
          category: 'injection',
          severity,
          confidence,
          description:
            `Found ${hit.count} ${label} character(s) in the ${field.location.field ?? 'text'} of ` +
            `${field.location.kind}${field.location.name ? ` "${field.location.name}"` : ''}. ` +
            `These are invisible to a human reviewer but are read verbatim by the model.${decodedNote}`,
          remediation:
            'Reject or normalize server metadata containing invisible/smuggling characters. ' +
            'Legitimate tool descriptions do not need them.',
          location: field.location,
          evidence: hit.decoded ?? `${hit.count}× ${hit.family}`,
          owasp: 'LLM01:2025 Prompt Injection',
          references: ['https://unicode.org/reports/tr39/'],
          data: { family: hit.family, count: hit.count, decoded: hit.decoded, ...(hit.mojibake ? { mojibake: true } : {}) },
        });
      }

      // ANSI / CSI terminal escape sequences: hidden/overwritten text and color
      // tricks enable consent phishing in a terminal client. No legitimate
      // reason for them to be in server metadata.
      if (ANSI_ESCAPE.test(field.text)) {
        findings.push({
          ruleId: 'MTC-UNI-010',
          title: `ANSI terminal escape sequence in ${field.location.field ?? field.location.kind}`,
          category: 'injection',
          severity: 'high',
          confidence: 'strong',
          description:
            'A terminal escape (ANSI/CSI/OSC) sequence is embedded in server metadata. In a terminal client these ' +
            'can move the cursor, hide, recolor, or overwrite text — so the action a user approves can differ from ' +
            'what is displayed (consent phishing).',
          remediation: 'Strip control/escape sequences from server metadata before displaying it.',
          location: field.location,
          evidence: JSON.stringify(field.text.slice(0, 60)),
          owasp: 'LLM01:2025 Prompt Injection',
        });
      }

      // Mixed-script / homoglyph check (visible confusables).
      const { scripts, tokens } = mixedScriptTokens(field.text);
      if (scripts.size > 1) {
        // Mention vs use, as in the injection detector: a homoglyph quoted as an
        // example ("e.g. ``sk\u0430bc...``") in the docs of a tool that hunts
        // homoglyphs is its subject, and is dropped. A short quoted example after
        // a frame, or quoted in such a tool's docs, is lowered. Anything else —
        // prose in confusables behind an "e.g.", an unquoted token in a linter's
        // text — stays high. A field that names or presents an identity (a name, a
        // title, a resource URI) is never excused: it is what gets impersonated.
        const identity = IDENTITY_FIELDS.has(field.location.field ?? '');
        const defensiveTool = !identity && field.location.kind === 'tool' && DEFENSIVE_UNI_NAME.test(field.location.name ?? '');
        const quoted = !identity && mixedTokensQuoted(field.text, tokens, false);
        const framed = quoted && mixedTokensQuoted(field.text, tokens, true);
        if (defensiveTool && framed) continue;
        const mention = quoted && (defensiveTool || framed);
        findings.push({
          ruleId: 'MTC-UNI-009',
          title: `Mixed-script (homoglyph) text in ${field.location.field ?? field.location.kind}`,
          category: 'injection',
          severity: mention ? 'low' : 'high',
          confidence: mention ? 'heuristic' : 'strong',
          description:
            `A single token mixes multiple scripts (${[...scripts].join(', ')}). This is the signature of a ` +
            `homoglyph attack — visually identical characters from another script used to impersonate a ` +
            `trusted name or slip past keyword filters.` +
            (mention ? ' Here it reads as a quoted example or the subject of a confusable-checking tool, so it is reported low.' : ''),
          remediation: 'Restrict metadata to a single script, or normalize confusables before display.',
          location: field.location,
          evidence: field.text.slice(0, 120),
          owasp: 'LLM01:2025 Prompt Injection',
          references: ['https://unicode.org/reports/tr39/'],
          data: { scripts: [...scripts] },
        });
      }
    }

    return findings;
  },
};
