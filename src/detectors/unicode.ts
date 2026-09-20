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

// ESC (U+001B) then a CSI ([ ... final byte) or OSC (] ... BEL/ST) sequence.
const ANSI_ESCAPE = /\u001b(?:\[[0-9;?]*[ -\/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\))/;

interface FamilyHit {
  family: InvisibleFamily;
  count: number;
  decoded?: string;
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

/** Group invisible-character hits by family, decoding payload channels. */
export function analyzeText(text: string): FamilyHit[] {
  if (typeof text !== 'string') return [];
  const acc = new Map<InvisibleFamily, { count: number; tagChars: string[]; vsBytes: number[] }>();
  const chars = [...text];
  for (let i = 0; i < chars.length; i++) {
    const cp = chars[i]!.codePointAt(0);
    if (cp === undefined) continue;
    const fam = classifyCodepoint(cp);
    if (!fam) continue;
    // Skip legitimate emoji constructs that reuse smuggling-family codepoints.
    if (fam === 'variation-selector' && !vsIsSmuggling(chars, i, cp)) continue;
    if (fam === 'zero-width' && zwjIsEmojiSequence(chars, i, cp)) continue;
    const entry = acc.get(fam) ?? { count: 0, tagChars: [], vsBytes: [] };
    entry.count += 1;
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
    if (family === 'tags' && entry.tagChars.length > 0) hit.decoded = entry.tagChars.join('');
    if (family === 'variation-selector' && entry.vsBytes.length > 2) hit.decoded = bytesToReadable(entry.vsBytes);
    hits.push(hit);
  }
  return hits;
}

/** Resolve the Unicode script names present in a string (Latin, Cyrillic, …). */
function scriptsOf(text: string): Set<string> {
  const scripts = new Set<string>();
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
    }
  }
  return scripts;
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

export const unicodeDetector: Detector = {
  id: 'unicode',
  stage: 1,
  title: 'Lexical / Unicode integrity',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const threshold = ctx.config.invisibleCharThreshold;

    for (const field of collectTextFields(ctx.surface)) {
      for (const hit of analyzeText(field.text)) {
        const { severity, confidence } = severityFor(hit.family, hit.count, threshold);
        const label = FAMILY_LABELS[hit.family];
        const decodedNote = hit.decoded ? ` Decoded hidden payload: "${hit.decoded}".` : '';
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
          data: { family: hit.family, count: hit.count, decoded: hit.decoded },
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
      const scripts = scriptsOf(field.text);
      if (scripts.size > 1) {
        findings.push({
          ruleId: 'MTC-UNI-009',
          title: `Mixed-script (homoglyph) text in ${field.location.field ?? field.location.kind}`,
          category: 'injection',
          severity: 'high',
          confidence: 'strong',
          description:
            `A single token mixes multiple scripts (${[...scripts].join(', ')}). This is the signature of a ` +
            `homoglyph attack — visually identical characters from another script used to impersonate a ` +
            `trusted name or slip past keyword filters.`,
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
