/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Unicode threat data (pinned to Unicode 17.0.0).
 *
 * These are the codepoint families used to *smuggle* instructions into text an
 * LLM reads but a human reviewer does not. MCP Trust Checker's rule is to **decode, not
 * just strip** — where a family carries a payload (Tags block, variation
 * selectors) we recover and surface it as evidence.
 *
 * References:
 *  - Unicode UAX #9 (BiDi), UTS #39 (Security Mechanisms), UAX #44 (Character DB)
 *  - BiDi override source attacks (CVE-2021-42574)
 *  - "Invisible prompt injection" via Tags block & variation-selector channels
 */

export type InvisibleFamily =
  | 'tags' // U+E0000 block — ASCII mirror, decode with cp - 0xE0000
  | 'variation-selector' // 256-byte side channel
  | 'bidi-override' // reorder visible text
  | 'bidi-isolate'
  | 'bidi-mark'
  | 'zero-width' // zero-width space/joiner/non-joiner/BOM
  | 'invisible-math' // U+2060–2064 used as steganographic bits
  | 'default-ignorable' // soft hyphen, interlinear annotation, etc.
  | 'unusual-whitespace' // non-breaking / ideographic / thin spaces
  | 'control'; // C0/C1 control chars (except tab/newline/CR)

export interface CodepointRange {
  start: number;
  end: number;
  family: InvisibleFamily;
}

/** Ordered, non-overlapping ranges scanned by the Unicode detector. */
export const INVISIBLE_RANGES: CodepointRange[] = [
  // Tags block (ASCII mirror) — the highest-signal smuggling channel.
  { start: 0xe0000, end: 0xe007f, family: 'tags' },
  // Variation selectors (VS1–VS16 and the supplementary VS17–VS256 side channel).
  { start: 0xfe00, end: 0xfe0f, family: 'variation-selector' },
  { start: 0xe0100, end: 0xe01ef, family: 'variation-selector' },
  // BiDi overrides & embeddings.
  { start: 0x202a, end: 0x202e, family: 'bidi-override' },
  // BiDi isolates.
  { start: 0x2066, end: 0x2069, family: 'bidi-isolate' },
  // BiDi marks.
  { start: 0x200e, end: 0x200f, family: 'bidi-mark' },
  { start: 0x061c, end: 0x061c, family: 'bidi-mark' },
  // Zero-width family.
  { start: 0x200b, end: 0x200b, family: 'zero-width' }, // ZWSP
  { start: 0x200c, end: 0x200d, family: 'zero-width' }, // ZWNJ, ZWJ
  { start: 0xfeff, end: 0xfeff, family: 'zero-width' }, // BOM / ZWNBSP
  // Invisible math operators (used as 0/1 bits).
  { start: 0x2060, end: 0x2064, family: 'invisible-math' },
  // Other default-ignorables.
  { start: 0x00ad, end: 0x00ad, family: 'default-ignorable' }, // soft hyphen
  { start: 0x180e, end: 0x180e, family: 'default-ignorable' }, // Mongolian vowel separator
  { start: 0x17b4, end: 0x17b5, family: 'default-ignorable' }, // Khmer inherent vowels
  { start: 0xfff9, end: 0xfffb, family: 'default-ignorable' }, // interlinear annotation
  { start: 0x2028, end: 0x2029, family: 'default-ignorable' }, // line / paragraph separator
  // Unusual whitespace.
  { start: 0x00a0, end: 0x00a0, family: 'unusual-whitespace' }, // NBSP
  { start: 0x1680, end: 0x1680, family: 'unusual-whitespace' }, // Ogham space
  { start: 0x2000, end: 0x200a, family: 'unusual-whitespace' }, // en/em/thin spaces
  { start: 0x202f, end: 0x202f, family: 'unusual-whitespace' }, // narrow NBSP
  { start: 0x205f, end: 0x205f, family: 'unusual-whitespace' }, // medium math space
  { start: 0x3000, end: 0x3000, family: 'unusual-whitespace' }, // ideographic space
];

/** C0/C1 control ranges, excluding the benign tab/newline/CR. */
export const CONTROL_RANGES: CodepointRange[] = [
  { start: 0x0000, end: 0x0008, family: 'control' },
  { start: 0x000b, end: 0x000c, family: 'control' },
  { start: 0x000e, end: 0x001f, family: 'control' },
  { start: 0x007f, end: 0x007f, family: 'control' },
  { start: 0x0080, end: 0x009f, family: 'control' },
];

/** Whitespace codepoints that are legitimately ubiquitous and never flagged. */
export const BENIGN_CONTROL = new Set<number>([0x09, 0x0a, 0x0d]);

const ALL_RANGES = [...INVISIBLE_RANGES, ...CONTROL_RANGES];

/** Classify a single codepoint into an invisible family, or null if ordinary. */
export function classifyCodepoint(cp: number): InvisibleFamily | null {
  if (BENIGN_CONTROL.has(cp)) return null;
  for (const r of ALL_RANGES) {
    if (cp >= r.start && cp <= r.end) return r.family;
  }
  return null;
}

/** Decode a Tags-block codepoint to its mirrored ASCII char, or null. */
export function decodeTagCodepoint(cp: number): string | null {
  if (cp < 0xe0000 || cp > 0xe007f) return null;
  const ascii = cp - 0xe0000;
  if (ascii === 0x7f) return null; // CANCEL tag — a terminator, not printable
  return String.fromCharCode(ascii);
}

/** Decode a variation selector to the byte value it encodes in the side channel. */
export function decodeVariationSelectorByte(cp: number): number | null {
  if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00; // VS1–VS16 → 0–15
  if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16; // VS17–VS256 → 16–255
  return null;
}

/** Human labels for families, used in findings. */
export const FAMILY_LABELS: Record<InvisibleFamily, string> = {
  tags: 'Unicode Tags block (ASCII smuggling channel)',
  'variation-selector': 'variation-selector byte channel',
  'bidi-override': 'bidirectional override',
  'bidi-isolate': 'bidirectional isolate',
  'bidi-mark': 'bidirectional mark',
  'zero-width': 'zero-width / joiner character',
  'invisible-math': 'invisible math operator (steganographic bit)',
  'default-ignorable': 'default-ignorable character',
  'unusual-whitespace': 'unusual whitespace',
  control: 'C0/C1 control character',
};
