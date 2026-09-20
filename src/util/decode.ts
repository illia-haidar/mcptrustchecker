/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The decode ladder.
 *
 * A lexical detector that only reads the *literal* bytes of a field can be
 * defeated by writing the payload in any encoding the model still understands:
 * base64, percent-escapes, HTML entities, `\u` escapes, or the invisible
 * Unicode side channels. The model decodes those; a scanner that does not is
 * strictly weaker than the attacker.
 *
 * So every scannable field is expanded into a small set of DERIVED VIEWS —
 * each one a plain-text recovery of a layer the attacker hid the payload in —
 * and the full detector lexicon runs over each view as well as the original.
 *
 * Two properties matter and are enforced here:
 *
 *  - **Deterministic.** Transforms are applied in a fixed order, breadth-first,
 *    and results are de-duplicated by exact content, so the same input always
 *    yields the same layers in the same order.
 *  - **Bounded.** Depth, layer count, and per-layer length are all capped, and
 *    the byte-producing decoders (base64/hex/variation-selector) must recover
 *    something that actually looks like TEXT. A random identifier that happens
 *    to be valid base64 decodes to binary noise and is discarded, so the ladder
 *    adds recall without inventing a scannable surface out of nothing.
 */

import { classifyCodepoint, decodeTagCodepoint, decodeVariationSelectorByte } from '../data/unicode.js';

/** A recovered view of a field, plus the transform chain that produced it. */
export interface DecodedLayer {
  /** The recovered text — scanned exactly like the original field. */
  text: string;
  /** Transform ids, outermost first (e.g. `['unicode-tags','base64']`). */
  via: string[];
}

/** How many nested encodings to peel. Real droppers rarely exceed two. */
const MAX_DEPTH = 3;
/** Total derived views per field — a hard stop on pathological inputs. */
const MAX_LAYERS = 12;
/** Input cap, matching the field cap applied by `collectTextFields`. */
const MAX_INPUT = 100_000;
/** Per-layer cap, so a decompression-shaped input cannot blow up memory. */
const MAX_LAYER_LEN = 20_000;
/** Shorter recoveries carry no instruction and are pure noise. */
const MIN_PAYLOAD_LEN = 8;

/**
 * Does a byte-level recovery look like human-readable text rather than binary?
 * This is what keeps the ladder honest: without it every base64-shaped
 * identifier in the ecosystem would become a scannable "hidden payload".
 */
function isPlausibleText(s: string): boolean {
  if (s.length < MIN_PAYLOAD_LEN) return false;
  const chars = [...s];
  let printable = 0;
  for (const ch of chars) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0x09 || cp === 0x0a || cp === 0x0d || (cp >= 0x20 && cp !== 0x7f)) printable += 1;
  }
  if (printable / chars.length < 0.85) return false;

  // A recovered instruction is a PHRASE. Requiring genuine word structure —
  // two space-separated, vowel-bearing tokens — is what separates a decoded
  // sentence from the dominant noise class: a random identifier that happens
  // to be valid base64 and decodes to one run of mixed-case letters
  // (`a3F8Zk92QmR4TnBXc0x2` → `kq|fOvBdxNpWsLv`). Nothing is lost by this: the
  // detectors that consume these layers all match on word-separated text too.
  const wordlike = s
    .split(/\s+/)
    .map((t) => t.replace(/[^\p{L}\p{N}]/gu, ''))
    .filter((t) => t.length >= 2 && t.length <= 24 && /[aeiouyàâäåæéèêëïîôöœùûüÿаеёиоуыэюяαεηιουω]/i.test(t));
  if (wordlike.length >= 2) return true;

  // Scripts written without word spacing: a run of CJK is a phrase on its own.
  return /[぀-ヿ㐀-䶿一-鿿]{4,}/u.test(s);
}

/**
 * A recovery that is one long token drawn entirely from an encoding alphabet is
 * not prose — it is the NEXT layer. Keeping it lets the ladder peel a
 * double-encoded payload, and it cannot readmit the binary-noise class: random
 * bytes are rejected before this by the printable-ASCII gate, and the odds of
 * 24+ random bytes all landing inside the base64 alphabet are vanishing.
 */
function isEncodedIntermediate(s: string): boolean {
  const t = s.trim();
  return t.length >= 24 && /^[A-Za-z0-9+/=_-]+$/.test(t);
}

/** Accept a recovery if it reads as prose, or if it is plainly another layer. */
function acceptRecovery(s: string): boolean {
  return isPlausibleText(s) || isEncodedIntermediate(s);
}

/**
 * Bytes → text.
 *
 * A lossless UTF-8 decode is the whole test, and it recovers payloads in any
 * language. There is deliberately no latin1 fallback: latin1 maps all 256 byte
 * values to printable characters, so it accepts anything — measured over 15,000
 * real-shaped identifiers (hashes, cache keys, signatures) it alone turned 14%
 * of them into scannable "hidden payloads" made of mojibake. Narrowing it to
 * "every byte is printable ASCII" made it safe but also redundant: printable
 * ASCII is always valid UTF-8, so that branch could only ever re-test the string
 * UTF-8 had already accepted or rejected.
 */
function bytesToText(bytes: Buffer): string | null {
  if (bytes.length < MIN_PAYLOAD_LEN) return null;
  const utf8 = bytes.toString('utf8');
  if (utf8.includes('�')) return null; // not valid UTF-8 — not a text payload
  return acceptRecovery(utf8) ? utf8 : null;
}

// ---------------------------------------------------------------------------
// Individual transforms. Each returns the recovered text, or null when it does
// not apply (nothing to decode / the recovery is not plausible text).
// ---------------------------------------------------------------------------

/** Compatibility normalization — folds full-width, ligature and styled letters. */
function nfkc(s: string): string | null {
  const out = s.normalize('NFKC');
  return out === s ? null : out;
}

/**
 * Remove the invisible characters, revealing text that was broken up by them.
 * `i​gnore previous instructions` is invisible to a phrase regex and plain
 * as day to the model — stripping the separators is what closes that gap.
 */
function stripInvisible(s: string): string | null {
  let out = '';
  let removed = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    const family = classifyCodepoint(cp);
    if (family === null) {
      out += ch;
      continue;
    }
    removed += 1;
    // Unusual whitespace still separates words; collapse it to a plain space so
    // an ideographic-space-delimited sentence stays tokenizable.
    if (family === 'unusual-whitespace') out += ' ';
  }
  return removed > 0 ? out : null;
}

/** Recover the payload smuggled in the U+E0000 Tags block. */
function unicodeTags(s: string): string | null {
  let out = '';
  for (const ch of s) {
    const d = decodeTagCodepoint(ch.codePointAt(0)!);
    if (d !== null) out += d;
  }
  return acceptRecovery(out) ? out : null;
}

/** Recover the payload smuggled in the variation-selector byte channel. */
function variationSelectors(s: string): string | null {
  const bytes: number[] = [];
  for (const ch of s) {
    const b = decodeVariationSelectorByte(ch.codePointAt(0)!);
    if (b !== null) bytes.push(b);
  }
  return bytesToText(Buffer.from(bytes));
}

/**
 * Decode every base64-shaped run that recovers plausible text. All qualifying
 * blobs are joined, so a payload split across several blobs is still recovered
 * as one scannable view.
 */
function base64Blobs(s: string): string | null {
  const parts: string[] = [];
  // Bounded quantifier: an unbounded run over a multi-MB field is a DoS vector.
  // The boundaries are LOOKAROUND, not consumed characters: an earlier version
  // consumed the preceding delimiter and excluded `=` from it, which silently
  // made `key=<blob>` — the single most common way a blob is embedded — invisible
  // to the whole ladder. A lookbehind has no such blind spot and cannot swallow
  // the separator between two adjacent blobs either.
  for (const m of s.matchAll(/(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,4096}={0,2})(?![A-Za-z0-9+/=])/g)) {
    const blob = m[1]!;
    if (/^[0-9a-f]+$/i.test(blob)) continue; // pure hex — handled by hexRun
    let decoded: string | null = null;
    try {
      decoded = bytesToText(Buffer.from(blob, 'base64'));
    } catch {
      decoded = null;
    }
    if (decoded) parts.push(decoded);
  }
  return parts.length > 0 ? parts.join('\n') : null;
}

/** Decode a long run of bare hex digit pairs (`69676e6f7265…`). */
function hexRun(s: string): string | null {
  const parts: string[] = [];
  for (const m of s.matchAll(/(?:^|[^0-9a-fA-F])((?:[0-9a-fA-F]{2}){8,2048})(?![0-9a-fA-F])/g)) {
    const bytes: number[] = [];
    const run = m[1]!;
    for (let i = 0; i < run.length; i += 2) bytes.push(parseInt(run.slice(i, i + 2), 16));
    const text = bytesToText(Buffer.from(bytes));
    if (text) parts.push(text);
  }
  return parts.length > 0 ? parts.join('\n') : null;
}

/** Decode `\xNN`, `\uNNNN` and `\u{NNNNN}` escape sequences. */
function escapeSequences(s: string): string | null {
  // The guard must accept exactly what the replacement below accepts. It used to
  // demand 4-6 hex digits for the braced form while the replacement accepted
  // 1-6, so `\u{69}` was rejected here and never decoded at all.
  if (!/\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4})/.test(s)) return null;
  const out = s.replace(/\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})/g, (_all, x, braced, u) => {
    const hex = (x ?? braced ?? u) as string;
    const cp = parseInt(hex, 16);
    // Reject non-scalar values (lone surrogates) — `fromCodePoint` throws on them.
    if (!Number.isFinite(cp) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return _all as string;
    return String.fromCodePoint(cp);
  });
  return out === s ? null : out;
}

/** Percent-decode (`%69%67…`), tolerating malformed sequences. */
function percentEscapes(s: string): string | null {
  if (!/%[0-9a-fA-F]{2}/.test(s)) return null;
  const out = s.replace(/(?:%[0-9a-fA-F]{2})+/g, (seq) => {
    try {
      return decodeURIComponent(seq);
    } catch {
      // Not valid UTF-8 — fall back to a byte-wise latin1 recovery.
      const bytes: number[] = [];
      for (const m of seq.matchAll(/%([0-9a-fA-F]{2})/g)) bytes.push(parseInt(m[1]!, 16));
      return Buffer.from(bytes).toString('latin1');
    }
  });
  return out === s ? null : out;
}

/** The handful of named HTML entities worth decoding alongside numeric ones. */
const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  sol: '/',
  colon: ':',
  period: '.',
  commat: '@',
  lpar: '(',
  rpar: ')',
};

/** Decode HTML entities (`&#105;`, `&#x69;`, `&amp;`). */
function htmlEntities(s: string): string | null {
  if (!/&(?:#\d{1,7}|#x[0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});/.test(s)) return null;
  const out = s.replace(/&(?:#(\d{1,7})|#x([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));/g, (all, dec, hex, name) => {
    if (dec || hex) {
      const cp = parseInt((dec ?? hex) as string, dec ? 10 : 16);
      if (!Number.isFinite(cp) || cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return all as string;
      return String.fromCodePoint(cp);
    }
    return NAMED_ENTITIES[(name as string).toLowerCase()] ?? (all as string);
  });
  return out === s ? null : out;
}

/**
 * The ladder, in a FIXED order — this is what makes the output deterministic.
 * Normalizing views come first so a payload hidden behind both a normalization
 * trick and an encoding is reached at the shallowest possible depth.
 */
const TRANSFORMS: { id: string; run: (s: string) => string | null }[] = [
  { id: 'nfkc', run: nfkc },
  { id: 'strip-invisible', run: stripInvisible },
  { id: 'unicode-tags', run: unicodeTags },
  { id: 'variation-selector', run: variationSelectors },
  { id: 'escape-sequences', run: escapeSequences },
  { id: 'percent', run: percentEscapes },
  { id: 'html-entity', run: htmlEntities },
  { id: 'base64', run: base64Blobs },
  { id: 'hex', run: hexRun },
];

/**
 * Cheap necessary-condition test for "this field could contain an encoded
 * layer". Each alternative is the minimal syntax one transform requires:
 * a non-ASCII codepoint (normalization + every invisible channel), a percent
 * escape, an HTML entity, a `\x`/`\u` escape, or a 16-character run of
 * base64/hex alphabet — which prose does not produce, since words are shorter
 * than that and separated by spaces.
 */
// The first alternative is "anything that is not ordinary printable ASCII or
// benign whitespace". It has to be that wide, not merely non-ASCII: C0 controls
// and DEL are ASCII, `classifyCodepoint` classifies them, and `stripInvisible`
// removes them — so a payload split by `\x01` is recoverable and a non-ASCII-only
// test would have skipped the whole ladder and lost it.
const ENCODING_HINT =
  /[^\x20-\x7e\t\n\r]|%[0-9a-fA-F]{2}|&(?:#\d|#x[0-9a-fA-F]|[a-zA-Z]{2,8};)|\\[xu][0-9a-fA-F]|\\u\{[0-9a-fA-F]|[A-Za-z0-9+/]{16}/;

/** Human label for a transform chain, used in finding text. */
export function describeChain(via: string[]): string {
  const LABEL: Record<string, string> = {
    nfkc: 'Unicode compatibility normalization',
    'strip-invisible': 'invisible-character removal',
    'unicode-tags': 'the Unicode Tags block',
    'variation-selector': 'the variation-selector byte channel',
    'escape-sequences': '\\x/\\u escape sequences',
    percent: 'percent-encoding',
    'html-entity': 'HTML entities',
    base64: 'base64',
    hex: 'hex',
  };
  return via.map((v) => LABEL[v] ?? v).join(' → ');
}

/**
 * Expand a field into its derived views. The original text is NOT included —
 * callers scan it directly and use these as additional passes.
 *
 * Breadth-first so shallow encodings are reported with the shortest chain, and
 * de-duplicated by exact content so two transforms that converge on the same
 * recovery (common for `nfkc` and `strip-invisible`) cost only one scan.
 */
export function decodeLayers(input: string): DecodedLayer[] {
  if (typeof input !== 'string' || input.length === 0) return [];
  const src = input.length > MAX_INPUT ? input.slice(0, MAX_INPUT) : input;
  // Fast path. Ordinary prose carries none of the hints below, and the ladder is
  // the most expensive thing the text detectors do, so the common case must not
  // pay for it. This is a strict pre-filter, not a heuristic: every transform in
  // TRANSFORMS needs at least one of these to fire, so skipping on a miss cannot
  // lose a layer. That claim is only true because the first alternative covers
  // every non-printable byte rather than only non-ASCII — see ENCODING_HINT.
  if (!ENCODING_HINT.test(src)) return [];
  const seen = new Set<string>([src]);
  const out: DecodedLayer[] = [];
  let frontier: DecodedLayer[] = [{ text: src, via: [] }];

  for (let depth = 0; depth < MAX_DEPTH && frontier.length > 0 && out.length < MAX_LAYERS; depth += 1) {
    const next: DecodedLayer[] = [];
    for (const node of frontier) {
      for (const t of TRANSFORMS) {
        if (out.length >= MAX_LAYERS) break;
        let produced: string | null;
        try {
          produced = t.run(node.text);
        } catch {
          produced = null; // a transform must never be able to fail a scan
        }
        if (produced === null || produced.length === 0) continue;
        const text = produced.length > MAX_LAYER_LEN ? produced.slice(0, MAX_LAYER_LEN) : produced;
        if (seen.has(text)) continue;
        seen.add(text);
        const layer: DecodedLayer = { text, via: [...node.via, t.id] };
        out.push(layer);
        next.push(layer);
      }
    }
    frontier = next;
  }
  return out;
}
