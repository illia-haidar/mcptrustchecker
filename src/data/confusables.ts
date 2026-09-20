/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * A curated subset of the UTS #39 confusables mapping (homoglyph → ASCII
 * skeleton). This is intentionally small and high-precision: it covers the
 * Latin-lookalike Cyrillic / Greek / fullwidth / digit-lookalike characters
 * that matter for package-name and command-keyword squatting. It is NOT a full
 * confusables.txt — the mixed-script detector (using Unicode script properties)
 * catches the general case; this map exists to compute a `skeleton()` for the
 * typosquat watchlist comparison.
 */

export const CONFUSABLE_MAP: Record<string, string> = {
  // Cyrillic → Latin
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  х: 'x',
  у: 'y',
  к: 'k',
  м: 'm',
  т: 't',
  н: 'h',
  в: 'b',
  і: 'i',
  ѕ: 's',
  ј: 'j',
  // Greek → Latin
  ο: 'o',
  ρ: 'p',
  α: 'a',
  ν: 'v',
  τ: 't',
  ι: 'i',
  κ: 'k',
  // Fullwidth → ASCII
  ａ: 'a',
  ｅ: 'e',
  ｉ: 'i',
  ｏ: 'o',
  ｒ: 'r',
  ｍ: 'm',
  ｃ: 'c',
  ｐ: 'p',
  // Digit / letter lookalikes
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '5': 's',
  '$': 's',
  '@': 'a',
};

/**
 * Reduce a string to its confusable skeleton: NFKD-fold, then map each char
 * through the confusable table, lowercased. Two strings with the same skeleton
 * are visually confusable. Used only against the protected watchlist.
 */
export function skeleton(input: string): string {
  const normalized = input.normalize('NFKD').toLowerCase();
  let out = '';
  for (const ch of normalized) {
    out += CONFUSABLE_MAP[ch] ?? ch;
  }
  return out;
}
