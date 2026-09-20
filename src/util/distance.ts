/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * String-distance & version helpers for the supply-chain and posture stages.
 * All pure and dependency-free.
 */

/**
 * Damerau-Levenshtein (optimal string alignment) edit distance. Counts
 * insertions, deletions, substitutions and adjacent transpositions each as 1.
 * `swap` counting is what makes "sdk" vs "sdck"-style transposes cost 1.
 */
export function damerauLevenshtein(a: string, b: string): number {
  const al = a.length;
  const bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;

  const d: number[][] = Array.from({ length: al + 1 }, () => new Array<number>(bl + 1).fill(0));
  for (let i = 0; i <= al; i++) d[i]![0] = i;
  for (let j = 0; j <= bl; j++) d[0]![j] = j;

  for (let i = 1; i <= al; i++) {
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(
        d[i - 1]![j]! + 1, // deletion
        d[i]![j - 1]! + 1, // insertion
        d[i - 1]![j - 1]! + cost, // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, d[i - 2]![j - 2]! + 1); // transposition
      }
      d[i]![j] = val;
    }
  }
  return d[al]![bl]!;
}

/** QWERTY physical-adjacency map (lowercase). */
const QWERTY_ADJ: Record<string, string> = {
  q: 'wa',
  w: 'qeas',
  e: 'wrsd',
  r: 'etdf',
  t: 'ryfg',
  y: 'tugh',
  u: 'yihj',
  i: 'uojk',
  o: 'ipkl',
  p: 'ol',
  a: 'qwsz',
  s: 'awedxz',
  d: 'serfcx',
  f: 'drtgvc',
  g: 'ftyhbv',
  h: 'gyujnb',
  j: 'huikmn',
  k: 'jiolm',
  l: 'kop',
  z: 'asx',
  x: 'zsdc',
  c: 'xdfv',
  v: 'cfgb',
  b: 'vghn',
  n: 'bhjm',
  m: 'njk',
};

/** True if two single chars are physically adjacent on a QWERTY keyboard. */
export function isKeyboardAdjacent(a: string, b: string): boolean {
  return (QWERTY_ADJ[a.toLowerCase()] ?? '').includes(b.toLowerCase());
}

/**
 * True when `candidate` differs from `target` by exactly one substitution and
 * that substitution is a keyboard-adjacent slip (a classic typo, distinct from
 * a deliberate homoglyph swap).
 */
export function isKeyboardTypo(candidate: string, target: string): boolean {
  if (candidate.length !== target.length) return false;
  let diffs = 0;
  let adjacent = false;
  for (let i = 0; i < candidate.length; i++) {
    if (candidate[i] !== target[i]) {
      diffs += 1;
      adjacent = isKeyboardAdjacent(candidate[i]!, target[i]!);
      if (diffs > 1) return false;
    }
  }
  return diffs === 1 && adjacent;
}

/** Parse a dotted version into numeric segments (non-numeric parts → 0). */
function parseVersion(v: string): number[] {
  return v
    .replace(/^[v=]/, '')
    .split(/[.+-]/)
    .map((s) => {
      const n = Number.parseInt(s, 10);
      return Number.isNaN(n) ? 0 : n;
    });
}

/** Compare two versions. Returns -1 if a<b, 0 if equal, 1 if a>b. */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/** Strip an npm scope, returning the bare package name. */
export function bareName(pkg: string): string {
  const slash = pkg.indexOf('/');
  return pkg.startsWith('@') && slash >= 0 ? pkg.slice(slash + 1) : pkg;
}
