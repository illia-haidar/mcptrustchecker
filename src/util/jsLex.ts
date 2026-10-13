/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * A deliberately small lexer for the source analyses that need more than a
 * regex but much less than a parser: "is this offset code or a string?",
 * "where does this call's argument list end?", "which function encloses this
 * line?". One linear pass per file builds a mask; everything else is a lookup.
 *
 * It never executes anything and never builds an AST. When it cannot be sure —
 * an exotic regex literal, an unterminated string — it errs toward treating the
 * text as code, which keeps the analyses that depend on it conservative.
 */

export type Lang = 'js' | 'py';

/** Mask values: what the character at an offset belongs to. */
export const CODE = 0;
export const STRING = 1;
export const COMMENT = 2;
export const REGEX = 3;

export function langOf(path: string): Lang {
  return /\.py$/i.test(path) ? 'py' : 'js';
}

/** Characters after which a `/` starts a regex literal rather than a division. */
const REGEX_PRECEDER = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^']);
const REGEX_KEYWORDS = /(?:^|[^\w$])(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/;

/**
 * Classify every character of `src`. Template literals are handled with a
 * stack so the code inside `${…}` is marked as code (it is where interpolated
 * values live), and the literal text around it as string.
 */
export function codeMask(src: string, lang: Lang): Uint8Array {
  return lang === 'py' ? pyMask(src) : jsMask(src);
}

function jsMask(src: string): Uint8Array {
  const n = src.length;
  const mask = new Uint8Array(n);
  // Stack of open template literals; each entry counts the `{` depth inside the
  // current `${…}` so a `}` that closes an object literal is not mistaken for
  // the end of the interpolation.
  const tpl: number[] = [];
  let lastSig = ''; // last significant (non-space) code character, for the regex heuristic
  let lastSigIdx = -1;
  let i = 0;
  while (i < n) {
    const c = src[i]!;
    // Inside `${ … }`: track braces so the closing `}` returns to template text.
    if (tpl.length && c === '}' && tpl[tpl.length - 1] === 0) {
      // The `}` closing an interpolation belongs to the template, like its `${`.
      // Left as code it unbalanced every bracket count after it: one template
      // string with `${x}` was enough to end a function body early.
      mask[i] = STRING;
      tpl.pop();
      i += 1;
      i = scanTemplateText(src, mask, i, tpl);
      lastSig = '`';
      lastSigIdx = i - 1;
      continue;
    }
    if (c === '{' && tpl.length) tpl[tpl.length - 1]! += 1;
    else if (c === '}' && tpl.length) tpl[tpl.length - 1]! -= 1;

    if (c === '/' && src[i + 1] === '/') {
      const s = i;
      while (i < n && src[i] !== '\n') i++;
      mask.fill(COMMENT, s, i);
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const s = i;
      const e = src.indexOf('*/', i + 2);
      i = e < 0 ? n : e + 2;
      mask.fill(COMMENT, s, i);
      continue;
    }
    if (c === "'" || c === '"') {
      const s = i;
      i += 1;
      while (i < n && src[i] !== c && src[i] !== '\n') i += src[i] === '\\' ? 2 : 1;
      i = Math.min(n, i + 1);
      mask.fill(STRING, s, i);
      lastSig = c;
      lastSigIdx = i - 1;
      continue;
    }
    if (c === '`') {
      mask[i] = STRING;
      i = scanTemplateText(src, mask, i + 1, tpl);
      lastSig = '`';
      lastSigIdx = i - 1;
      continue;
    }
    if (c === '/' && isRegexStart(src, lastSig, lastSigIdx)) {
      const s = i;
      i += 1;
      let inClass = false;
      while (i < n && src[i] !== '\n') {
        const d = src[i]!;
        if (d === '\\') { i += 2; continue; }
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) break;
        i += 1;
      }
      if (i < n && src[i] === '/') {
        i += 1;
        while (i < n && /[a-z]/i.test(src[i]!)) i++;
        mask.fill(REGEX, s, i);
        lastSig = ')'; // a regex literal is an operand
        lastSigIdx = i - 1;
        continue;
      }
      // Not a terminated regex on this line: treat the `/` as an operator.
      i = s + 1;
      lastSig = '/';
      lastSigIdx = s;
      continue;
    }
    if (c !== ' ' && c !== '\t' && c !== '\n' && c !== '\r') {
      lastSig = c;
      lastSigIdx = i;
    }
    i += 1;
  }
  return mask;
}

/** Scan template-literal text from `i` until the closing backtick or a `${`. */
function scanTemplateText(src: string, mask: Uint8Array, i: number, tpl: number[]): number {
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    if (c === '\\') { mask[i] = STRING; if (i + 1 < n) mask[i + 1] = STRING; i += 2; continue; }
    if (c === '`') { mask[i] = STRING; return i + 1; }
    if (c === '$' && src[i + 1] === '{') {
      mask[i] = STRING;
      mask[i + 1] = STRING;
      tpl.push(0);
      return i + 2;
    }
    mask[i] = STRING;
    i += 1;
  }
  return n;
}

function isRegexStart(src: string, lastSig: string, lastSigIdx: number): boolean {
  if (lastSigIdx < 0) return true;
  if (REGEX_PRECEDER.has(lastSig)) return true;
  if (/[\w$]/.test(lastSig)) return REGEX_KEYWORDS.test(src.slice(Math.max(0, lastSigIdx - 11), lastSigIdx + 1));
  return false;
}

function pyMask(src: string): Uint8Array {
  const n = src.length;
  const mask = new Uint8Array(n);
  let i = 0;
  while (i < n) {
    const c = src[i]!;
    if (c === '#') {
      const s = i;
      while (i < n && src[i] !== '\n') i++;
      mask.fill(COMMENT, s, i);
      continue;
    }
    if (c === "'" || c === '"') {
      const s = i;
      const triple = src[i + 1] === c && src[i + 2] === c;
      if (triple) {
        const close = c + c + c;
        const e = src.indexOf(close, i + 3);
        i = e < 0 ? n : e + 3;
      } else {
        i += 1;
        while (i < n && src[i] !== c && src[i] !== '\n') i += src[i] === '\\' ? 2 : 1;
        i = Math.min(n, i + 1);
      }
      // A string prefix (r, b, f, u, rb, fr…) belongs to the literal.
      let p = s;
      let k = 0;
      while (p > 0 && k < 2 && /[rbfuRBFU]/.test(src[p - 1]!)) { p--; k++; }
      if (p > 0 && /\w/.test(src[p - 1]!)) p = s;
      mask.fill(STRING, p, i);
      continue;
    }
    i += 1;
  }
  return mask;
}

/** Offsets of the start of every line, for O(log n) line lookups. */
export function lineStarts(src: string): number[] {
  const out = [0];
  for (let i = 0; i < src.length; i++) if (src.charCodeAt(i) === 10) out.push(i + 1);
  return out;
}

/** 1-based line number of `index`, given {@link lineStarts}. */
export function lineAt(starts: number[], index: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

const OPEN = '([{';
const CLOSE = ')]}';

/**
 * Index of the bracket matching the one at `open`, counting only code
 * characters. Returns -1 when it is not closed within `limit` characters.
 */
export function matchBracket(src: string, mask: Uint8Array, open: number, limit = 200_000): number {
  const start = src[open];
  if (start === undefined || !OPEN.includes(start)) return -1;
  let depth = 0;
  const end = Math.min(src.length, open + limit);
  for (let i = open; i < end; i++) {
    if (mask[i] !== CODE) continue;
    const c = src[i]!;
    if (OPEN.includes(c)) depth++;
    else if (CLOSE.includes(c)) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export interface ArgList {
  /** Trimmed argument texts. */
  args: string[];
  /** Absolute offset of each argument's first non-space character. */
  starts: number[];
  /** Offset of the closing parenthesis. */
  end: number;
}

/** Split the argument list whose `(` is at `open` at its top-level commas. */
export function splitArgs(src: string, mask: Uint8Array, open: number): ArgList | null {
  const close = matchBracket(src, mask, open);
  if (close < 0) return null;
  const args: string[] = [];
  const starts: number[] = [];
  let depth = 0;
  let from = open + 1;
  const push = (to: number): void => {
    const raw = src.slice(from, to);
    const lead = raw.length - raw.trimStart().length;
    const text = raw.trim();
    if (text) {
      args.push(text);
      starts.push(from + lead);
    }
  };
  for (let i = open + 1; i < close; i++) {
    if (mask[i] !== CODE) continue;
    const c = src[i]!;
    if (OPEN.includes(c)) depth++;
    else if (CLOSE.includes(c)) depth--;
    else if (c === ',' && depth === 0) {
      push(i);
      from = i + 1;
    }
  }
  push(close);
  return { args, starts, end: close };
}

/**
 * Brace depth (`{}` only, code characters only) at each of the given offsets,
 * computed in one pass. Used to tell a top-level `require()` from one tucked
 * inside a function body — the "lazy" load that only runs on one code path.
 */
export function braceDepths(src: string, mask: Uint8Array, offsets: number[]): Map<number, number> {
  const out = new Map<number, number>();
  if (!offsets.length) return out;
  const sorted = [...new Set(offsets)].sort((a, b) => a - b);
  let k = 0;
  let depth = 0;
  for (let i = 0; i < src.length && k < sorted.length; i++) {
    while (k < sorted.length && sorted[k] === i) out.set(sorted[k++]!, depth);
    if (mask[i] !== CODE) continue;
    const c = src.charCodeAt(i);
    if (c === 123) depth++;
    else if (c === 125) depth = Math.max(0, depth - 1);
  }
  while (k < sorted.length) out.set(sorted[k++]!, depth);
  return out;
}

/** Split an expression at top-level occurrences of `sep` (outside strings and brackets). */
export function splitTopLevel(expr: string, sep: string): string[] {
  const mask = codeMask(expr, 'js');
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < expr.length; i++) {
    if (mask[i] !== CODE) continue;
    const c = expr[i]!;
    if (OPEN.includes(c)) depth++;
    else if (CLOSE.includes(c)) depth--;
    else if (depth === 0 && expr.startsWith(sep, i)) {
      out.push(expr.slice(from, i));
      from = i + sep.length;
      i += sep.length - 1;
    }
  }
  out.push(expr.slice(from));
  return out.map((s) => s.trim());
}

/**
 * Every offset where `name` occurs as a whole identifier in code. `bareOnly`
 * skips member accesses (`x.name`) so a property that happens to share the
 * name is not mistaken for the binding.
 */
export function identOffsets(src: string, mask: Uint8Array, name: string, bareOnly = true): number[] {
  const out: number[] = [];
  if (!name) return out;
  let from = 0;
  for (;;) {
    const i = src.indexOf(name, from);
    if (i < 0) break;
    from = i + name.length;
    if (mask[i] !== CODE) continue;
    const before = i > 0 ? src[i - 1]! : '';
    const after = src[i + name.length] ?? '';
    if (/[\w$]/.test(before) || /[\w$]/.test(after)) continue;
    if (bareOnly && before === '.') {
      // `...name` (spread) is a bare use, `x.name` is a member access.
      if (!(src[i - 2] === '.' && src[i - 3] === '.')) continue;
    }
    out.push(i);
  }
  return out;
}
