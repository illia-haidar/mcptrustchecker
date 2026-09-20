/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 4b — Implementation-level analysis.
 *
 * Metadata detectors read what a server *claims*. This one reads what its code
 * *does*: when the server's source is available (a local package directory or an
 * extracted tarball), it scans for dangerous sinks — arbitrary execution, shell
 * spawning, hardcoded egress, obfuscated payloads, credential reads. Fully
 * deterministic; no LLM, no execution of the code.
 */

import type { Detector, DetectorContext, Finding, SourceFile } from '../types.js';
import { SOURCE_PATTERNS, isNonRuntimePath } from '../data/sourcePatterns.js';
import { SECRET_PATTERNS } from '../data/injectionPatterns.js';

const MAX_FINDINGS_PER_RULE = 10; // don't drown the report on a big codebase

/** Threat rules assert something about the SERVER's runtime behaviour, so they
 *  are not raised from test/benchmark/example/release-tooling files. The
 *  capability rules still fire there — that code really is in the package.
 *  MTC-SRC-004 (obfuscated payload) is here too: a decode+exec blob in a test
 *  fixture or a vendored bundle is not the server's runtime behaviour. */
const RUNTIME_ONLY_RULES = new Set(['MTC-SRC-004', 'MTC-SRC-007', 'MTC-SRC-009', 'MTC-SRC-010']);

/** Capability-sink rules (arbitrary exec / shell / dynamic module load). The code
 *  really ships, so they fire even in packaging/dev/install tooling — but THERE
 *  they are downgraded: it is not the server's request-handling runtime, and an
 *  install-time shell is already surfaced by MTC-SUP-010 (`runs install scripts`).
 *  Firing them HIGH on a build/install script overstates them as a runtime threat. */
const CAPABILITY_SINK_RULES = new Set(['MTC-SRC-001', 'MTC-SRC-002', 'MTC-SRC-003', 'MTC-SRC-005', 'MTC-SRC-006']);

/** Rules whose match is suppressed when it sits INSIDE a string literal — the shape
 *  is DATA (a scanner's detection pattern / example / red-team fixture), not code.
 *  SRC-009 (assembled command), SRC-010 (dynamic eval), SRC-004 (obfuscated payload)
 *  and SRC-007 (unsafe deserialization) are all catalogued verbatim by security
 *  tooling, so a string-literal occurrence must not self-accuse. */
const STRING_GUARD_RULES = new Set(['MTC-SRC-004', 'MTC-SRC-007', 'MTC-SRC-009', 'MTC-SRC-010']);

/** `Function("m","return import(m)")` is the standard optional-dependency loader —
 *  it wraps a dynamic `import()` to bypass a bundler's static resolution, not to
 *  eval arbitrary code. Recognise it so MTC-SRC-001 does not raise a HIGH "dynamic
 *  code execution" on it; the dynamic import it contains is still reported by
 *  MTC-SRC-005 at medium/heuristic, so the signal is not lost, only right-sized. */
function isOptionalImportLoader(content: string, index: number): boolean {
  const win = content.slice(index, index + 120);
  const back = content.slice(Math.max(0, index - 200), index);
  // `eval(...)` branch (SRC-010): the only benign vendored eval idiom is the
  // WebAssembly/emscripten runtime's `eval(func)`, guarded by an ASM_CONSTS /
  // wasm-bindgen context. A genuine `eval(script)` in server code has none.
  if (/^eval\s*\(/.test(win)) return /\b(?:ASM_CONSTS|emscripten|wasm_bindgen|WebAssembly)\b/.test(back);
  if (!/^(?:new\s+)?Function\s*\(/.test(win)) return false;
  // The optional-dependency loader, `Function("m","return import(m)")`.
  if (/\breturn\s+import\s*\(/.test(win)) return true;
  // Benign, ubiquitous vendored idioms that are NOT arbitrary eval: the global-this
  // polyfill `Function("return this")()` (lodash/core-js), the empty `Function("")`
  // eval feature-probe (zod's `allowsEval`), and the `function-bind` polyfill
  // `Function("binder","return function(){…}")` (transitive via call-bind/es-abstract,
  // inlined into countless bundled `dist` files).
  if (/^(?:new\s+)?Function\s*\(\s*(['"`])\s*return\s+this\s*\1\s*\)/.test(win)) return true;
  if (/^(?:new\s+)?Function\s*\(\s*(['"`])\1\s*\)/.test(win)) return true;
  if (/^(?:new\s+)?Function\s*\(\s*(['"`])binder\1\s*,/.test(win)) return true;
  // Zod's `allowsEval` probe embedded in a GENERATED bundle as an ESCAPED empty
  // string — `new Function(\"\")` — where the backslash defeats the quote lookahead.
  if (/^(?:new\s+)?Function\s*\(\s*\\+(['"])\s*\\+\1\s*\)/.test(win)) return true;
  // wasm-bindgen generated glue: `new Function(getStringFromWasm0(ptr,len))`, and
  // any `new Function(...)` sitting inside a WebAssembly/emscripten runtime blob —
  // generated method-caller glue copied into `dist`, not the server's own eval.
  if (/^(?:new\s+)?Function\s*\(\s*getStringFromWasm0\b/.test(win)) return true;
  if (/\b(?:wasm_bindgen|WebAssembly|emscripten|getStringFromWasm|ASM_CONSTS)\b/.test(back)) return true;
  return false;
}

/** True when the match sits INSIDE a quoted/backtick string literal on its line —
 *  an `eval(`/`exec(` that is string DATA (a security scanner's detection pattern,
 *  a remediation example, a red-team payload fixture), not executed code. Uses a
 *  detection-rule key hint plus the standard odd-unescaped-quotes test. */
function isInsideStringLiteral(content: string, index: number): boolean {
  // Fast, high-precision hint: a `pattern:`/`example:`/`payload:` … key immediately
  // before a quote on the match's OWN line marks the value as detection/example DATA.
  let ls = index;
  while (ls > 0 && content[ls - 1] !== '\n') ls--;
  if (/\b(?:pattern|patterns|before|after|fix|example|examples|payload|sample|description|desc|label|rule|rules|title|message|msg|test|input|snippet|code|regex|match)s?\s*[:=]\s*['"`]/i.test(content.slice(ls, index)))
    return true;
  // Multi-line string-state scan: a small lexer that tracks '/"/backtick strings
  // (with escapes), Python triple-quotes and JS template literals ACROSS lines, so
  // an `exec(`/`eval(` sitting inside a quoted rule/example — even a multi-line one —
  // is recognised as data, not code. `//` and `/* */` comments are skipped so a
  // quote inside a comment cannot throw off the string parity.
  let st: string | null = null; // '"' | "'" | '`' | '"""' | "'''"
  for (let i = 0; i < index; ) {
    const c = content[i]!;
    if (st === null) {
      if ((c === '"' || c === "'") && content[i + 1] === c && content[i + 2] === c) { st = c + c + c; i += 3; continue; }
      if (c === '"' || c === "'" || c === '`') { st = c; i += 1; continue; }
      if (c === '/' && content[i + 1] === '/') { while (i < index && content[i] !== '\n') i++; continue; }
      if (c === '/' && content[i + 1] === '*') { i += 2; while (i < index && !(content[i] === '*' && content[i + 1] === '/')) i++; i += 2; continue; }
      i += 1;
    } else if (st.length === 3) {
      if (c === st[0] && content[i + 1] === st[0] && content[i + 2] === st[0]) { st = null; i += 3; continue; }
      i += 1;
    } else {
      if (c === '\\') { i += 2; continue; }
      if (c === st) { st = null; i += 1; continue; }
      i += 1;
    }
  }
  return st !== null;
}

/** True when the match sits on a comment line (`//`, `*`, `/*`, `#`) — a lexical
 *  pattern that fires on a JSDoc/comment ("spawn (e.g. `'npx'`)") is documentation,
 *  not code, and must not raise a finding. */
function isCommentLine(content: string, index: number): boolean {
  let s = index;
  while (s > 0 && content[s - 1] !== '\n') s--;
  const prefix = content.slice(s, index).trimStart();
  return prefix.startsWith('//') || prefix.startsWith('*') || prefix.startsWith('/*') || prefix.startsWith('#');
}

/** `.exec(`/`.spawn(` on a NON-process receiver whose argument is a SQL statement
 *  is a database call (`db.exec(\`SELECT …\`)`), not command execution. Leading
 *  literal `\n`/`\r`/`\t` escapes (common in minified bundles) are tolerated so
 *  `db.exec(\`\nPRAGMA journal_mode=WAL\`)` is still recognised as SQL. */
// A SQL / GraphQL / Cypher statement as the first arg is a database/query call,
// not a shell command. Leading literal `\n`/`\r`/`\t` escapes (minified bundles)
// are tolerated so `db.exec(\`\nPRAGMA journal_mode=WAL\`)` still reads as SQL.
const SQL_ARG = /^(?:\\[nrt]|\s)*[(`'"]*(?:\\[nrt]|\s)*(?:--[^\n]*\n\s*)?(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|PRAGMA|BEGIN|COMMIT|ROLLBACK|WITH|REPLACE|VACUUM|ATTACH|DETACH|SAVEPOINT|RELEASE|ANALYZE|REINDEX|EXPLAIN|MUTATION|QUERY|SUBSCRIPTION|FRAGMENT|MATCH|MERGE|UNWIND)\b/i;
/** Receiver tokens whose `.exec()` runs SQL (a DB handle), never a shell. */
// Deliberately NOT conn/connection/session/client — ssh2's `conn.exec('rm -rf ~')`
// / `session.exec(cmd)` IS a real shell exec; the GraphQL/Cypher cases are covered
// by the query-keyword ARG test, not by receiver name.
const DB_RECEIVER = /(?:^|[.#])(?:sql|db|database|sqlite|stmt|statement|prepared?|pragma|d1|prisma|knex|drizzle)$/i;
/** A receiver whose `.exec()` is RegExp.prototype.exec (a match), not a shell. */
const REGEXP_RECEIVER = /(?:^|[.#])(?:[A-Z0-9_]{2,}|(?:re|rx|regexp?|pattern|matcher|expr)\w*)$/;
/** child_process aliases whose `.exec()` IS a shell — never skipped by the above. */
const CP_RECEIVER = /(?:^|[._])(?:child_?process|childprocess|cp|execa|shelljs|sh|proc|subprocess)$/i;
function isSqlExec(content: string, index: number): boolean {
  // (1) A regex-LITERAL receiver — `/pat/.exec(x)` — is a RegExp match, not a shell.
  if (content[index - 1] === '.' && content[index - 2] === '/') return true;
  // (2) Named receiver: a DB handle / query client (`sql.exec`, `this.#o.exec`,
  //     `session.exec`) or a RegExp-named const (`EMAIL_RE.exec`, `pattern.exec`)
  //     is not a shell — UNLESS the receiver is a child_process alias, which always
  //     wins so `cp.exec(...)` / `child_process_1.exec(...)` still fires.
  if (content[index - 1] === '.') {
    let j = index - 2;
    while (j >= 0 && /[\w$#]/.test(content[j]!)) j--;
    const recv = content.slice(j + 1, index - 1);
    if (CP_RECEIVER.test(recv)) return false;
    if (recv.startsWith('#') || DB_RECEIVER.test(recv) || REGEXP_RECEIVER.test(recv)) return true;
  }
  // (3) Argument: `db.exec(\`SELECT …\`)` is a SQL statement, not a shell command.
  const paren = content.indexOf('(', index);
  if (paren < 0) return false;
  return SQL_ARG.test(content.slice(paren + 1, paren + 90));
}

/** Iterate every match of a (possibly non-global) pattern so a benign first hit
 *  (a comment, a SQL string) cannot mask a real later one. */
function* allMatches(content: string, pattern: RegExp): Generator<RegExpExecArray> {
  const g = pattern.global ? pattern : new RegExp(pattern.source, pattern.flags + 'g');
  g.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = g.exec(content))) {
    yield m;
    if (m.index === g.lastIndex) g.lastIndex++;
  }
}

/** Declaration files (`*.d.ts`) carry TYPES only — no runtime code, so an
 *  `import { IOType } from 'node:child_process'` in a `.d.ts` is not execution. */
const DECLARATION_FILE = /\.d\.[cm]?ts$/i;

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line += 1;
  return line;
}

/** Secret patterns whose match is a genuine PRIVATE credential — a leak worth a
 *  confirmed high finding (and the confirmed-high grade gate). Google API keys
 *  (public-by-design client keys) and JWTs (routed by decoded role) are handled
 *  separately below and never default to `confirmed`. */
const CONFIRMED_SECRET_IDS = new Set(['aws-access-key', 'github-token', 'slack-token', 'stripe-secret', 'openai-key', 'private-key']);

/** Documentation/placeholder credential values — AWS's own canonical example keys,
 *  the jwt.io John-Doe token body, `xoxb-test-token`, sequential/all-x dummies. A
 *  match here is NOT a leaked secret. */
// AWS's documented example keys are matched by their ROOT (not the full ...EXAMPLE
// suffix) so bait variants like `AKIAIOSFODNN7FAKEXMP` (defense-mcp honeypot) are
// recognised as placeholders, not a live leak. These roots are the literal AWS
// docs prefixes — a real random key containing them is astronomically unlikely.
const KNOWN_PLACEHOLDER = /AKIAIOSFODNN7|AKIAI44QH8DHB|wJalrXUtnFEMI|bPxRfiCYEXAMPLEKEY|xoxb-test-token/i;
const PLACEHOLDER_BODY =
  /example|xxxx+|placeholder|dummy|redacted|changeme|deadbeef|notreal|your[-_]?(?:key|token|secret|api|id)|fake[-_]?(?:key|token|secret)|test[-_]?(?:token|key|secret)|1234567890|0123456789|abcdefghij|(?:[a-z]\d){6,}|[-_]here\b|\byour[-_][a-z0-9_-]*(?:token|key|secret|id)\b/i;

function looksLikePlaceholder(value: string): boolean {
  if (KNOWN_PLACEHOLDER.test(value)) return true;
  if (PLACEHOLDER_BODY.test(value)) return true;
  // A body that is a single repeated character is filler, never a real secret.
  const body = value.replace(/^[A-Za-z_-]+[-_]/, '');
  return /^(.)\1{7,}$/.test(body);
}

/** A file whose secret hits are CORROBORATED as test/fixture data, not a live leak:
 *  it assembles MULTIPLE distinct secret/PII shapes (a scanner's own vector corpus)
 *  OR carries an explicit fixture marker in the path / surrounding window. Used to
 *  downgrade SRC-008 to low/heuristic ONLY with such corroboration — never on a
 *  plain single embedded credential. */
const FIXTURE_MARKER = /\b(?:leak|demo|synthetic|fixture|writeCases|secretlint|gitleaks|detect-secrets|redact|sanitiz)\w*|Hardcoded secret|(^|\/)(?:test|tests|fixtures|__tests__|examples?|samples?)\//i;
function isCorroboratedFixture(path: string, content: string, index: number): boolean {
  const win = content.slice(Math.max(0, index - 200), index + 200);
  if (FIXTURE_MARKER.test(path) || FIXTURE_MARKER.test(win)) return true;
  // Multiple DISTINCT live-secret shapes clustered in one file = a vector corpus.
  let shapes = 0;
  for (const re of [/\bAKIA[0-9A-Z]{16}\b/, /\bgh[posru]_[0-9A-Za-z]{20,}/, /\bsk_live_[0-9A-Za-z]{16,}/, /\bxox[baprs]-[0-9A-Za-z-]{10,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./]) {
    if (re.test(content)) shapes++;
  }
  return shapes >= 3;
}

/** Base64URL-decode a JWT payload and JSON-parse it; null if not a decodable JWT. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split('.')[1];
  if (!part) return null;
  try {
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj: unknown = JSON.parse(json);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Classify a hardcoded-secret match into (severity, confidence, note), or null to
 *  suppress it (a placeholder / sample token that is not a real credential).
 *  Only genuine private credentials in runtime code get `confirmed` — the confidence
 *  the grade gate keys on — so example keys, public keys and test fixtures can no
 *  longer cap a reputable package at C/D. */
function classifySecret(
  id: string,
  value: string,
  win: string,
): { severity: Finding['severity']; confidence: Finding['confidence']; note: string } | null {
  if (looksLikePlaceholder(value)) return null;
  if (id === 'jwt') {
    const payload = decodeJwtPayload(value);
    const role = payload ? String(payload.role ?? '').toLowerCase() : '';
    const iss = payload ? String(payload.iss ?? '').toLowerCase() : '';
    if (payload && (String(payload.name) === 'John Doe' || String(payload.sub) === '1234567890')) return null; // sample token
    if (role === 'service_role')
      return { severity: 'high', confidence: 'confirmed', note: 'a Supabase service_role key (full-access credential)' };
    if (role === 'anon' || role === 'public' || role === 'authenticated' || iss === 'supabase')
      return { severity: 'low', confidence: 'heuristic', note: 'a public-by-design (anon/publishable) key — RLS, not secrecy, protects it' };
    return { severity: 'medium', confidence: 'heuristic', note: 'an embedded JSON Web Token (often an example or expired token)' };
  }
  if (id === 'google-api-key') {
    // Google API keys are designed to ship in clients (Firebase/Maps/CrUX),
    // restricted by referrer/quota — a leaked one is a hygiene note, not a gating leak.
    const firebase = /firebase|authDomain|VITE_[A-Z_]*FIREBASE|googleapis\.com/i.test(win);
    return {
      severity: 'low',
      confidence: 'heuristic',
      note: firebase ? 'a public Firebase/web API key' : 'a client API key (restricted by referrer/quota, not a private secret)',
    };
  }
  if (CONFIRMED_SECRET_IDS.has(id))
    return { severity: 'high', confidence: 'confirmed', note: 'a live-looking credential hardcoded in shipped code' };
  return { severity: 'high', confidence: 'strong', note: 'a hardcoded credential in shipped code' };
}

export const sourceDetector: Detector = {
  id: 'source',
  stage: 4,
  title: 'Implementation-level source analysis',
  run(ctx: DetectorContext): Finding[] {
    const raw: SourceFile[] = Array.isArray(ctx.surface.sourceFiles) ? ctx.surface.sourceFiles : [];
    if (!raw.length) return [];
    // Process in a stable path order (code-unit, never locale) so the per-rule
    // finding cap keeps the SAME findings regardless of how the caller ordered
    // the files — the "same input ⇒ byte-identical report" promise must not
    // depend on filesystem or archive iteration order.
    const files = [...raw].sort((a, b) => {
      const x = typeof a?.path === 'string' ? a.path : '';
      const y = typeof b?.path === 'string' ? b.path : '';
      return x < y ? -1 : x > y ? 1 : 0;
    });
    const findings: Finding[] = [];
    const perRule = new Map<string, number>();

    for (const f of files) {
      if (!f || typeof f.content !== 'string') continue;
      const path = typeof f.path === 'string' ? f.path : 'source';
      // Declaration files are types only — never runtime code. Skip them entirely.
      if (DECLARATION_FILE.test(path)) continue;
      const nonRuntime = isNonRuntimePath(path);

      for (const p of SOURCE_PATTERNS) {
        if (nonRuntime && RUNTIME_ONLY_RULES.has(p.id)) continue;
        const seen = perRule.get(p.id) ?? 0;
        if (seen >= MAX_FINDINGS_PER_RULE) continue;

        // Take the first REAL match — skipping comments/JSDoc, the optional-import
        // loader (SRC-001), and SQL passed to a DB `.exec()` (SRC-009) — so a benign
        // lexical hit can neither raise a finding nor mask a genuine later one.
        let m: RegExpExecArray | undefined;
        for (const cand of allMatches(f.content, p.pattern)) {
          if (cand.index === undefined) continue;
          if (isCommentLine(f.content, cand.index)) continue;
          // Vendored/generated eval idioms (optional-import loader, wasm-bindgen
          // glue, empty/escaped `new Function`) — benign for both SRC-001 (presence)
          // and SRC-010 (dynamic eval).
          if ((p.id === 'MTC-SRC-001' || p.id === 'MTC-SRC-010') && isOptionalImportLoader(f.content, cand.index)) continue;
          // A DB `.exec()` is not a shell command sink (SRC-009).
          if (p.id === 'MTC-SRC-009' && isSqlExec(f.content, cand.index)) continue;
          // An `exec(`/`eval(`/decode-blob/deserialize match that is string DATA — a
          // security scanner's detection pattern, a remediation example, a red-team
          // payload fixture — is not executed code. SRC-004 (obfuscation) and SRC-007
          // (unsafe deser) join SRC-009/010 here so a scanner cataloguing these
          // shapes as strings does not self-flag.
          if (STRING_GUARD_RULES.has(p.id) && isInsideStringLiteral(f.content, cand.index)) continue;
          m = cand;
          break;
        }
        if (!m || m.index === undefined) continue;

        // A capability sink in packaging/dev/install tooling ships, but it is not
        // the server runtime (and an install-time shell is already MTC-SUP-010), so
        // right-size it instead of overstating it as a HIGH threat "in server code".
        const inTooling = nonRuntime && CAPABILITY_SINK_RULES.has(p.id);
        const severity = inTooling ? ('low' as Finding['severity']) : p.severity;
        const confidence = inTooling ? ('heuristic' as Finding['confidence']) : p.confidence;
        const title = inTooling
          ? `${p.title.replace(/ in server code$/, '')} in packaging/dev tooling (${path})`
          : `${p.title} (${path})`;
        const where = inTooling
          ? 'a packaging/dev/install script (shipped, but not the server runtime)'
          : "the server's implementation";

        perRule.set(p.id, seen + 1);
        findings.push({
          ruleId: p.id,
          title,
          category: p.category,
          severity,
          confidence,
          description:
            `In ${where} (\`${path}:${lineOf(f.content, m.index)}\`): ${p.why} ` +
            `This is read from the code itself — not from the tool description — so a poisoned server cannot hide it behind honest-looking metadata.`,
          remediation:
            'Review this call path: confirm it never receives unsanitized tool input, constrain it, or remove it. ' +
            'Treat a server whose code reaches these sinks as high-capability regardless of what its tools claim.',
          location: { kind: 'server', name: path },
          // Evidence carries a little surrounding source, not the bare token, so the
          // claim is auditable ("why is this HIGH?") rather than an opaque `exec(`.
          evidence: f.content.slice(Math.max(0, m.index - 24), m.index + 96).replace(/\s+/g, ' ').trim().slice(0, 160),
          owasp: p.category === 'exfiltration' ? 'LLM02:2025 Sensitive Information Disclosure' : 'LLM05:2025 Improper Output Handling',
          // `nonRuntime` lets the capability scorer skip tooling findings so the
          // low/heuristic downgrade actually stops the -6/-10, not just relabels.
          data: { rule: p.id, file: path, line: lineOf(f.content, m.index), nonRuntime: inTooling },
        });
      }

      // Embedded credential VALUE hardcoded in source (not just referenced).
      const seenSecret = perRule.get('MTC-SRC-008') ?? 0;
      if (seenSecret < MAX_FINDINGS_PER_RULE) {
        for (const sp of SECRET_PATTERNS) {
          let hit: { m: RegExpExecArray; sev: Finding['severity']; conf: Finding['confidence']; note: string } | undefined;
          for (const cand of allMatches(f.content, sp.pattern)) {
            if (cand.index === undefined) continue;
            // A secret on a comment line, or a placeholder/sample/public-by-design
            // value, is not a leaked credential — skip and keep looking.
            if (isCommentLine(f.content, cand.index)) continue;
            const win = f.content.slice(Math.max(0, cand.index - 80), cand.index + 120);
            const cls = classifySecret(sp.id, cand[0]!, win);
            if (!cls) continue;
            let { severity, confidence } = cls;
            // A "secret" in test/benchmark/example/vendor/build code is a fixture,
            // not a runtime credential leak: cap it at low/heuristic so it can
            // neither trip the confirmed-high gate nor demote a band, and attribute
            // it honestly ("in test/example/packaging").
            if (nonRuntime) {
              severity = 'low';
              confidence = 'heuristic';
            } else if (confidence === 'confirmed' && isCorroboratedFixture(path, f.content, cand.index)) {
              // A confirmed live-secret shape sitting in a CORROBORATED fixture — a
              // scanner's own vector corpus, or a file marked leak/demo/fixture — is
              // test data, not a runtime leak. Downgrade so it cannot trip the gate.
              // (Requires corroboration; a plain single embedded credential stays confirmed.)
              severity = 'low';
              confidence = 'heuristic';
            }
            hit = { m: cand, sev: severity, conf: confidence, note: cls.note };
            break;
          }
          if (!hit) continue;
          perRule.set('MTC-SRC-008', seenSecret + 1);
          const line = lineOf(f.content, hit.m.index!);
          findings.push({
            ruleId: 'MTC-SRC-008',
            title: nonRuntime
              ? `Hardcoded ${sp.label} in test/example/packaging (${path})`
              : `Hardcoded ${sp.label} in server code (${path})`,
            category: 'exfiltration',
            severity: hit.sev,
            confidence: hit.conf,
            description:
              `A hardcoded ${sp.label} (${hit.note}) appears in \`${path}:${line}\`. ` +
              (hit.conf === 'confirmed'
                ? 'Secrets in source ship to everyone who installs the package and are a direct credential leak.'
                : 'Verify whether this is a real credential; if so, remove and rotate it.'),
            remediation: 'Remove the secret, rotate it, and load credentials from the environment or a secret store.',
            location: { kind: 'server', name: path },
            evidence: `${sp.label}: ${hit.m[0]!.slice(0, 4)}…(redacted)`,
            owasp: 'LLM02:2025 Sensitive Information Disclosure',
            data: { secretType: sp.id, file: path, line },
          });
          break; // one secret finding per file is enough
        }
      }
    }

    // Compound: the server both ASSEMBLES shell commands from runtime values and
    // EVALUATES runtime values as code. Either alone is a precondition that
    // legitimate CLI wrappers and template engines routinely trip; together, in
    // runtime code, they are the dropper shape — an attacker who influences one
    // has a second primitive waiting. Scored on top of its parts, because the
    // combination carries information neither part does.
    const cmdFinding = findings.find((f) => f.ruleId === 'MTC-SRC-009');
    const evalFinding = findings.find((f) => f.ruleId === 'MTC-SRC-010');
    if (cmdFinding && evalFinding) {
      const cmdFile = (cmdFinding.data?.file as string | undefined) ?? undefined;
      const evalFile = (evalFinding.data?.file as string | undefined) ?? undefined;
      const sameFile = !!cmdFile && cmdFile === evalFile;
      findings.push({
        ruleId: 'MTC-SRC-011',
        title: 'Assembled command execution and dynamic evaluation in the same server',
        category: 'injection',
        severity: 'high',
        confidence: 'strong',
        description:
          `The implementation both builds shell commands out of runtime values (\`${cmdFile ?? 'command sink'}\`) ` +
          `and evaluates runtime values as code (\`${evalFile ?? 'eval sink'}\`). ` +
          'Each is a separate arbitrary-execution primitive; a server exposing both gives anything that reaches ' +
          'either one a direct path to running attacker-chosen code.' +
          (sameFile
            ? ''
            : ' These two sinks are in different files — confirm whether they are actually connected, or are unrelated code paths (e.g. a vendored bundle plus a CLI wrapper).'),
        remediation:
          'Remove the dynamic eval, and pass command arguments as an argv array instead of building a shell string. ' +
          'If both are genuinely required, constrain and validate every value that can reach them.',
        location: { kind: 'server', name: sameFile ? (cmdFile as string) : 'implementation' },
        owasp: 'LLM05:2025 Improper Output Handling',
        data: { rules: ['MTC-SRC-009', 'MTC-SRC-010'], commandFile: cmdFile, evalFile, sameFile },
      });
    }
    return findings;
  },
};
