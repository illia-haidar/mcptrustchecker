/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Read the BODY of an install hook (MTC-SUP-010).
 *
 * The rule used to judge `"postinstall": "node scripts/setup.mjs"` by that
 * one string — no `curl | sh` in it, so "low, review what it does" — while the
 * script itself sat unread in the package. This module reads it, and one level
 * of the package files it loads, and answers four questions:
 *
 *   gate     does it exit early in CI, without a terminal, or on an opt-out flag?
 *   network  does it fetch anything?
 *   process  does it run anything but the package's own CLI?
 *   writes   does it write outside the package — the home directory, and in
 *            particular another AI tool's configuration or agent rules?
 *
 * Static and best-effort. When the hook is anything other than a single
 * `node|python <file>` that ships in the package, it returns null and the
 * caller keeps its previous behaviour.
 */

import { builtinModules } from 'node:module';
import type { SourceFile } from '../types.js';
import { fileCtxOf } from '../util/fileCtx.js';
import { fold } from '../util/constFold.js';
import { splitArgs } from '../util/jsLex.js';
import { scanProcessCalls } from './callSites.js';

export interface HookReview {
  script: string;
  /** Early-exit conditions found before any side effect. */
  gate: string[];
  /** The gate includes "no terminal" (stdin/stdout isTTY). */
  ttyGated: boolean;
  network: boolean;
  /** Every process it starts is the package's own CLI under the running node/python. */
  ownCliOnly: boolean;
  /** Programs it starts other than its own CLI. */
  programs: string[];
  /** Any filesystem write at all. */
  writes: boolean;
  /** Home-directory paths it writes under (best-effort, `~/…`). */
  homeWrites: string[];
  /** The subset that belongs to another AI tool's configuration or rules. */
  toolConfigWrites: string[];
  /** The interactive prompt's default, when it asks. */
  prompt?: 'default-yes' | 'default-no';
  /**
   * Third-party modules it loads: their code was not read, so nothing can be
   * claimed about what they do. A review with any of these gives no verdict.
   */
  opaqueDeps: string[];
}

const HOOK = /^\s*(?:node|nodejs|python3?|py)\s+(?:-[\w-]+\s+)*["']?((?:\.\/)?[\w@./-]+\.(?:m?js|cjs|py))["']?\s*$/;
// Network: a call that fetches, OR merely loading a networking module — an
// aliased `const h = require('https'); h.request(…)` is invisible to call patterns.
const NETWORK = /\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|\burllib\.request\b|\brequests\.(?:get|post|put|request|Session)\b|\bhttp\.client\b|\bsocket\.socket\b|\bcurl\b|\bwget\b|(?:require|import)\s*\(?\s*['"](?:node:)?(?:https?|http2|net|tls|dgram|dns)['"]|\bfrom\s*['"](?:node:)?(?:https?|http2|net|tls|dgram|dns)['"]|['"](?:node-fetch|undici|axios|got|ws|socket\.io-client|request|superagent|needle|ky|phin|cross-fetch|isomorphic-fetch)['"]|^\s*(?:import|from)\s+(?:requests|httpx|aiohttp|urllib3|socket|http\.client|ftplib|smtplib|paramiko)\b/m;
// Writes: any filesystem mutation, sync, async or promise-based.
const WRITE = /\b(?:writeFileSync|writeFile|writeSync|appendFileSync|appendFile|mkdirSync|mkdir|mkdtempSync|copyFileSync|copyFile|cpSync|renameSync|rmSync|rmdirSync|unlinkSync|chmodSync|chownSync|symlinkSync|linkSync|truncateSync|utimesSync|createWriteStream)\s*\(|\b(?:fs|fsp|promises|fse|fs\.promises)\.(?:rename|rm|rmdir|unlink|chmod|chown|symlink|truncate|cp|mkdir|write|writev|appendFile|writeFile|copyFile|link|utimes)\s*\(|\bopenSync\s*\([^)]*['"][wa+rx]|\bopen\s*\([^)]*['"][wa]\+?b?['"]|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy\w*|move|rmtree)\b|\bos\.(?:remove|unlink|rename|makedirs|mkdir|rmdir|chmod|symlink)\s*\(/;
const HOME_ROOT = /(?:\bos\.homedir\(\)|\bhomedir\(\)|\bhome\(\)|\bgetHome\w*\(\)|process\.env\.(?:HOME|USERPROFILE)\b|os\.path\.expanduser\(\s*['"]~|Path\.home\(\))/;
/** Directories/files that are another AI tool's configuration or agent instructions. */
const TOOL_CONFIG = /(?:^|\/)(?:\.cline|Cline|\.cursor|\.vscode|\.claude|Claude|claude_desktop_config\.json|\.codex|\.windsurf|\.codeium|\.continue|\.gemini|\.aider[\w.-]*|\.roo|Roo)(?:\/|$)/;

export function reviewInstallHook(command: string, files: SourceFile[]): HookReview | null {
  const m = HOOK.exec(command);
  if (!m) return null;
  const script = m[1]!.replace(/^\.\//, '');
  const byPath = new Map(files.filter((f) => f && typeof f.path === 'string').map((f) => [f.path.replace(/^\.\//, ''), f]));
  const file = byPath.get(script);
  if (!file || typeof file.content !== 'string') return null;

  // The hook and the package files it loads, transitively (bounded): a helper two
  // imports down that writes or fetches is still the hook's behaviour.
  const reviewed: SourceFile[] = [file];
  const queue: { f: SourceFile; depth: number }[] = [{ f: file, depth: 0 }];
  while (queue.length && reviewed.length < 30) {
    const { f, depth } = queue.shift()!;
    if (depth >= 3) continue;
    for (const g of loadedPackageFiles(f, byPath)) {
      if (reviewed.includes(g)) continue;
      reviewed.push(g);
      queue.push({ f: g, depth: depth + 1 });
    }
  }
  const src = file.content;

  // Side effects in the hook file itself, to place the gate before them.
  const ctx = fileCtxOf(file);
  const scan = scanProcessCalls(ctx);
  const firstEffect = Math.min(
    ...[scan.calls[0]?.index, src.search(WRITE), src.search(NETWORK)].filter((x): x is number => typeof x === 'number' && x >= 0),
    src.length,
  );
  const gate: string[] = [];
  let ttyGated = false;
  const reIf = /\bif\s*\(\s*([^)]{1,400}?)\s*\)\s*\{?\s*(?:process\.exit|return\b)|^\s*if\s+([^\n:]{1,300}):\s*\n?\s*(?:sys\.exit|return\b|exit\()/gm;
  let g: RegExpExecArray | null;
  while ((g = reIf.exec(src))) {
    if (g.index > firstEffect || !ctx.isCode(g.index)) continue;
    let cond = (g[1] ?? g[2] ?? '').trim();
    if (/^[A-Za-z_$][\w$]*$/.test(cond)) cond = ctx.constInit(cond) ?? cond;
    if (/process\.env\.CI\b|environ(?:\.get)?\s*[([]\s*['"]CI['"]/.test(cond) && !gate.includes('CI')) gate.push('CI');
    if (/isTTY|isatty\s*\(/.test(cond)) {
      ttyGated = true;
      if (!gate.includes('non-interactive install (no terminal)')) gate.push('non-interactive install (no terminal)');
    }
    for (const v of cond.matchAll(/process\.env\.([A-Z0-9_]*(?:NO_|SKIP|DISABLE|OPT_?OUT)[A-Z0-9_]*)/g)) if (!gate.includes(v[1]!)) gate.push(v[1]!);
  }

  const network = reviewed.some((f) => NETWORK.test(stripComments(f.content)));
  const programs = new Set<string>();
  let ownCliOnly = true;
  for (const f of reviewed) {
    for (const c of scanProcessCalls(fileCtxOf(f)).calls) {
      const own = (c.program === '<node>' || /^(?:node|python3?|sys\.executable)$/.test(c.program)) && c.shape.startsWith('fixed-program');
      if (!own) {
        ownCliOnly = false;
        programs.add(c.program);
      }
    }
  }

  const writes = reviewed.some((f) => WRITE.test(stripComments(f.content)));
  const homeWrites = new Set<string>();
  for (const f of reviewed) for (const p of homePaths(f)) homeWrites.add(p);
  const toolConfigWrites = [...homeWrites].filter((p) => TOOL_CONFIG.test(p.replace(/^~\//, '/')));

  const prompt = /\[Y\/n\]/.test(src) ? 'default-yes' : /\[y\/N\]/.test(src) ? 'default-no' : undefined;

  const builtins = new Set(builtinModules.flatMap((b) => [b, `node:${b}`]));
  const opaque = new Set<string>();
  for (const f of reviewed) {
    const c = fileCtxOf(f);
    for (const m of f.content.matchAll(/\b(?:from|import|require)\s*\(?\s*['"]([^'"./][^'"]*)['"]/g)) {
      if (!c.isCode(m.index!)) continue;
      const spec = m[1]!;
      if (builtins.has(spec) || builtins.has(spec.split('/')[0]!)) continue;
      opaque.add(spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!);
    }
    if (/\.py$/i.test(f.path)) {
      for (const m of f.content.matchAll(/^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/gm)) {
        const mod = (m[1] ?? m[2])!.split('.')[0]!;
        if (!PY_STDLIB.has(mod) && !mod.startsWith('_')) opaque.add(mod);
      }
    }
  }

  return {
    script,
    gate,
    ttyGated,
    network,
    ownCliOnly,
    programs: [...programs].sort(),
    writes,
    homeWrites: [...homeWrites].sort(),
    toolConfigWrites: toolConfigWrites.sort(),
    ...(prompt ? { prompt } : {}),
    opaqueDeps: [...opaque].sort(),
  };
}

/** Python modules whose behaviour is known well enough not to block a verdict. */
const PY_STDLIB = new Set(['os', 'sys', 'pathlib', 'shutil', 'subprocess', 'json', 're', 'platform', 'getpass', 'stat', 'textwrap', 'typing', 'enum', 'argparse', 'logging', 'tempfile', 'site', 'sysconfig', 'importlib', 'io', 'time', 'datetime', 'glob', 'fnmatch', 'functools', 'itertools', 'collections', 'contextlib', 'dataclasses', 'configparser', 'urllib', 'http', 'socket', 'ssl', 'hashlib', 'base64', 'zipfile', 'tarfile']);

/** Package files the hook loads: relative imports/requires and folded own-package paths (one level). */
function loadedPackageFiles(file: SourceFile, byPath: Map<string, SourceFile>): SourceFile[] {
  const ctx = fileCtxOf(file);
  const src = file.content;
  const dir = file.path.includes('/') ? file.path.slice(0, file.path.lastIndexOf('/')) : '';
  const out = new Map<string, SourceFile>();
  const add = (rel: string, fromDir: boolean): void => {
    for (const base of fromDir ? [join(dir, rel), rel] : [rel]) {
      for (const cand of [base, `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`]) {
        const hit = byPath.get(cand);
        if (hit && hit !== file) {
          out.set(cand, hit);
          return;
        }
      }
    }
  };
  for (const m of src.matchAll(/\b(?:from|import|require)\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g)) if (ctx.isCode(m.index!)) add(m[1]!, true);
  for (const m of src.matchAll(/\b(?:require|import)\s*\(\s*(?!['"`])/g)) {
    if (!ctx.isCode(m.index!)) continue;
    const args = splitArgs(src, ctx.mask, src.indexOf('(', m.index!));
    if (!args || args.args.length !== 1) continue;
    const v = fold(ctx, args.args[0]!, { at: m.index!, pathContext: true });
    if (v.kind === 'own-path') add(v.value, true);
  }
  return [...out.values()];
}

/** `path.join(<home>, "a", "b")` and friends → `~/a/b` (literal segments only). */
function homePaths(f: SourceFile): string[] {
  const ctx = fileCtxOf(f);
  const src = f.content;
  const out: string[] = [];
  for (const m of src.matchAll(/\b(?:path\.)?(?:join|resolve)\s*\(/g)) {
    if (!ctx.isCode(m.index!)) continue;
    const args = splitArgs(src, ctx.mask, m.index! + m[0].length - 1);
    if (!args || args.args.length < 2) continue;
    if (!HOME_ROOT.test(args.args[0]!)) continue;
    const segs: string[] = [];
    for (const a of args.args.slice(1)) {
      const v = fold(ctx, a, { at: m.index! });
      if (v.kind !== 'literal' || v.values.length !== 1) break;
      segs.push(v.values[0]!);
    }
    if (segs.length) out.push(`~/${segs.join('/')}`);
  }
  for (const m of src.matchAll(/['"`]~\/([^'"`\s]+)['"`]/g)) out.push(`~/${m[1]}`);
  return out;
}

function join(dir: string, rel: string): string {
  const parts: string[] = [];
  for (const seg of `${dir}/${rel}`.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return parts.join('/');
}

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1').replace(/^\s*#[^\n]*/gm, '');
}
