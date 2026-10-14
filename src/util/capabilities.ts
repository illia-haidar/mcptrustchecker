/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Capability extraction: derive each tool's roles (untrusted-input,
 * sensitive-source, external-sink, code-exec, file-write) from its name,
 * description verbs, and parameter shape. This is the substrate the toxic-flow
 * graph runs over.
 *
 * Since 1.16 two more inputs can ADD roles, and neither can remove one:
 *   - the tool's own `annotations` — a server that declares `readOnlyHint:
 *     false` or `openWorldHint: true` is telling the client it writes or reaches
 *     outside. Annotations are untrusted, so they only ever raise: a self-declared
 *     `readOnlyHint: true` never strips what the name or the handler shows, or a
 *     hostile server could hide a write behind a hint;
 *   - for a statically recovered tool, what its handler visibly does (an HTTP
 *     POST/PUT/PATCH/DELETE to an API).
 *
 * Since 1.16.1 a keyword in the DESCRIPTION counts only where the prose says the
 * tool does it: not after a negation ("Do NOT use curl or fetch", "it cannot
 * fetch updates"), and not inside the name of another tool on the surface ("call
 * auth.get_token next" is about that tool). The tool's own name is never
 * filtered. Each tag also records where its evidence sits (`sources`).
 *
 * Also since 1.16.1, a code-exec or file-write keyword that is another word in
 * its tool (`eval_run` is an evaluation, `ue_spawn_actor` places a game object,
 * `rootr_unlink_row_page` removes a relation, a speech tool's `script` is spoken)
 * gives no tag. MTC-CAP-003 reads the same homonym rules, so the capability
 * level, MTC-CAP-001/002 and MTC-CAP-003 agree.
 */

import type { CapabilitySource, CapabilityTag, ResolvedConfig, ServerSurface, StaticToolOrigin, ToolCapability, ToolDef } from '../types.js';
import { CAPABILITY_SIGNALS, PARAM_NAME_SIGNALS } from '../data/capabilityLexicon.js';
import { normalizeForMatch } from './text.js';

function tokenize(text: string): Set<string> {
  return new Set(normalizeForMatch(text).split(' ').filter(Boolean));
}

function keywordMatches(haystack: string, tokens: Set<string>, keyword: string): boolean {
  const k = normalizeForMatch(keyword);
  if (k.includes(' ')) return haystack.includes(k);
  return tokens.has(k);
}

/** A sentence end in the prose, kept as its own token so a negation does not reach past it. */
const STOP = '\u0001';
/** Where another tool's name stood: matches no keyword and negates nothing. */
const MASK = '\u0002';
/** Tokens before a keyword that a negation may stand on ("do NOT use curl or fetch" — four). */
const NEGATION_WINDOW = 4;
const NEGATORS = new Set(['not', 'never', 'cannot', "can't", 'can’t', "don't", 'don’t', "doesn't", 'doesn’t', "won't", 'won’t']);
/**
 * A negated verb of failing or holding back affirms what follows: "Don't
 * hesitate to fetch", "never fails to fetch", "will never refuse to download",
 * "Do NOT stop until you curl", "Never ask before running webhook calls".
 */
const NEGATION_CANCELLERS = new Set([
  'hesitate', 'hesitates', 'hesitating', 'fail', 'fails', 'failing', 'forget', 'forgets', 'refuse', 'refuses',
  'stop', 'stops', 'wait', 'waits', 'matter', 'matters', 'mind', 'limited', 'until', 'ask', 'asks', 'asking',
  'cease', 'ceases', 'neglect', 'neglects', 'omit', 'skip',
]);
/** After a comma, these open a new clause ("Not cached, will fetch fresh data"); a list item does not. */
const CLAUSE_OPENERS = new Set([
  'will', 'would', 'can', 'could', 'may', 'might', 'should', 'must', 'it', 'its', "it'll", 'we', 'they', 'you', 'i',
  'this', 'that', 'which', 'then', 'but', 'so', 'just', 'also', 'always', 'instead', 'still', 'now', 'simply',
]);
/** Other tools' names masked in one description, at most — past it, prose counts as before. */
const MAX_MASKED_NAMES = 256;

/**
 * A tool's description, tokenised the way {@link keywordMatches} reads it, with
 * sentence ends marked and other tools' names masked. `hit(kw)` is true when the
 * keyword stands somewhere the prose is not negating it.
 */
class DescriptionMatcher {
  private readonly tokens: string[];
  private readonly text: string;
  private readonly starts: number[];
  private readonly set: Set<string>;

  constructor(desc: string, otherNames: readonly string[]) {
    // Another tool is named the way identifiers are written: `auth.get_token`,
    // "web3_list_keys,", `get_secret` in backticks. Only that is masked — the
    // same words in prose ("List files attached to a task" next to a
    // `list_files` tool) are prose. A one-word name (`curl`, `fetch`) is a tool
    // only where the text marks it as one: quoted, `curl tool`, `call curl`.
    let raw = desc;
    for (const n of otherNames) {
      if (!raw.includes(n)) continue;
      raw = maskMentions(raw, n);
    }
    // `.` before a space, a newline and a spaced or bare dash end a clause;
    // marking them keeps every other token exactly as `normalizeForMatch` makes it.
    const text = normalizeForMatch(raw.replace(/\.(?=\s|$)|\n|\s[-–—]+(?=\s)|[—–]/g, ` ${STOP} `));
    this.text = text;
    this.tokens = text ? text.split(' ') : [];
    this.set = new Set(this.tokens);
    this.starts = [];
    let at = 0;
    for (const t of this.tokens) {
      this.starts.push(at);
      at += t.length + 1;
    }
  }

  hit(keyword: string): boolean {
    const k = normalizeForMatch(keyword);
    if (!k) return false;
    if (!k.includes(' ')) {
      if (!this.set.has(k)) return false;
      for (let i = 0; i < this.tokens.length; i++) if (this.tokens[i] === k && !this.negatedAt(i)) return true;
      return false;
    }
    // A phrase matches as a substring, as `keywordMatches` does.
    for (let at = this.text.indexOf(k); at >= 0; at = this.text.indexOf(k, at + 1)) {
      if (!this.negatedAt(this.tokenAt(at))) return true;
    }
    return false;
  }

  /** Index of the token holding character offset `at`. */
  private tokenAt(at: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= at) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  /**
   * A negation within {@link NEGATION_WINDOW} tokens before token `i`, inside its
   * clause, that governs it: not one cancelled by a verb of failing between them
   * ("don't hesitate to fetch").
   */
  private negatedAt(i: number): boolean {
    const word = (j: number): string => {
      const raw = this.tokens[j] ?? '';
      // A negator is a short word; a long token is never one (and is not trimmed).
      return raw.length <= 12 ? raw.replace(/^[^a-z]+|[^a-z]+$/g, '') : '';
    };
    for (let j = i - 1, seen = 0; j >= 0 && seen < NEGATION_WINDOW; j--, seen++) {
      const raw = this.tokens[j]!;
      // A sentence or clause ends here: what stands before it is not about this keyword.
      const end = raw[raw.length - 1];
      if (raw === STOP || end === '!' || end === '?' || end === ';' || end === ':' || end === ')') return false;
      // A comma ends a clause when a new one starts after it — not between list items.
      if (end === ',' && (CLAUSE_OPENERS.has(word(j + 1)) || this.insteadOfBefore(j))) return false;
      const w = word(j);
      // "not only fetches …" / "not just" adds, it does not negate.
      const negates = (NEGATORS.has(w) && !(w === 'not' && (word(j + 1) === 'only' || word(j + 1) === 'just'))) || (w === 'instead' && word(j + 1) === 'of');
      if (negates) {
        for (let k = j + 1; k < i; k++) if (NEGATION_CANCELLERS.has(word(k))) return false;
        return true;
      }
      if (raw.startsWith('(')) return false; // the keyword is outside "(not cached)"
    }
    return false;
  }

  /** Does "instead of" stand within the window before token `j`? ("Instead of caching, fetch …") */
  private insteadOfBefore(j: number): boolean {
    for (let k = j; k >= 0 && k > j - NEGATION_WINDOW; k--) {
      if (this.tokens[k] === 'instead' && this.tokens[k + 1]?.replace(/[^a-z]+$/, '') === 'of') return true;
    }
    return false;
  }
}

/**
 * Mask each mention of tool name `name` written as an identifier: bounded so it
 * is not part of a longer name, and — for a one-word name — quoted, followed by
 * "tool", or called.
 */
function maskMentions(text: string, name: string): string {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const oneWord = /^[A-Za-z][a-z0-9]*$/.test(name);
  const re = new RegExp(`(?<![\\w.$-])${esc}(?![\\w$-]|\\.\\w)`, 'g');
  return text.replace(re, (m, at: number) => {
    if (oneWord) {
      const before = text.slice(Math.max(0, at - 16), at);
      const after = text.slice(at + m.length, at + m.length + 8);
      const quoted = /[`'"]$/.test(before) && /^[`'"]/.test(after);
      if (!quoted && !/^\s{1,3}tool\b/i.test(after) && !/\b(?:call|calls|calling|invoke|invokes|invoking)\s{1,3}$/i.test(before)) return m;
    }
    return ` ${MASK} `;
  });
}

const relevantNamesMemo = new WeakMap<readonly string[], string[]>();

/**
 * The surface's tool names a description may mention, as declared — only those
 * that themselves contain a capability keyword (no other name can change a
 * match), longest first, without the tool's own name.
 */
function otherToolNames(ownName: string, surfaceNames: readonly string[] | undefined): string[] {
  if (!surfaceNames?.length) return [];
  let relevant = relevantNamesMemo.get(surfaceNames);
  if (!relevant) {
    const set = new Set<string>();
    for (const raw of surfaceNames) {
      if (typeof raw !== 'string' || set.size >= MAX_MASKED_NAMES) continue;
      if (raw.length < 3 || raw.length > 200 || set.has(raw)) continue;
      const n = normalizeForMatch(raw);
      const toks = tokenize(raw);
      if (CAPABILITY_SIGNALS.some((sig) => sig.keywords.some((kw) => keywordMatches(n, toks, kw)))) set.add(raw);
    }
    relevant = [...set].sort((a, b) => b.length - a.length);
    relevantNamesMemo.set(surfaceNames, relevant);
  }
  return relevant.filter((n) => n !== ownName);
}

function paramNames(tool: ToolDef): string[] {
  const props = tool.inputSchema?.properties;
  if (!props) return [];
  return Object.keys(props);
}

// --- Homonyms ----------------------------------------------------------------
//
// A code-exec or file-write keyword in a tool's NAME, or a command-shaped
// PARAMETER, is sometimes another word that looks the same: `eval_run` is an
// evaluation, `ue_spawn_actor` places a game object, `rootr_unlink_row_page`
// removes a relation, and the `script` of `dialogue_to_speech` is the text to be
// spoken. Tag derivation (below) and the annotation check (MTC-CAP-003) read
// these rules from here, so the capability level, MTC-CAP-001/002 and
// MTC-CAP-003 agree. Each exemption is narrow and none needs handler evidence: a
// live scan has none, and a hostile server's `exec_shell_info` must still be
// caught by its name alone.

const tokensOf = (s: string): string[] => s.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean);
const hasAny = (tokens: Iterable<string>, words: Set<string>): boolean => {
  for (const t of tokens) if (words.has(t)) return true;
  return false;
};

/** The words of one tool the homonym rules read. */
export interface ToolWords {
  /** Name tokens in order, as {@link normalizeForMatch} splits them. */
  name: string[];
  nameSet: Set<string>;
  /** Parameter names as declared. */
  params: string[];
  paramTokens: Set<string>;
  description: string;
  title: string;
}

export function toolWords(tool: ToolDef): ToolWords {
  const name = normalizeForMatch(typeof tool?.name === 'string' ? tool.name : '').split(' ').filter(Boolean);
  const params = paramNames(tool);
  return {
    name,
    nameSet: new Set(name),
    params,
    paramTokens: new Set(params.flatMap(tokensOf)),
    description: typeof tool?.description === 'string' ? tool.description : '',
    title: typeof tool?.title === 'string' ? tool.title : '',
  };
}

// Next to `eval`, these make it code evaluation (`js_eval`, `eval_expression`);
// without one, `eval_run` / `eval_gate` / `get_recall_eval` name an EVALUATION — a
// score or a test run — not an interpreter.
// A language's name counts the same (`rego_eval_with_profile` evaluates Rego).
const CODE_TOKENS = new Set(['code', 'js', 'javascript', 'ts', 'typescript', 'python', 'py', 'expr', 'expression', 'script', 'shell', 'cmd', 'command', 'snippet', 'program', 'lua', 'ruby', 'repl', 'rego', 'sql', 'jq', 'tcl', 'perl', 'php', 'bash', 'sh', 'wasm', 'lisp', 'clojure', 'julia', 'groovy', 'starlark', 'jsonata', 'jmespath', 'xpath', 'cel']);
// …or a description that says what is evaluated ("Evaluate a JavaScript expression").
const CODE_PROSE = /\b(?:javascript|typescript|python|js|code|expressions?|snippets?|scripts?|interpret\w*|repl|sandbox|rego|sql|lua|ruby|wasm)\b/i;
// …unless that description says the tool parses or validates it ("Parse and
// validate a .manim source snippet"): a checker named eval, not an interpreter.
const PARSE_LEAD = /^\s*(?:parses?|parsing|validates?|validating|lints?|linting)\b/i;
// Next to `spawn`, a game-engine object (`ue_spawn_actor`, `scene_spawn`) — unless
// a process word says otherwise (`spawn_worker`, `spawn_shell_process`).
const GAME_SPAWN_TOKENS = new Set(['actor', 'actors', 'entity', 'entities', 'npc', 'npcs', 'prefab', 'prefabs', 'mob', 'mobs', 'pawn', 'character', 'characters', 'enemy', 'enemies', 'item', 'items', 'particle', 'particles', 'vehicle', 'object', 'objects', 'scene', 'level', 'blueprint', 'mesh', 'sprite', 'creature', 'monster']);
const PROCESS_TOKENS = new Set(['process', 'proc', 'subprocess', 'shell', 'cmd', 'command', 'child', 'exec', 'terminal', 'bash', 'worker', 'agent', 'subagent', 'job', 'task', 'daemon', 'server', 'container', 'pod', 'vm', 'sandbox', 'session']);
// `unlink` is unlink(2) when it is the bare verb (`state-unlink`), when something
// file-shaped is named next to it, or when the tool says it deletes a file.
// Otherwise `unlink_<record>` removes a link between records. A folder is not on
// the list: `unlink_folder_guide` takes a guide out of a folder.
const UNLINK_FILE_TOKENS = new Set(['file', 'files', 'disk', 'disks', 'path', 'paths', 'dir', 'dirs', 'directory', 'directories', 'volume', 'volumes', 'symlink', 'symlinks', 'inode', 'inodes', 'fs', 'filesystem']);
// What usually lives on disk as a file — a `lockfile` / `pidfile` (any token
// ending in "file"), a socket, a temp or cache entry, a lock. These count unless
// the tool says it deletes no file ("Unlink a record. Does not delete the file.").
const UNLINK_FILEISH_TOKENS = new Set(['socket', 'sockets', 'sock', 'tmp', 'temp', 'tempdir', 'cache', 'caches', 'lock', 'locks', 'pid', 'fifo']);
const fileish = (t: string): boolean => UNLINK_FILEISH_TOKENS.has(t) || /^[a-z0-9]{1,24}files?$/.test(t);
const DENIES_DELETING_FILE = /\b(?:does not|doesn['’]t|never|will not|won['’]t|is not|isn['’]t)\s+(?:deleted?|removed?|erased?|unlinked?)\b/i;
const DELETES_FILE = /\b(?:deletes?|deleting|removes?|removing|erases?|erasing|unlinks?)\s+(?:\S+\s+){0,3}?(?:files?|symlinks?|director(?:y|ies)|sockets?)\b|\b(?:from|on|off)\s+(?:the\s+)?(?:disk|filesystem|file\s+system)\b/gi;
const NEGATED_BEFORE = /\b(?:not|never|without|no)\s*$|n['’]t\s*$/i;
// A `script` parameter on a speech / media tool is the text to be spoken.
const SPOKEN_SCRIPT_CONTEXT = /\b(?:speech|speak|spoken|voices?|audio|tts|dialogue|narrat\w*|podcast|screenplay|subtitles?|captions?|voiceovers?|lines? of dialogue)\b/i;
const EXEC_SEMANTICS = /\b(?:execut\w*|eval\w*|shell|bash|interpret\w*|python|javascript|typescript|powershell|sandbox|runs?|running)\b/i;

/** The description says, not negated, that the tool deletes a file ("This deletes the .contextforge file"). */
function deletesFile(description: string): boolean {
  if (description.length > MAX_PROSE) return true; // not read whole: no exemption rests on it
  const text = description;
  DELETES_FILE.lastIndex = 0;
  for (let m = DELETES_FILE.exec(text); m; m = DELETES_FILE.exec(text)) {
    if (!NEGATED_BEFORE.test(text.slice(Math.max(0, m.index - 12), m.index))) return true;
  }
  return false;
}

function evalIsCode(w: ToolWords): boolean {
  if (w.name.length === 1) return true; // a tool called just `eval`
  if (hasAny(w.nameSet, CODE_TOKENS) || hasAny(w.paramTokens, CODE_TOKENS)) return true;
  if (!CODE_PROSE.test(w.description)) return false;
  return !(PARSE_LEAD.test(w.description) && !assertsExecution(w.description));
}

function unlinkIsAssociation(w: ToolWords): boolean {
  const at = w.name.indexOf('unlink');
  if (at < 0 || at === w.name.length - 1) return false;
  if (hasAny(w.nameSet, UNLINK_FILE_TOKENS) || hasAny(w.paramTokens, UNLINK_FILE_TOKENS) || deletesFile(w.description)) return false;
  return !((w.name.some(fileish) || [...w.paramTokens].some(fileish)) && !DENIES_DELETING_FILE.test(w.description.slice(0, MAX_PROSE)));
}

/** Prose that says a process is started ("Spawns a child process …") overrules a game-object reading of `spawn`. */
const PROCESS_PROSE = /\b(?:child\s+process(?:es)?|sub-?process(?:es)?|(?:a|new|os|system)\s+process(?:es)?|shell\s+command|executable)\b/i;

/**
 * Is name keyword `kw` (a code-exec / file-write lexicon keyword found in the
 * tool's NAME) another word here — an evaluation, a game object, a relation?
 */
export function nameKeywordIsHomonym(kw: string, w: ToolWords): boolean {
  const k = normalizeForMatch(kw);
  if (k === 'eval') return !evalIsCode(w);
  if (k === 'spawn') return hasAny(w.nameSet, GAME_SPAWN_TOKENS) && !hasAny(w.nameSet, PROCESS_TOKENS) && !PROCESS_PROSE.test(w.description.slice(0, MAX_PROSE));
  if (k === 'unlink') return unlinkIsAssociation(w);
  return false;
}

/** The description a parameter declares in its schema, if any. */
export function schemaParamDescription(tool: ToolDef, param: string): string {
  const props = tool?.inputSchema?.properties;
  const p = props && Object.hasOwn(props, param) ? props[param] : undefined;
  return p && typeof p === 'object' && typeof p.description === 'string' ? p.description : '';
}

/**
 * Is code-exec parameter token `token` of parameter `param` another word here?
 * `eval_id` / `eval_name` name an evaluation (a parameter called `eval`
 * evaluates); the `script` of a speech tool is the text to be spoken unless its
 * text says it is run.
 */
export function execParamIsHomonym(param: string, token: string, tool: ToolDef, w: ToolWords): boolean {
  const toks = tokensOf(param);
  if (token === 'eval') return toks.length > 1 && !toks.some((x) => CODE_TOKENS.has(x));
  if (token === 'script' && SPOKEN_SCRIPT_CONTEXT.test(`${w.name.join(' ')} ${w.title} ${w.description}`)) {
    return !EXEC_SEMANTICS.test(`${w.description} ${schemaParamDescription(tool, param)}`);
  }
  return false;
}

/** Verbs that, next to a `url` parameter, say the tool reads that URL. */
const FETCH_VERBS = ['fetch', 'fetches', 'download', 'downloads', 'scrape', 'scrapes', 'crawl', 'crawls', 'browse', 'browses', 'retrieve', 'retrieves'];

// --- Execution verbs -----------------------------------------------------------

/**
 * Prose read for execution verbs, at most (a description can be megabytes). A
 * rule that lowers or exempts on what prose does NOT say never rests on prose
 * longer than this: it is not read whole.
 */
export const MAX_PROSE = 8_000;
// "executed" is the passive of the same assertion ("Build steps are executed in
// the build container", "Commands to RUN steps, executed verbatim"), as "are run"
// already was; "previously / already executed" stays someone else's run.
const RUN_VERBS = new Set(['run', 'runs', 'running', 'rerun', 'reruns', 'rerunning', 'execute', 'executes', 'executing', 'executed', 'exec', 'execs', 'eval', 'evals', 'evaluate', 'evaluates', 'evaluating', 'spawn', 'spawns', 'spawning', 'invoke', 'invokes', 'invoking']);
/** Verbs that mean execution only with a process-like word nearby ("start the MCP server", "Starts an interactive process"). */
const START_VERBS = new Set(['start', 'starts', 'starting', 'launch', 'launches', 'launching']);
const PROCESS_NOUNS = new Set(['process', 'processes', 'subprocess', 'server', 'servers', 'program', 'programs', 'daemon', 'session', 'sessions', 'repl', 'shell', 'interpreter', 'command', 'commands', 'cmd', 'script', 'scripts', 'service', 'services', 'container', 'containers', 'worker', 'workers', 'binary', 'executable']);
/** `run` as a noun: "a dry run", "the last run", "per run". */
const RUN_NOUN_BEFORE = new Set(['a', 'an', 'the', 'each', 'per', 'every', 'last', 'next', 'previous', 'this', 'that', 'first', 'test', 'dry', 'trial', 'one', 'any', 'its', 'their', 'your', 'our', 'my']);
/** `running` as a state or an adjective: "a long-running session", "is running", "running processes". */
const RUNNING_STATE_BEFORE = new Set(['long', 'still', 'currently', 'already', 'is', 'are', 'was', 'were', 'be', 'been', 'keep', 'keeps', 'while']);
const RUNNING_ADJ_NOUNS = new Set([...PROCESS_NOUNS, 'job', 'jobs', 'task', 'tasks', 'instance', 'instances', 'pod', 'pods', 'vm', 'vms', 'app', 'apps', 'agent', 'agents', 'sandbox', 'sandboxes', 'workflow', 'workflows', 'build', 'builds', 'total', 'count', 'tally', 'average', 'list']);
/** `exec` / `eval` are verbs only where a verb stands ("to exec", "and eval"); elsewhere a noun: "a previously launched exec". */
const SHORT_VERB_BEFORE = new Set(['to', 'and', 'or', 'then', 'can', 'will', 'may', 'must', 'it', 'which', 'that', 'also', 'directly', 'simply', 'just']);
const VERB_NEGATORS = new Set(['not', 'never', 'cannot', "can't", "don't", "doesn't", "won't", "didn't", "isn't", 'no', 'nor', 'without']);
/** Words that make the verb about someone else's run, or a later or earlier one: "would execute", "before running it", "already run". */
const NOT_ASSERTED = new Set(['would', 'could', 'might', 'already', 'previously', 'before']);
const VERB_WINDOW = 4;

/**
 * A Dockerfile instruction named by its upper-case keyword — "Default shell for
 * RUN instruction linting" — is a noun, not an order to run anything. Read
 * before the text is lower-cased; "run instructions" in lower case stays a verb.
 */
const DOCKERFILE_KEYWORD = /\b(?:RUN|CMD|ENTRYPOINT)(?=\s{1,4}(?:instructions?|directives?|lines?|statements?|steps?|layers?)\b)/g;

/** Each sentence of `text` as lowercase word tokens. */
export function proseSentences(text: string): string[][] {
  if (!text) return [];
  return text
    .slice(0, MAX_PROSE)
    .replace(DOCKERFILE_KEYWORD, 'dockerfile')
    .replace(/[’‘]/g, "'")
    .split(/[.!?;]+(?=\s|$)|\n+/)
    .map((s) => s.toLowerCase().match(/[a-z0-9]+(?:'[a-z]+)?/g) ?? [])
    .filter((s) => s.length > 0);
}

/**
 * Does token `i` of sentence `s` say that something is run, executed, evaluated,
 * spawned or started — as a verb, asserted? Not a noun ("a dry run"), not a state
 * ("long-running", "running processes"), not negated ("without re-running
 * them"), and not someone else's or an earlier run ("would execute", "before
 * running it", "a previously launched exec").
 */
export function execVerbAt(s: readonly string[], i: number): boolean {
  const w = s[i] ?? '';
  const prev = s[i - 1] ?? '';
  const next = s[i + 1] ?? '';
  const shellOut = (w === 'shell' || w === 'shells') && next === 'out';
  if (!RUN_VERBS.has(w) && !START_VERBS.has(w) && !shellOut) return false;
  if ((w === 'run' || w === 'runs') && RUN_NOUN_BEFORE.has(prev)) return false;
  if ((w === 'exec' || w === 'execs' || w === 'eval' || w === 'evals') && i > 0 && !SHORT_VERB_BEFORE.has(prev)) return false;
  if (w === 'running' && (RUNNING_STATE_BEFORE.has(prev) || RUNNING_ADJ_NOUNS.has(next))) return false;
  if (START_VERBS.has(w)) {
    let near = false;
    for (let j = Math.max(0, i - 3); j <= Math.min(s.length - 1, i + 3) && !near; j++) near = j !== i && PROCESS_NOUNS.has(s[j]!);
    if (!near) return false;
  }
  for (let j = i - 1; j >= 0 && j >= i - VERB_WINDOW; j--) {
    const t = s[j]!;
    if (VERB_NEGATORS.has(t) && !(t === 'not' && (s[j + 1] === 'only' || s[j + 1] === 'just'))) return false;
    if (NOT_ASSERTED.has(t) || (t === 'about' && s[j + 1] === 'to') || (t === 'instead' && s[j + 1] === 'of')) return false;
  }
  return true;
}

/**
 * Does any sentence of `text` assert execution (see {@link execVerbAt})? Prose
 * too long to read whole counts as asserting it.
 */
export function assertsExecution(text: string): boolean {
  if (text.length > MAX_PROSE) return true;
  return proseSentences(text).some((s) => s.some((_, i) => execVerbAt(s, i)));
}

// --- Parameters of a statically recovered tool ---------------------------------

/** Source read after a static registration, at most, and of one parameter's value. */
const MAX_REGISTRATION = 12_000;
const MAX_PARAM_VALUE = 2_000;
const NEXT_REGISTRATION = /\.(?:registerTool|addTool|tool)\s*\(|@[A-Za-z_][\w.]{0,60}\.tool\b/;
const SCHEMA_ANCHOR = /\b(?:inputSchema|input_schema|parameters|paramsSchema|properties)\s*[:=]|\bz\d?\s*\.\s*object\s*\(|\bdef\s+[A-Za-z_]\w{0,80}\s*\(/;
const PARAM_DESCRIPTION = /(?:\.describe\s*\(\s*|\bdescription\s*[:=]\s*)(?:'((?:[^'\\\n]|\\.){0,1500})'|"((?:[^"\\\n]|\\.){0,1500})"|`([^`\\]{0,1500})`)/;
const STRING_LITERAL = /'(?:[^'\\\n]|\\.){0,2000}'|"(?:[^"\\\n]|\\.){0,2000}"|`[^`\\]{0,2000}`/g;
const CONSTRAINED_VALUE = /\.\s*enum\s*\(|\bz\d?\s*\.\s*(?:enum|nativeEnum|literal|boolean|number|bigint)\b|\benum\s*:|\bconst\s*:|\bLiteral\s*\[|\btype\s*:\s*["'](?:boolean|number|integer)["']|^\s*(?:bool|int|float)\b/;
const VALUE_PATTERN = /\.regex\s*\(\s*\/((?:[^/\\\n]|\\.){1,80})\/|\bpattern\s*[:=]\s*(?:'((?:[^'\\\n]|\\.){1,80})'|"((?:[^"\\\n]|\\.){1,80})")/;

/** What a static registration's source says about one parameter. */
export interface ParamFacts {
  description?: string;
  /** An enum, a literal, a boolean/number type or a short restrictive pattern. */
  constrained: boolean;
  /**
   * The registration's `.regex(/…/)` / `pattern:` when it is the value's only
   * constraint (no enum, literal or non-string type). A pattern searches rather
   * than matches whole, so a caller that needs the value pinned (a destination,
   * not an alphabet) reads it: `^https?://` admits any host.
   */
  pattern?: string;
}

/** A pattern that admits only a narrow alphabet (`^[a-z0-9_-]+$`), not anything (`.*`, `\S+`, `[^…]`). */
export function restrictivePattern(p: string): boolean {
  return p.length > 0 && p.length <= 80 && !/\.[*+{]|\\S[*+{]|\[\\s\\S\]|\[\^/.test(p);
}

/**
 * A `pattern` that bounds the WHOLE value over a narrow alphabet. JSON Schema
 * patterns search, they do not match whole: `^https?://` admits any host after
 * it, so only a pattern anchored at both ends (and not split by a top-level `|`)
 * that `restrictivePattern` accepts constrains where a request goes.
 */
export function boundsWholeValue(p: string): boolean {
  if (!restrictivePattern(p) || p[0] !== '^' || p[p.length - 1] !== '$') return false;
  let escapes = 0;
  for (let j = p.length - 2; j >= 0 && p[j] === '\\'; j--) escapes++;
  if (escapes % 2 === 1) return false;
  let depth = 0;
  let inClass = false;
  for (let j = 0; j < p.length; j++) {
    const ch = p[j];
    if (ch === '\\') j++;
    else if (inClass) inClass = ch !== ']';
    else if (ch === '[') inClass = true;
    else if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (ch === '|' && depth <= 0) return false;
  }
  return true;
}

/** The text of one tool's registration: from its name on the origin's line to the next registration. */
function registrationText(src: string, line: number, toolName: string): string {
  let at = 0;
  for (let n = 1; n < line; n++) {
    const nl = src.indexOf('\n', at);
    if (nl < 0) break;
    at = nl + 1;
  }
  // The tool's own name at or after that line: a bundle keeps every registration on one line.
  let from = -1;
  for (const probe of ['"', "'", '`'].map((q) => q + toolName + q).concat(`def ${toolName}(`)) {
    const j = src.indexOf(probe, at);
    if (j >= 0 && j - at < MAX_REGISTRATION && (from < 0 || j < from)) from = j;
  }
  if (from < 0) from = at;
  const text = src.slice(from, from + MAX_REGISTRATION);
  const skip = toolName.length + 2;
  const next = NEXT_REGISTRATION.exec(text.slice(skip));
  return next ? text.slice(0, skip + next.index) : text;
}

/** The value expression after `key:` at `start`: up to a comma or a closing bracket at its own depth. */
function valueAt(text: string, start: number): string {
  const end = Math.min(text.length, start + MAX_PARAM_VALUE);
  let depth = 0;
  let i = start;
  while (i < end) {
    const c = text[i]!;
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < end && text[j] !== c) j += text[j] === '\\' ? 2 : 1;
      i = j + 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
    } else if (c === ',' && depth === 0) break;
    i++;
  }
  return text.slice(start, Math.min(i, end));
}

/**
 * For a statically recovered tool, what its registration source says about
 * parameter `param`: the description it declares (`.describe("…")`,
 * `description: "…"`, `Field(description="…")`) and whether its value is
 * constrained (`z.enum([…])`, `Literal[…]`, a boolean or number). The static
 * extractor keeps only parameter NAMES; a live scan has the whole schema and
 * never needs this. Bounded reads only: the source is the server's own and may
 * be hostile.
 */
export function staticParamFacts(surface: ServerSurface, toolName: string, param: string): ParamFacts | undefined {
  if (surface?.toolProvenance !== 'static' || !surface.staticTools || !Object.hasOwn(surface.staticTools, toolName)) return undefined;
  if (!/^[A-Za-z_$][\w$-]{0,63}$/.test(param) || toolName.length > 200) return undefined;
  const origin = surface.staticTools[toolName];
  const files = Array.isArray(surface.sourceFiles) ? surface.sourceFiles : [];
  const file = origin && files.find((f) => f && f.path === origin.file);
  if (!file || typeof file.content !== 'string' || typeof origin.line !== 'number') return undefined;
  const text = registrationText(file.content, origin.line, toolName);
  const anchor = text.search(SCHEMA_ANCHOR);
  const body = anchor > 0 ? text.slice(anchor) : text;
  const esc = param.replace(/[$]/g, '\\$');
  const key = new RegExp(`(?:^|[\\s{,(])(["']?)${esc}\\1\\s*:`).exec(body);
  if (!key) return undefined;
  const value = valueAt(body, key.index + key[0].length);
  const code = value.replace(STRING_LITERAL, '""');
  const d = PARAM_DESCRIPTION.exec(value);
  const p = VALUE_PATTERN.exec(value);
  const pattern = p ? (p[1] ?? p[2] ?? p[3] ?? '') : '';
  const pinned = CONSTRAINED_VALUE.test(code);
  return {
    ...(d ? { description: d[1] ?? d[2] ?? d[3] ?? '' } : {}),
    constrained: pinned || (pattern !== '' && restrictivePattern(pattern)),
    ...(!pinned && pattern !== '' ? { pattern } : {}),
  };
}

/** Extract capability tags + evidence for a single tool. */
export function extractToolCapability(tool: ToolDef, origin?: StaticToolOrigin, surfaceNames?: readonly string[]): ToolCapability {
  const name = typeof tool?.name === 'string' ? tool.name : '';
  const desc = typeof tool?.description === 'string' ? tool.description : '';
  // Operative surface = the tool NAME only (what the tool DOES), used for the
  // high-impact capability tags below.
  const nameHay = normalizeForMatch(name);
  const nameTokens = tokenize(name);
  const prose = new DescriptionMatcher(desc, otherToolNames(name, surfaceNames));
  const reasons: Partial<Record<CapabilityTag, string[]>> = {};
  const sources: Partial<Record<CapabilityTag, CapabilitySource[]>> = {};
  const tags = new Set<CapabilityTag>();

  const addReason = (tag: CapabilityTag, why: string, from: CapabilitySource | CapabilitySource[]): void => {
    tags.add(tag);
    (reasons[tag] ??= []).push(why);
    const list = (sources[tag] ??= []);
    for (const f of Array.isArray(from) ? from : [from]) if (!list.includes(f)) list.push(f);
  };

  // `code-exec` and `file-write` are the tags that drive the biggest blast-radius
  // penalty (-6/-10). Require OPERATIVE evidence — the keyword in the tool NAME, not
  // in prose — for them: a read-only analyzer DESCRIBED as "detects shell/eval usage"
  // must not itself be tagged command-execution. Param-name signals (below) still add
  // operative evidence. Other tags keep name+description matching.
  const OPERATIVE_ONLY = new Set<CapabilityTag>(['code-exec', 'file-write']);
  // A name keyword that is another word here (`eval_run`, `ue_spawn_actor`,
  // `rootr_unlink_row_page`) is no evidence — see the homonym rules above.
  const words = toolWords(tool);
  for (const sig of CAPABILITY_SIGNALS) {
    const operative = OPERATIVE_ONLY.has(sig.tag);
    // One reason per signal is enough: the first keyword the tool shows. The
    // remaining keywords are read only to learn whether the NAME shows the role.
    let why: string | undefined;
    let inName = false;
    let inProse = false;
    for (const kw of sig.keywords) {
      if (keywordMatches(nameHay, nameTokens, kw) && !(operative && nameKeywordIsHomonym(kw, words))) {
        why ??= `keyword "${kw}"${operative ? ' in tool name' : ''}`;
        inName = true;
        break;
      }
      if (!operative && !why && prose.hit(kw)) {
        why = `keyword "${kw}"`;
        inProse = true;
      }
    }
    if (why) addReason(sig.tag, why, [...(inName ? ['name' as const] : []), ...(inProse ? ['description' as const] : [])]);
  }

  const pTokens = words.paramTokens;
  for (const sig of PARAM_NAME_SIGNALS) {
    for (const pn of sig.names) {
      if (!pTokens.has(pn)) continue;
      // Every parameter carrying it is another word here: `eval_id`, the `script` a speech tool speaks.
      if (sig.tag === 'code-exec' && words.params.every((p) => !tokensOf(p).includes(pn) || execParamIsHomonym(p, pn, tool, words))) continue;
      addReason(sig.tag, `parameter "${pn}"`, 'param');
      break;
    }
  }

  // Read-only getter exclusion: a tool whose NAME is a pure getter reads or
  // enumerates — it neither sends data out nor mutates files. A getter that only
  // MATCHED a sink/write keyword ('list_webhooks' hitting "webhook", 'get_config'
  // picking up external-sink) is a spurious toxic-flow leg, so strip those two
  // roles. Its read roles (sensitive-source / untrusted-input) are kept, and any
  // getter that ALSO does a write/send verb is left untouched.
  if (isPureGetter(name)) {
    tags.delete('external-sink');
    tags.delete('file-write');
    delete reasons['external-sink'];
    delete reasons['file-write'];
    delete sources['external-sink'];
    delete sources['file-write'];
  }

  // RAISE-ONLY inputs, applied after the getter exclusion so a declaration or a
  // handler that writes is never stripped by a reading name.
  const hints = declaredHints(tool);
  if (hints) {
    // destructiveHint means something only for a tool that is not read-only (the spec).
    const writes = hints.readOnlyHint === false || (hints.destructiveHint === true && hints.readOnlyHint !== true);
    const said = (): string =>
      [
        hints.readOnlyHint === false ? 'readOnlyHint: false' : '',
        hints.destructiveHint === true ? 'destructiveHint: true' : '',
        hints.openWorldHint === true ? 'openWorldHint: true' : '',
      ]
        .filter(Boolean)
        .join(', ');
    // A tool that changes something in the open world acts on an external
    // service; one that changes state without reaching outside changes the state
    // it holds. An open-world tool that does not declare a write reads from
    // outside: its answers are content nobody vetted.
    if (writes && hints.openWorldHint === true) addReason('external-sink', `declares ${said()}`, 'hint');
    else if (writes) addReason('state-write', `declares ${said()}`, 'hint');
    else if (hints.openWorldHint === true) addReason('untrusted-input', 'declares openWorldHint: true (interacts with entities outside the server)', 'hint');
  }
  for (const b of origin?.behavior ?? []) addReason(b.tag, `${b.why} at ${origin!.file}:${b.line}`, 'handler');

  // A tool that takes the URL itself — a parameter named `url` / `uri`, not a
  // token inside `relayer_ui_url` — and says it fetches, downloads or scrapes
  // takes in whatever the caller points it at. That makes its prose-only
  // untrusted-input leg operative (a live scan has no handler to show it).
  const from = sources['untrusted-input'];
  if (from && !from.some((f) => f !== 'description') && words.params.some((p) => /^(?:url|uri|urls|uris)$/i.test(p))) {
    const fetchVerb = FETCH_VERBS.find((v) => prose.hit(v));
    if (fetchVerb) addReason('untrusted-input', `parameter "url" with "${fetchVerb}" in the description`, 'param');
  }

  return {
    tool: name,
    tags: [...tags],
    reasons,
    ...(Object.keys(sources).length ? { sources } : {}),
    ...(hints ? { hints } : {}),
    ...(origin ? { hintSource: origin.hintSource } : {}),
  };
}

/**
 * A tool whose NAME is a pure getter — `get_*`, `list_*`, `*_status`, `*_info` —
 * and names no write or send verb. It reads or enumerates; a sink or mutation
 * keyword it happens to contain (`list_webhooks`, `vm_agent_exec_status`) is not
 * what it does.
 */
export function isPureGetter(name: string): boolean {
  const isGetter =
    /^(get|list|read|fetch|search|find|query|show|view|describe|count|check|has|is|lookup)[_-]/i.test(name) ||
    /(_results?|_list|_status|_info|_config|_details?|_metadata)$/i.test(name);
  const alsoMutates = /write|create|update|delete|set[_-]|put[_-]|send|post|upload|edit|modif|append|remove|publish|forward/i.test(name);
  return isGetter && !alsoMutates;
}

/** The explicit boolean hints a tool declares, or undefined when it declares none. */
function declaredHints(tool: ToolDef): ToolCapability['hints'] {
  const a = tool?.annotations;
  if (!a || typeof a !== 'object') return undefined;
  const out: NonNullable<ToolCapability['hints']> = {};
  for (const k of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const) {
    if (typeof a[k] === 'boolean') out[k] = a[k] as boolean;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Extract capabilities for every tool in a surface (non-object tools skipped). */
export function extractCapabilities(surface: ServerSurface, _config: ResolvedConfig): ToolCapability[] {
  const tools = Array.isArray(surface.tools) ? surface.tools : [];
  const origins = surface.toolProvenance === 'static' ? surface.staticTools : undefined;
  const defs = tools.filter((t): t is ToolDef => Boolean(t) && typeof t === 'object');
  // One array for every tool: the names a description may mention are read once.
  const names = defs.map((t) => (typeof t.name === 'string' ? t.name : ''));
  return defs.map((t) => extractToolCapability(t, origins && typeof t.name === 'string' && Object.hasOwn(origins, t.name) ? origins[t.name] : undefined, names));
}

/** Tags that can act as an exfiltration/impact sink. */
export const SINK_TAGS: CapabilityTag[] = ['external-sink', 'code-exec'];

/** True if a capability set can serve as an external sink. */
export function isSink(tags: CapabilityTag[]): boolean {
  return tags.some((t) => SINK_TAGS.includes(t));
}
