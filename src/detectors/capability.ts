/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 3 — Capability findings. The capability *tags* are computed by the
 * engine and shared via context; here we turn them into findings:
 *  - dangerous capabilities (command/code execution, filesystem mutation);
 *  - annotation-vs-behavior mismatch, open-world + sensitive read, and missing
 *    destructiveHint (the annotation-truthfulness story);
 *  - schema-level injection preconditions (unconstrained command / URL / path
 *    parameters — the advertised half of command-injection / SSRF / traversal);
 *  - declared server capabilities that are high-signal on their own (sampling,
 *    elicitation) — static proxies for classes rivals only catch at runtime.
 */

import type { CapabilityTag, Detector, DetectorContext, Finding, JsonSchema, ServerSurface, ToolCapability, ToolDef } from '../types.js';
import {
  CAPABILITY_SIGNALS,
  COMMAND_PARAM_NAMES,
  PARAM_NAME_SIGNALS,
  PATH_PARAM_NAMES,
  SECRET_FIELD_NAMES,
  SSRF_PARAM_NAMES,
} from '../data/capabilityLexicon.js';
import {
  assertsExecution,
  boundsWholeValue,
  execParamIsHomonym,
  execVerbAt,
  MAX_PROSE,
  nameKeywordIsHomonym,
  proseSentences,
  restrictivePattern,
  schemaParamDescription,
  staticParamFacts,
  toolWords,
  type ToolWords,
} from '../util/capabilities.js';
import { normalizeForMatch } from '../util/text.js';

function capFor(caps: ToolCapability[], tool: string): ToolCapability | undefined {
  return caps.find((c) => c.tool === tool);
}

const tokensOf = (s: string): string[] => s.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean);
const hasAny = (tokens: Set<string> | string[], words: Set<string>): boolean => [...tokens].some((t) => words.has(t));

// File-write keywords that only ADD (the MCP spec's destructiveHint=false case:
// "the tool performs only additive updates"). Every other file-write keyword —
// delete, remove, unlink, rmdir, overwrite, and the ambiguous write/edit/move —
// is treated as destructive.
const ADDITIVE_WRITE_KEYWORDS = new Set(['create file', 'save file', 'append file']);
// Any of these in the name or a parameter makes even an additive-looking write destructive.
const DESTRUCTIVE_TOKENS = new Set(['delete', 'del', 'remove', 'rm', 'unlink', 'rmdir', 'overwrite', 'drop', 'purge', 'wipe', 'truncate', 'erase', 'destroy', 'replace', 'move', 'rename', 'clear', 'reset']);
// The tool says, in its own words, that it does not run what it is given
// ("Does not execute or publish the bundle"), and nothing else in the text says
// it does. Third person only: an imperative "never run X" is a warning written
// for a tool that runs things. Only ever applied to PARAMETER evidence: a name
// like `exec_shell_info` is never talked out of.
const DISCLAIMS_EXEC = /\b(?:does not|doesn't|will not|won't) (?:execute|run)\b|\bwithout (?:executing|running)\b/gi;
const EXEC_VERB = /\b(?:execut\w*|runs?|running|eval\w*|spawn\w*|invoke[sd]?)\b/i;

function disclaimsExecution(description: string): boolean {
  const rest = description.replace(DISCLAIMS_EXEC, ' ');
  return rest !== description && !EXEC_VERB.test(rest);
}
// …but a tool that hands the command on to something else ("Forwards the command
// to the agent. Does not execute anything itself.") has it run elsewhere: the
// disclaimer lowers that evidence to weak, it does not remove it.
const HANDS_ON_COMMAND = /\b(?:forward|send|relay|pass|dispatch|submit|deliver|queue|proxie|proxy|route|hand)(?:s|es|ed|ing)?\s+(?:it\s+|them\s+)?(?:(?:the|this|a|an|each|every|your|its)\s+)?(?:command|commands|cmd|script|scripts|code|shell)\b/i;

// A plan / preview tool that says it changes nothing ("Preview deleting a project
// document … the tool itself modifies nothing"). Both halves are required, and it
// only discounts a NAME-derived file write, never execution.
const PLAN_FRAME = /^\s*(?:previews?|previewing|plans?|planning|dry[- ]?runs?|simulates?|simulating)\b/i;
// A plan that it then carries out is no preview ("Plans the removal of the file
// at path and carries it out; the plan itself modifies nothing").
const CARRIES_OUT =
  /\b(?:carr(?:y|ies|ying)\s+(?:it|them|this|that|(?:the|each)\s+\w+)\s+out|(?:appl(?:y|ies|ying)|execut(?:e|es|ing)|perform(?:s|ing)?|commit(?:s|ting)?)\s+(?:it|them|the\s+(?:plan|change|changes|deletion|removal|operation))|(?:and|then)\s+(?:deletes?|removes?|writes?|overwrites?|erases?|unlinks?|applies)\b)/i;
const NO_MUTATION = /\b(?:modifies|changes|writes|deletes|touches) nothing\b(?! else)|\b(?:does not|doesn't|never|will not|won't) (?:modify|write|delete|change|touch) anything\b|\bwithout (?:writing|modifying|deleting|changing) anything\b/i;

/**
 * How strongly a tool's execution is evidenced. `strong`: its NAME says it
 * executes (`exec`, `run_command`, `execute_code`, `spawn_process`), its handler
 * does, or a command-shaped parameter is a free-form string that the tool's own
 * words say is run. `weak`: only a parameter NAME does — a Discord slash
 * `command`, a ShellCheck `shell` dialect, a game `command`, the `script` of a
 * poster font. A contradiction that rests on weak evidence is still reported,
 * at low/heuristic; it is never dropped.
 */
type Strength = 'none' | 'weak' | 'strong';
const stronger = (a: Strength, b: Strength): Strength => (a === 'strong' || b === 'strong' ? 'strong' : a === 'weak' || b === 'weak' ? 'weak' : 'none');

interface MutationEvidence {
  /** Execution evidenced by the tool's name, its handler, or a command/code parameter. */
  exec: Strength;
  /** The parameters behind weak execution evidence, for the finding's text. */
  weakParams: string[];
  /**
   * Weak execution evidence that gave the tool no code-exec tag — `eval_run`
   * read as an evaluation although it takes a free-form `input`. CAP-003 still
   * reports it, low.
   */
  untagged?: string;
  /** A file write evidenced by the name: none, only additive, or destructive. */
  write: 'none' | 'additive' | 'destructive';
}

const EXEC_PARAM_NAMES = new Set(PARAM_NAME_SIGNALS.filter((s) => s.tag === 'code-exec').flatMap((s) => s.names));
/** What an interpreter named `eval` would take: not a `source` to parse, a value to evaluate. */
const EVAL_INPUT_PARAMS = new Set(['input', 'inputs', 'expr', 'expression', 'formula', 'program', 'statement']);
// The last word of a parameter name that makes it an identifier or a setting of
// the command, not the command itself: `command_number`, `script_id`, `shell_dialect`.
const NON_COMMAND_HEADS = new Set(['id', 'ids', 'uuid', 'guid', 'number', 'num', 'no', 'index', 'idx', 'count', 'key', 'keys', 'type', 'types', 'kind', 'status', 'version', 'ref', 'timeout', 'limit', 'level', 'mode', 'format', 'lang', 'language', 'dialect', 'style', 'tier', 'hash', 'size', 'length', 'offset', 'cursor', 'page', 'total', 'enabled']);
// The first word of a parameter name that makes it a switch: `include_command`, `show_script`.
const FLAG_LEADS = new Set(['include', 'with', 'show', 'use', 'enable', 'disable', 'allow', 'has', 'is', 'skip', 'no', 'hide', 'exclude', 'omit']);
// Words of a description sentence that are about what a command parameter carries.
const EXEC_OBJECT_MENTIONS = new Set(['command', 'commands', 'cmd', 'cmds', 'script', 'scripts', 'shell', 'shells', 'code', 'program', 'programs', 'process', 'processes', 'executable', 'binary', 'expression', 'expressions', 'snippet', 'snippets', 'cli']);
// `build_command` on `verify_build`: the tool is named for what the command does.
const COMMAND_ACTIONS = new Set(['build', 'test', 'tests', 'typecheck', 'lint', 'compile', 'install', 'start', 'run', 'launch', 'deploy', 'setup', 'init', 'bootstrap', 'format', 'migrate', 'seed', 'serve']);
// Read verbs: before an execution word in a NAME they make it a noun (`get_run_status`).
const READ_NAME_VERBS = new Set(['get', 'list', 'read', 'show', 'describe', 'fetch', 'poll', 'view', 'inspect', 'query', 'search', 'find']);

/** A name's words, camelCase split too (`runScript` → run, script). */
const nameWords = (name: string): string[] =>
  name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/** An enum, a const, a boolean / number type, or a short restrictive pattern. */
function schemaConstrains(prop: JsonSchema | undefined): boolean {
  if (!prop || typeof prop !== 'object') return false;
  if (Array.isArray(prop.enum) && prop.enum.length > 0) return true;
  if (Object.hasOwn(prop, 'const')) return true;
  const types = Array.isArray(prop.type) ? prop.type : prop.type === undefined ? [] : [prop.type];
  if (types.length > 0 && types.every((t) => t === 'boolean' || t === 'number' || t === 'integer' || t === 'null')) return true;
  return typeof prop.pattern === 'string' && restrictivePattern(prop.pattern);
}

/**
 * Does command-shaped parameter `param` evidence execution strongly? Its value
 * must be a free-form string — no enum, const or restrictive pattern, and not an
 * identifier or a switch by its name — and an execution verb must say it is run:
 * in the tool's name, in the parameter's own description, in a sentence of the
 * tool's description that is about the command, or in the tool's name as the
 * action the command does (`build_command` on `verify_build`). For a statically
 * recovered tool the parameter's description and constraint are read from its
 * registration source.
 */
function paramRunsCommand(tool: ToolDef, param: string, w: ToolWords, surface: ServerSurface): boolean {
  const toks = tokensOf(param);
  if (NON_COMMAND_HEADS.has(toks[toks.length - 1]!) || (toks.length > 1 && FLAG_LEADS.has(toks[0]!))) return false;
  const prop = tool.inputSchema?.properties?.[param];
  let description = schemaParamDescription(tool, param);
  let constrained = schemaConstrains(prop);
  if (!constrained && !description) {
    const facts = staticParamFacts(surface, tool.name, param);
    if (facts) {
      description = facts.description ?? '';
      constrained = facts.constrained;
    }
  }
  if (constrained) return false;

  const name = nameWords(tool.name);
  if (name.some((_, i) => execVerbAt(name, i) && !name.slice(0, i).some((t) => READ_NAME_VERBS.has(t)))) return true;
  if (assertsExecution(description) || w.description.length > MAX_PROSE) return true;
  const mentions = new Set([...toks.filter((t) => t.length >= 3), ...EXEC_OBJECT_MENTIONS]);
  for (const s of proseSentences(w.description)) {
    if (!s.some((_, i) => execVerbAt(s, i))) continue;
    // A start verb already stands next to a process word ("an MCP server starts").
    if (s.some((t) => mentions.has(t)) || s.some((t, i) => (t.startsWith('start') || t.startsWith('launch')) && execVerbAt(s, i))) return true;
  }
  const action = toks.length > 1 ? toks[toks.length - 2]! : '';
  return COMMAND_ACTIONS.has(action) && w.nameSet.has(action);
}

// A name keyword can be lowered to weak only for a tool that reads the result
// of an execution: its name is a status / poll / list-of-a-noun shape, the
// execution word is not followed by what is executed (`exec_shell_info` is), and
// the description leads with reading and asserts no execution ("Return exit
// status + captured stdout/stderr for a previously launched exec"). Never by
// name alone: 1.16 rejected a getter exemption because a hostile `exec_shell_info`
// declared read-only must still be caught.
const STATUS_TAILS = new Set(['status', 'poll', 'result', 'results', 'output', 'outputs', 'log', 'logs', 'history', 'events']);
const EXEC_OBJECT_TOKENS = new Set(['shell', 'command', 'commands', 'cmd', 'code', 'script', 'scripts', 'process', 'bash', 'sh', 'python', 'py', 'js', 'javascript', 'node', 'sql', 'program', 'binary', 'file', 'expression', 'expr']);
const READ_LEADS = new Set(['return', 'returns', 'read', 'reads', 'list', 'lists', 'get', 'gets', 'poll', 'polls', 'fetch', 'fetches', 'retrieve', 'retrieves', 'inspect', 'inspects', 'describe', 'describes', 'show', 'shows', 'report', 'reports']);
const SINGLE_WORD_EXEC_KEYWORDS = new Set(['exec', 'shell', 'subprocess', 'spawn', 'bash', 'eval', 'powershell']);

// Words that join two actions in a name: `fetch_and_exec` fetches AND executes.
const NAME_CONJUNCTIONS = new Set(['and', 'then', 'or', 'plus', 'with']);

function readsAnExecution(kw: string, w: ToolWords, rawName: string): boolean {
  if (!SINGLE_WORD_EXEC_KEYWORDS.has(kw)) return false;
  const at = w.name.indexOf(kw);
  if (at < 0 || EXEC_OBJECT_TOKENS.has(w.name[at + 1] ?? '')) return false;
  const last = w.name[w.name.length - 1]!;
  // The read verb has to come BEFORE the execution word, with no conjunction
  // between them (`get_exec_status`, not `fetch_and_exec` or `exec_and_fetch`) —
  // or the execution word is a namespace and the read verb opens the action
  // under it (`exec.list_capabilities`).
  const before = w.name.slice(0, at);
  const read = before.findIndex((t) => READ_NAME_VERBS.has(t));
  const namespaced = new RegExp(`(?:^|[.:/])${kw}[.:/]`, 'i').test(rawName) && READ_NAME_VERBS.has(w.name[at + 1] ?? '');
  const readsIt = (read >= 0 && !before.slice(read + 1).some((t) => NAME_CONJUNCTIONS.has(t))) || namespaced;
  const shape = (STATUS_TAILS.has(last) && at < w.name.length - 1 && !w.name.some((t) => NAME_CONJUNCTIONS.has(t))) || readsIt;
  if (!shape) return false;
  const lead = proseSentences(w.description)[0]?.[0] ?? '';
  return READ_LEADS.has(lead) && !assertsExecution(w.description);
}

// A guard that keeps a REGISTRY of what may be run: `register_subprocess`,
// `audit_subprocess`. The execution word is the object of a verb that does not
// run it — weak evidence, reported low, never dropped.
const NON_EXECUTING_VERBS = new Set(['register', 'audit', 'validate', 'check', 'describe', 'inspect', 'verify', 'lint', 'review', 'scan', 'allowlist', 'whitelist', 'approve', 'deny', 'block', 'policy']);
// `run_code` named for a code SCANNER (`sf_run_code_scanner`): it runs an analyzer over code.
const ANALYZER_TOKENS = new Set(['scanner', 'scan', 'analyzer', 'analyser', 'analysis', 'analyze', 'analyse', 'lint', 'linter', 'review', 'audit', 'checker']);

function namesExecutionAsObject(kw: string, w: ToolWords): boolean {
  if (kw === 'subprocess' || kw === 'process' || kw === 'shell') {
    const at = w.name.indexOf(kw);
    return at > 0 && NON_EXECUTING_VERBS.has(w.name[0]!) && !w.params.some((p) => tokensOf(p).some((t) => EXEC_PARAM_NAMES.has(t)));
  }
  if (kw === 'run code') {
    const at = w.name.findIndex((t, i) => t === 'run' && w.name[i + 1] === 'code');
    return at >= 0 && ANALYZER_TOKENS.has(w.name[at + 2] ?? '');
  }
  return false;
}

/**
 * Is a tool's state-mutating capability (code-exec / file-write) evidenced
 * *operatively* — by its NAME, its handler or a PARAMETER — rather than only by a
 * keyword that happens to appear in its prose description? A read-only getter
 * like `get_config` whose description merely lists "defaultShell" /
 * "blockedCommands" picks up a `code-exec` tag from the word "shell", but it does
 * not execute anything. Only operative evidence is strong enough to call an
 * annotation a lie (MTC-CAP-003), so a description-only mention must not trip
 * that rule.
 *
 * Name and parameter tokens are homonyms often enough to need their context
 * (`eval_run`, `ue_spawn_actor`, `qtm4j_unlink_test_cycles_from_plan`, the
 * `script` of `dialogue_to_speech`); those rules are shared with tag derivation
 * in `util/capabilities.ts`.
 */
function mutationEvidence(tool: ToolDef, cap: ToolCapability, surface: ServerSurface): MutationEvidence {
  const w = toolWords(tool);
  const description = w.description;
  const nameNorm = w.name.join(' ');
  const ev: MutationEvidence = { exec: 'none', weakParams: [], write: 'none' };
  if (cap.sources?.['code-exec']?.includes('handler')) ev.exec = 'strong';

  // Parameters. Only code-exec names live in PARAM_NAME_SIGNALS for these tags.
  const disclaims = disclaimsExecution(description);
  const handsOn = disclaims && HANDS_ON_COMMAND.test(description.slice(0, MAX_PROSE));
  for (const pn of w.params) {
    const toks = tokensOf(pn);
    if ((disclaims && !handsOn) || !toks.some((t) => EXEC_PARAM_NAMES.has(t) && !execParamIsHomonym(pn, t, tool, w))) continue;
    if (!handsOn && paramRunsCommand(tool, pn, w, surface)) ev.exec = 'strong';
    else {
      ev.exec = stronger(ev.exec, 'weak');
      ev.weakParams.push(pn);
    }
  }

  // No blanket exemption for "getter" names here: a hostile server can name a
  // command runner `exec_shell_info` and declare it read-only; the contradiction
  // is the signal this rule exists for.
  const writeKinds: ('additive' | 'destructive')[] = [];
  for (const sig of CAPABILITY_SIGNALS) {
    if (sig.tag !== 'code-exec' && sig.tag !== 'file-write') continue;
    for (const kw of sig.keywords) {
      const k = normalizeForMatch(kw);
      if (!(k.includes(' ') ? nameNorm.includes(k) : w.nameSet.has(k))) continue;
      if (nameKeywordIsHomonym(k, w)) {
        // `eval_run` that takes a free-form `input` / `expression` to evaluate
        // may well be an interpreter: an evaluation reading lowers it, no more.
        if (k === 'eval' && w.params.some((p) => EVAL_INPUT_PARAMS.has(p.toLowerCase()) && !schemaConstrains(tool.inputSchema?.properties?.[p]))) {
          ev.untagged ??= `the name word "eval" next to a free-form "${w.params.find((p) => EVAL_INPUT_PARAMS.has(p.toLowerCase()))}" parameter`;
        }
        continue;
      }
      if (sig.tag === 'code-exec') ev.exec = stronger(ev.exec, readsAnExecution(k, w, tool.name) || namesExecutionAsObject(k, w) ? 'weak' : 'strong');
      else writeKinds.push(ADDITIVE_WRITE_KEYWORDS.has(k) ? 'additive' : 'destructive');
    }
  }
  if (
    writeKinds.length > 0 &&
    (PLAN_FRAME.test(w.title) || PLAN_FRAME.test(description)) &&
    NO_MUTATION.test(description) &&
    !CARRIES_OUT.test(description.slice(0, MAX_PROSE))
  ) {
    writeKinds.length = 0;
  }
  if (writeKinds.includes('destructive') || (writeKinds.length > 0 && (hasAny(w.nameSet, DESTRUCTIVE_TOKENS) || hasAny(w.paramTokens, DESTRUCTIVE_TOKENS)))) {
    ev.write = 'destructive';
  } else if (writeKinds.length > 0) {
    ev.write = 'additive';
  }
  return ev;
}

/** True if a string-typed property has no enum/pattern constraint. */
function isUnconstrainedString(prop: JsonSchema | undefined): boolean {
  if (!prop || typeof prop !== 'object') return true;
  const t = prop.type;
  const stringy = t === undefined || t === 'string' || (Array.isArray(t) && t.includes('string'));
  if (!stringy) return false;
  return !prop.enum && !prop.pattern;
}

/**
 * A URL / host string whose only constraint is a pattern that does not bound the
 * whole value: JSON Schema patterns search, so `^https?://` still admits any
 * host after it — the destination stays the model's choice (see
 * `boundsWholeValue`).
 */
function prefixOnlyPattern(prop: JsonSchema | undefined): boolean {
  if (!prop || typeof prop !== 'object' || prop.enum || prop.const !== undefined) return false;
  const t = prop.type;
  const stringy = t === undefined || t === 'string' || (Array.isArray(t) && t.includes('string'));
  return stringy && typeof prop.pattern === 'string' && !boundsWholeValue(prop.pattern);
}

/** A property the extractor recovered by name only: `{}`. */
function isEmptySchema(prop: JsonSchema | undefined): boolean {
  return !prop || (typeof prop === 'object' && Object.keys(prop).length === 0);
}

function nameMatches(paramName: string, list: string[]): boolean {
  const tokens = paramName.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean);
  return list.some((n) => tokens.includes(n));
}

export const capabilityDetector: Detector = {
  id: 'capability',
  stage: 3,
  title: 'Capability & annotation analysis',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    for (const tool of ctx.surface.tools) {
      if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string') continue;
      const cap = capFor(ctx.capabilities, tool.name);
      if (!cap) continue;
      const tags = cap.tags;
      const reasons = cap.reasons;
      const has = (t: CapabilityTag): boolean => tags.includes(t);

      if (has('code-exec')) {
        findings.push({
          ruleId: 'MTC-CAP-001',
          title: `Tool "${tool.name}" exposes command/code execution`,
          category: 'permissions',
          severity: 'high',
          confidence: 'strong',
          description:
            `Tool "${tool.name}" appears to run shell commands or evaluate code ` +
            `(${(reasons['code-exec'] ?? []).join(', ')}). Arbitrary execution driven by model input is one of ` +
            `the most dangerous MCP capabilities; combined with any untrusted input it becomes RCE.`,
          remediation: 'Sandbox execution, allowlist commands/arguments, and never pass model output to a shell unescaped.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM05:2025 Improper Output Handling',
          data: { tags },
        });
      }

      if (has('file-write')) {
        findings.push({
          ruleId: 'MTC-CAP-002',
          title: `Tool "${tool.name}" can modify the filesystem`,
          category: 'permissions',
          severity: 'medium',
          confidence: 'strong',
          description:
            `Tool "${tool.name}" can write, overwrite or delete files ` +
            `(${(reasons['file-write'] ?? []).join(', ')}). Verify it is scoped to a safe directory.`,
          remediation: 'Constrain file operations to an explicit, non-sensitive root; reject path traversal.',
          location: { kind: 'tool', name: tool.name },
          data: { tags },
        });
      }

      // Annotation-vs-behavior mismatch. Only a tool that genuinely MODIFIES
      // state (file-write / code-exec) contradicts readOnly/non-destructive — a
      // tool that merely makes an outbound request (e.g. fetch/scrape) can be
      // legitimately read-only, so external-sink alone is NOT a contradiction.
      const claimsReadOnly = tool.annotations?.readOnlyHint === true;
      const claimsNonDestructive = tool.annotations?.destructiveHint === false;
      // Require OPERATIVE evidence (name/param), not a description-only keyword,
      // before calling the annotation a lie — else a read-only getter that merely
      // describes shell/exec config (get_config, get_prompts) is a false positive.
      // readOnlyHint=true is contradicted by any write or execution. By the MCP
      // spec destructiveHint=false means "only additive updates", so it is
      // contradicted only by execution or a DESTRUCTIVE write — `create_file` /
      // `save_file` / `append_file` declaring it are telling the truth.
      // Execution evidenced only weakly (a command-shaped parameter nothing says
      // is run, a status read of an earlier exec) is reported at low/heuristic.
      const ev = claimsReadOnly || claimsNonDestructive ? mutationEvidence(tool, cap, ctx.surface) : undefined;
      const execs = !ev ? 'none' : has('code-exec') ? ev.exec : ev.untagged ? 'weak' : 'none';
      const writes = has('file-write') && ev !== undefined && ev.write !== 'none';
      const destroys = has('file-write') && ev?.write === 'destructive';
      const strong = claimsReadOnly ? execs === 'strong' || writes : claimsNonDestructive && (execs === 'strong' || destroys);
      if (strong || execs === 'weak') {
        const hint = claimsReadOnly ? 'readOnlyHint=true' : 'destructiveHint=false';
        const weakWhy = ev!.weakParams.length
          ? `a command-shaped parameter (${ev!.weakParams.map((p) => `"${p}"`).join(', ')}) that nothing in the tool's name or text says is run`
          : !has('code-exec') && ev!.untagged
            ? ev!.untagged
            : 'a name that reads the result of an execution, or names an execution it does not run';
        findings.push({
          ruleId: 'MTC-CAP-003',
          title: `Annotation contradicts behavior on "${tool.name}"`,
          category: 'permissions',
          severity: strong ? 'medium' : 'low',
          confidence: strong ? 'strong' : 'heuristic',
          description: strong
            ? `Tool "${tool.name}" advertises ${hint} but its ` +
              `derived capabilities include state-modifying actions (${tags.join(', ')}). Tool annotations are ` +
              `attacker-controllable and must never be trusted; a mismatch like this is exactly how a hostile server ` +
              `hides a destructive tool.`
            : `Tool "${tool.name}" advertises ${hint}, and its only execution evidence is ${weakWhy}. That may be a ` +
              `name, a setting or text rather than something executed; if the tool does run it, the annotation is false. ` +
              `Tool annotations are attacker-controllable and must never be trusted.`,
          remediation: 'Ignore server-provided annotations for security decisions; gate destructive tools on explicit user consent.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM06:2025 Excessive Agency',
          data: { tags, annotations: tool.annotations, ...(strong ? {} : { evidence: ev!.weakParams.length ? 'parameter' : 'name' }) },
        });
      }

      // open-world hint + sensitive read = a lethal-trifecta signal from annotations.
      if (tool.annotations?.openWorldHint === true && has('sensitive-source')) {
        findings.push({
          ruleId: 'MTC-CAP-004',
          title: `Open-world tool "${tool.name}" also reads sensitive data`,
          category: 'exfiltration',
          severity: 'medium',
          confidence: 'heuristic',
          description:
            `Tool "${tool.name}" declares openWorldHint=true — it interacts with entities outside the trust boundary — ` +
            `while also reading sensitive data. That combination is a canonical lethal-trifecta indicator.`,
          remediation: 'Separate outward-facing tools from sensitive-data reads; require confirmation between them.',
          location: { kind: 'tool', name: tool.name },
          owasp: 'LLM02:2025 Sensitive Information Disclosure',
          data: { tags },
        });
      }

      // Missing destructiveHint on a genuinely destructive tool (write/exec only,
      // to avoid flagging the very common annotation-less "send" tool).
      const noDestructiveHint = !tool.annotations || tool.annotations.destructiveHint === undefined;
      const genuinelyDestructive = has('file-write') || has('code-exec');
      if (genuinelyDestructive && noDestructiveHint) {
        findings.push({
          ruleId: 'MTC-CAP-005',
          title: `Mutating tool "${tool.name}" declares no destructiveHint`,
          category: 'hygiene',
          severity: 'low',
          confidence: 'heuristic',
          description:
            `Tool "${tool.name}" can mutate/egress but declares no destructiveHint. Clients that don't default to ` +
            `spec-safe behavior may not prompt before running it.`,
          remediation: 'Declare accurate annotations, and gate destructive tools on user confirmation regardless.',
          location: { kind: 'tool', name: tool.name },
          data: { tags },
        });
      }

      // Schema-level injection preconditions (only on the relevant capability).
      const props = tool.inputSchema?.properties ?? {};
      for (const [pname, pschema] of Object.entries(props)) {
        const destination = nameMatches(pname, SSRF_PARAM_NAMES);
        if (!isUnconstrainedString(pschema) && !(destination && prefixOnlyPattern(pschema))) continue;
        // A statically recovered tool's schema keeps only parameter NAMES; its
        // registration source says whether the value is an enum, a literal or a
        // number (`command: { type: 'string', enum: ['status', 'restart'] }`).
        // A destination pinned only by a prefix (`url: z.string().regex(/^https?:\/\//)`)
        // is still the model's choice.
        if (isEmptySchema(pschema)) {
          const facts = staticParamFacts(ctx.surface, tool.name, pname);
          if (facts?.constrained && !(destination && facts.pattern !== undefined && !boundsWholeValue(facts.pattern))) continue;
        }
        const field = `inputSchema.properties.${pname}`;
        if (has('code-exec') && nameMatches(pname, COMMAND_PARAM_NAMES)) {
          findings.push({
            ruleId: 'MTC-CAP-006',
            title: `Unconstrained command parameter "${pname}" on "${tool.name}"`,
            category: 'permissions',
            severity: 'medium',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" takes a command-shaped parameter "${pname}" with no enum/pattern constraint. ` +
              `Free-form, model- or attacker-controlled arguments reaching a shell is the command-injection precondition.`,
            remediation: 'Constrain the parameter (enum/pattern), or build the command from a fixed template with escaped args.',
            location: { kind: 'tool', name: tool.name, field },
            owasp: 'LLM05:2025 Improper Output Handling',
            data: { param: pname },
          });
        } else if ((has('external-sink') || has('untrusted-input')) && nameMatches(pname, SSRF_PARAM_NAMES)) {
          findings.push({
            ruleId: 'MTC-CAP-007',
            title: `Unconstrained URL/host parameter "${pname}" on "${tool.name}"`,
            category: 'network',
            severity: 'medium',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" takes a URL/host parameter "${pname}" with no allowlist/pattern. An outbound-request ` +
              `tool with an unbounded destination enables SSRF and cloud-metadata access (e.g. 169.254.169.254).`,
            remediation: 'Allowlist destinations or constrain the parameter; block private/link-local addresses server-side.',
            location: { kind: 'tool', name: tool.name, field },
            owasp: 'LLM06:2025 Excessive Agency',
            data: { param: pname },
          });
        } else if ((has('file-write') || has('sensitive-source')) && nameMatches(pname, PATH_PARAM_NAMES)) {
          findings.push({
            ruleId: 'MTC-CAP-008',
            title: `Unconstrained path parameter "${pname}" on "${tool.name}"`,
            category: 'permissions',
            severity: 'low',
            confidence: 'heuristic',
            description:
              `Tool "${tool.name}" takes a path parameter "${pname}" with no constraint. Without a canonicalize-and-` +
              `contain check (not visible statically), this permits ../ traversal outside the intended root.`,
            remediation: 'Resolve and verify the path stays within an allowed root; reject traversal sequences.',
            location: { kind: 'tool', name: tool.name, field },
            data: { param: pname },
          });
        }
      }
    }

    // --- Server-capability pass (declared capabilities are facts, not guesses) ---
    const rawCaps = ctx.surface.server.capabilities;
    const caps = rawCaps && typeof rawCaps === 'object' ? rawCaps : {};
    if ('sampling' in caps) {
      findings.push({
        ruleId: 'MTC-CAP-009',
        title: 'Server declares the sampling capability',
        category: 'permissions',
        severity: 'medium',
        confidence: 'strong',
        description:
          'This server declares the MCP `sampling` capability, letting it drive the client\'s own LLM with ' +
          'server-authored prompts. That reverse-trust channel enables token/resource drain, conversation hijack, ' +
          'and covert tool invocation. Most benign servers do not need sampling.',
        remediation: 'Only grant sampling to servers you fully trust; review what the server does with completions.',
        location: { kind: 'server', field: 'capabilities.sampling' },
        owasp: 'LLM06:2025 Excessive Agency',
      });
    }
    if ('elicitation' in caps) {
      // Plain declared elicitation is a CAPABILITY (MTC-CAP-010, not scored). Only
      // when it also solicits a secret is it a trust THREAT (MTC-CAP-011, scored).
      const secretField = findSecretSeekingField(ctx);
      findings.push({
        ruleId: secretField ? 'MTC-CAP-011' : 'MTC-CAP-010',
        title: 'Server declares the elicitation capability' + (secretField ? ' and solicits secrets' : ''),
        category: secretField ? 'exfiltration' : 'permissions',
        severity: secretField ? 'high' : 'medium',
        confidence: 'strong',
        description:
          'This server declares the MCP `elicitation` capability (it can pop mid-session input requests). This ' +
          'enables consent-fatigue conditioning and phishing.' +
          (secretField
            ? ` It also exposes a secret-seeking field ("${secretField}") — the spec forbids collecting secrets via elicitation.`
            : ''),
        remediation: 'Treat elicitation prompts as untrusted UI; never enter credentials into an elicitation request.',
        location: { kind: 'server', field: 'capabilities.elicitation' },
        owasp: 'LLM02:2025 Sensitive Information Disclosure',
        ...(secretField ? { evidence: secretField } : {}),
      });
    }

    return findings;
  },
};

/** Find the first param/prompt-arg name that solicits a secret, if any. */
function findSecretSeekingField(ctx: DetectorContext): string | undefined {
  const check = (name: string): boolean =>
    name.toLowerCase().split(/[^a-z0-9]+/i).some((tok) => SECRET_FIELD_NAMES.includes(tok));
  for (const tool of ctx.surface.tools) {
    if (!tool || typeof tool !== 'object') continue;
    for (const p of Object.keys(tool.inputSchema?.properties ?? {})) if (check(p)) return p;
  }
  for (const prompt of ctx.surface.prompts) {
    const args = Array.isArray(prompt?.arguments) ? prompt.arguments : [];
    for (const a of args) if (a && typeof a === 'object' && typeof a.name === 'string' && check(a.name)) return a.name;
  }
  return undefined;
}
