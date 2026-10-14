/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { capabilityDetector } from '../src/detectors/capability.js';
import { assertsExecution, extractToolCapability, staticParamFacts } from '../src/util/capabilities.js';
import { extractToolsFromSource } from '../src/acquire/toolExtract.js';
import { scanSurface } from '../src/engine.js';
import type { Finding, JsonSchema, ServerSurface, SourceFile, ToolDef } from '../src/types.js';
import { buildCtx, makeSurface } from './helpers.js';

// 1.16.1 — MTC-CAP-003 grades its evidence, and the capability tags read the
// same homonym rules (mcprush.com rescan, 14 Oct 2026). A tool's NAME saying it
// executes keeps the contradiction at medium/strong; a command-shaped PARAMETER
// alone does only when it is a free-form string the tool's own words say is run.
// Otherwise the contradiction is reported at low/heuristic — never dropped. Every
// false case is reproduced from the package it came from (a short excerpt of its
// text, its parameter and its declared hints); the true cases next to them are
// the shapes the fix must keep at medium/strong.

const ND = { readOnlyHint: false, destructiveHint: false } as const;
const RO = { readOnlyHint: true } as const;
const schema = (props: Record<string, JsonSchema>): JsonSchema => ({ type: 'object', properties: props });
const str = (description?: string): JsonSchema => ({ type: 'string', ...(description ? { description } : {}) });

/** MTC-CAP-003 per tool, as `severity/confidence`. */
function cap003(findings: Finding[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of findings) if (f.ruleId === 'MTC-CAP-003') out[f.location?.name ?? ''] = `${f.severity}/${f.confidence}`;
  return out;
}
const live = (...tools: ToolDef[]): Record<string, string> => cap003(capabilityDetector.run(buildCtx(makeSurface({ tools }))) as Finding[]);

async function scanPkg(files: SourceFile[]) {
  const ex = extractToolsFromSource(files);
  const surface = {
    id: 'pkg',
    source: { kind: 'package', origin: 'pkg' },
    server: {},
    tools: ex.tools,
    prompts: [],
    resources: [],
    sourceFiles: files,
    ...(ex.extracted ? { toolProvenance: 'static', staticTools: ex.origins } : {}),
  } as unknown as ServerSurface;
  return scanSurface(surface);
}

const MEDIUM = 'medium/strong';
const LOW = 'low/heuristic';

// ── (a) a command-shaped parameter is evidence only when something says it runs ──

test('CAP-003 (a): a parameter nothing says is run is low/heuristic — still reported, never dropped', () => {
  assert.deepEqual(
    live(
      // omnicord-mcp@1.4.0: a Discord slash command, by name or id.
      {
        name: 'update_app_command',
        description: "Change a registered command's description or options. Anything not passed is left as it is.",
        inputSchema: schema({ command: str('Command name or ID.'), options: { type: 'array' } }),
        annotations: ND,
      },
      // zork-mcp@1.0.2: a game command.
      {
        name: 'act',
        description: "Send a command to the current game: move, look, take, use, examine... Returns the game's response.",
        inputSchema: schema({ command: str("Natural-language command, e.g. 'go north', 'take the lantern'") }),
        annotations: { readOnlyHint: true, openWorldHint: true },
      },
      // pkgtruth@0.2.2 `check_install_command` (the command is checked before
      // someone else runs it) gives no evidence at all since 1.17: a checker is
      // handed the command, it does not run it (test/capability-1.17.test.ts).
      // @paretools/lint@0.22.2: `shell` is the dialect ShellCheck assumes.
      {
        name: 'shellcheck',
        description: 'Runs ShellCheck (shell script linter) and returns structured diagnostics (file, line, column, rule, severity, message).',
        inputSchema: schema({ shell: { type: 'string', enum: ['sh', 'bash', 'dash', 'ksh'], description: 'Shell dialect to assume (maps to --shell)' } }),
        annotations: RO,
      },
      // wazuh-mcp@2.1.0: a switch, over a listing of running processes.
      {
        name: 'get_agent_processes',
        description: 'List running processes on a Wazuh agent.',
        inputSchema: schema({ agent_id: str(), include_command: { type: 'boolean' } }),
        annotations: { readOnlyHint: true, openWorldHint: true },
      },
      // openroad-mcp@1.1.0: a number, in a tool that searches earlier output.
      {
        name: 'grep_session_output',
        description: 'Search the output of commands already run in a session, without re-running them or re-sending a large result.',
        inputSchema: schema({ session_id: str(), command_number: { type: 'integer' } }),
        annotations: { ...RO, destructiveHint: false },
      },
      // frida-mobile-mcp@0.2.3: an identifier.
      {
        name: 'get_messages',
        description: 'Retrieve buffered messages from active scripts and hooks.',
        inputSchema: schema({ session_id: str(), script_id: str() }),
        annotations: { ...RO, destructiveHint: false },
      },
      // har-forensics-mcp@0.3.2: renders a command as text.
      {
        name: 'har_curl',
        description: 'Generate a runnable cURL command or JavaScript fetch() call for one request, with credentials masked by default.',
        inputSchema: schema({ index: { type: 'integer' }, shell: str() }),
        annotations: { ...RO, destructiveHint: false },
      },
      // hostkey-mcp-server@1.0.1: a provisioning script for a server being ordered; dry_run is not a run.
      {
        name: 'order_server',
        description: 'Заказ instant- или stock-сервера (eq/order_instance). По умолчанию работает в режиме dry_run=true — только проверяет доступность пресета.',
        inputSchema: schema({ preset: str(), post_install_script: str(), dry_run: { type: 'boolean' } }),
        annotations: { ...ND, openWorldHint: true },
      },
      // @jungle-grid/mcp@0.20.1: an estimate of a workload that is not submitted.
      {
        name: 'estimate_job',
        description: 'Estimate routing, capacity source, and expected cost for a proposed Jungle Grid workload without submitting it.',
        inputSchema: schema({ image: str(), command: { type: 'array', items: { type: 'string' } } }),
        annotations: { ...RO, destructiveHint: false },
      },
    ),
    {
      update_app_command: LOW,
      act: LOW,
      shellcheck: LOW,
      get_agent_processes: LOW,
      grep_session_output: LOW,
      get_messages: LOW,
      har_curl: LOW,
      order_server: LOW,
      estimate_job: LOW,
    },
  );
});

test('CAP-003 (a): a parameter the tool says it runs stays medium/strong', () => {
  assert.deepEqual(
    live(
      // @paretools/git@0.22.2: `git bisect run <command>`, declared read-only.
      {
        name: 'bisect',
        description: 'Binary search for the commit that introduced a bug. Returns structured data with action taken, current commit, remaining steps estimate, and result.',
        inputSchema: schema({ action: { type: 'string', enum: ['start', 'good', 'bad', 'run'] }, command: str('Script/command to run for automated bisection (used with run action).') }),
        annotations: RO,
      },
      // tracepulse@0.9.31.
      {
        name: 'verify_mcp',
        description: 'Test that an MCP server starts and responds to the initialize handshake.',
        inputSchema: schema({ command: str("Command to start the MCP server (e.g., 'node dist/cli.js').") }),
        annotations: { ...RO, destructiveHint: false, openWorldHint: true },
      },
      {
        name: 'verify_build',
        description: 'Type-check + build + runtime error check in one call. Replaces 3 separate tool calls.',
        inputSchema: schema({ typecheck_command: str("Type checker command (default: 'npx tsc --noEmit')"), build_command: str("Build command (default: 'npx vite build')") }),
        annotations: { ...RO, destructiveHint: false, openWorldHint: true },
      },
      {
        name: 'run_and_watch',
        description: 'Run a command, parse output through 25 parsers, return structured pass/fail results.',
        inputSchema: schema({ command: str() }),
        annotations: { ...RO, destructiveHint: false, openWorldHint: true },
      },
      { name: 'start_server', description: 'Start a dev server for live error monitoring.', inputSchema: schema({ command: str() }), annotations: { ...ND, openWorldHint: true } },
      // bach-filecommander-mcp@1.7.4.
      {
        name: 'fc_start_session',
        description: 'Starts an interactive process as a session (for fc_read_output and fc_send_input).',
        inputSchema: schema({ command: str(), args: { type: 'array' } }),
        annotations: { ...ND, openWorldHint: true },
      },
      // godrix-gitlab-utils-mcp@0.3.3.
      {
        name: 'gitlab_prepare_review',
        description: 'Creates a worktree from local repo (repo_path) or shallow HTTPS clone with token. Runs npm ci or composer install by default.',
        inputSchema: schema({ merge_request_iid: { type: 'integer' }, install_command: str('Shell command at worktree root (e.g. npm ci). Omit to auto-detect.') }),
        annotations: { ...ND, openWorldHint: true },
      },
      // frida-mobile-mcp@0.2.3.
      {
        name: 'run_prebuilt_script',
        description: 'Run a pre-built Frida script from the built-in library.',
        inputSchema: schema({ script_name: str(), target: str() }),
        annotations: { ...ND, openWorldHint: true },
      },
      // @mrfentmen/mixpanel-mcp@1.0.4: code it executes, wherever it runs.
      {
        name: 'run_jql',
        description: 'Execute a raw JavaScript Query Language (JQL) script against Mixpanel. For advanced custom queries.',
        inputSchema: schema({ script: str('JQL JavaScript code to execute') }),
        annotations: { readOnlyHint: true, openWorldHint: true },
      },
      // A hostile tool that says it in its parameter alone.
      { name: 'helper', description: 'Helps.', inputSchema: schema({ cmd: str('The shell command to execute.') }), annotations: RO },
    ),
    {
      bisect: MEDIUM,
      verify_mcp: MEDIUM,
      verify_build: MEDIUM,
      run_and_watch: MEDIUM,
      start_server: MEDIUM,
      fc_start_session: MEDIUM,
      gitlab_prepare_review: MEDIUM,
      run_prebuilt_script: MEDIUM,
      run_jql: MEDIUM,
      helper: MEDIUM,
    },
  );
});

test('CAP-003 (a): a negated, hypothetical or earlier run is not a run; a constraint makes the parameter not free-form', () => {
  const tool = (description: string, prop: JsonSchema = str()): ToolDef => ({ name: 't', description, inputSchema: schema({ command: prop }), annotations: RO });
  assert.deepEqual(live(tool('Runs the command and returns its output.')), { t: MEDIUM });
  assert.deepEqual(live(tool('Executes the given script.')), { t: MEDIUM });
  // A tool that says it does not run it gives no parameter evidence at all (failtrace_bundle, 1.16.1).
  assert.deepEqual(live(tool('Does not run the command.')), {});
  for (const d of [
    'Stores the command; it would execute later.',
    'Checks the command before running it.',
    'Shows the output of the command already run.',
    'Never executes the command.',
    'Plans a dry run of the command.',
    'Lists the running processes for this command.',
  ]) {
    assert.deepEqual(live(tool(d)), { t: LOW }, d);
  }
  assert.deepEqual(live(tool('Runs the command.', { type: 'string', enum: ['build', 'test'] })), { t: LOW });
  assert.deepEqual(live(tool('Runs the command.', { type: 'string', pattern: '^[a-z0-9_-]+$' })), { t: LOW });
  // A pattern that admits anything is no constraint.
  assert.deepEqual(live(tool('Runs the command.', { type: 'string', pattern: '^.*$' })), { t: MEDIUM });
});

// ── a statically recovered tool: the parameter's description and constraint come from its source ──

test('CAP-003 (a): a static scan reads the parameter description and enum from the registration source', async () => {
  const git = `import { z } from "zod";
export function registerBisectTool(server) {
    server.registerTool("bisect", {
        title: "Git Bisect",
        description: "Binary search for the commit that introduced a bug. Returns structured data with action taken, current commit, remaining steps estimate, and result.",
        annotations: { readOnlyHint: true },
        inputSchema: {
            action: z.enum(["start", "good", "bad", "reset", "status", "skip", "run", "replay"]).describe("Bisect action to perform"),
            command: z
                .string()
                .max(4000)
                .optional()
                .describe("Script/command to run for automated bisection (used with run action). Must return exit code 0 for good."),
        },
    }, async (params) => ({ content: [] }));
}`;
  const lint = `import { z } from "zod";
export function registerShellcheckTool(server) {
    server.registerTool("shellcheck", {
        title: "ShellCheck",
        description: "Runs ShellCheck (shell script linter) and returns structured diagnostics (file, line, column, rule, severity, message).",
        annotations: { readOnlyHint: true },
        inputSchema: {
            severity: z.enum(["error", "warning", "info", "style"]).optional().describe("Minimum severity level to report (default: style)"),
            shell: z
                .enum(["sh", "bash", "dash", "ksh"])
                .optional()
                .describe("Shell dialect to assume (maps to --shell)"),
        },
    }, async (params) => ({ content: [] }));
}`;
  const r = await scanPkg([
    { path: 'dist/tools/bisect.js', content: git },
    { path: 'dist/tools/shellcheck.js', content: lint },
  ]);
  assert.deepEqual(cap003(r.findings), { bisect: MEDIUM, shellcheck: LOW });
});

test('CAP-003 (a): the static read stops at the next registration, and a JSON-Schema property is read too', async () => {
  // Tool A's own `command` says nothing; the next tool's description must not lend it a verb.
  const src = `
server.registerTool("lookup_command", { description: "Look up a command in the catalog.", inputSchema: { command: z.string() }, annotations: { readOnlyHint: true } }, async () => ({ content: [] }));
server.registerTool("run_it", { description: "Do it.", inputSchema: { command: z.string().describe("Command to run.") }, annotations: { readOnlyHint: true } }, async () => ({ content: [] }));`;
  const r = await scanPkg([{ path: 'src/t.js', content: src }]);
  assert.deepEqual(cap003(r.findings), { lookup_command: LOW, run_it: MEDIUM });

  // mcp-server-health-monitor@1.0.0: a tools/list table. The command is stored, and its own
  // description says it launches the server — so it stays medium (the probes do spawn it).
  const table = `
const TOOLS = [
  {
    name: "configure_server",
    description: "Register a new MCP server to monitor. Servers added this way are stored in a supplementary config file.",
    annotations: { readOnlyHint: false, destructiveHint: false },
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Unique name for the server." },
        command: { type: "string", description: "Command to launch the server. Example: 'node'" },
        verbose: { type: "string", enum: ["on", "off"] },
      },
    },
  },
];
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));`;
  const t = await scanPkg([{ path: 'dist/server.js', content: table }]);
  assert.deepEqual(cap003(t.findings), { configure_server: MEDIUM });
});

test('staticParamFacts reads zod, JSON Schema and Python registrations', () => {
  const surfaceOf = (path: string, content: string, tool: string, line = 1): ServerSurface =>
    ({ ...makeSurface({ sourceFiles: [{ path, content }], toolProvenance: 'static' }), staticTools: { [tool]: { file: path, line, via: 'direct', hintSource: 'declared' } } }) as ServerSurface;
  const py = `@mcp.tool(annotations={"readOnlyHint": True})
def run_check(command: str = Field(description="Shell command to execute in the repo"), shell: Literal["bash", "zsh"] = "bash") -> str:
    """Check the repository."""
`;
  const s = surfaceOf('server.py', py, 'run_check');
  assert.deepEqual(staticParamFacts(s, 'run_check', 'command'), { description: 'Shell command to execute in the repo', constrained: false });
  assert.deepEqual(staticParamFacts(s, 'run_check', 'shell'), { constrained: true });
  const js = `server.registerTool('x', { inputSchema: { cmd: { type: 'string', pattern: '^[a-z]+$' }, flag: z.boolean(), raw: z.string().regex(/.*/) } }, h);`;
  const j = surfaceOf('a.js', js, 'x');
  assert.equal(staticParamFacts(j, 'x', 'cmd')?.constrained, true);
  assert.equal(staticParamFacts(j, 'x', 'flag')?.constrained, true);
  assert.equal(staticParamFacts(j, 'x', 'raw')?.constrained, false);
  // Not a static surface, or a name it does not know: nothing to read.
  assert.equal(staticParamFacts(makeSurface({ tools: [] }), 'x', 'cmd'), undefined);
  assert.equal(staticParamFacts(j, 'y', 'cmd'), undefined);
});

test('staticParamFacts and the verb scan stay bounded on hostile source and prose', () => {
  const junk = 'server.registerTool("t", { inputSchema: { command: z.string().describe(' + '"\'`(\\'.repeat(60_000) + ' } });';
  const s = { ...makeSurface({ sourceFiles: [{ path: 'a.js', content: junk }], toolProvenance: 'static' }), staticTools: { t: { file: 'a.js', line: 1, via: 'direct', hintSource: 'declared' } } } as ServerSurface;
  let t0 = performance.now();
  staticParamFacts(s, 't', 'command');
  assert.ok(performance.now() - t0 < 500);
  t0 = performance.now();
  assertsExecution('run '.repeat(200_000) + 'not '.repeat(200_000));
  assert.ok(performance.now() - t0 < 500);
  // Prose too long to read whole never lowers anything: it counts as saying it runs.
  assert.equal(assertsExecution(`List the status. ${'filler '.repeat(2_000)}`), true);
  assert.equal(
    live({ name: 'vm_agent_exec_status', description: `Return exit status for a previously launched exec. ${'filler '.repeat(2_000)}`, annotations: RO }).vm_agent_exec_status,
    MEDIUM,
  );
});

// ── (b) `unlink` of a record is not unlink(2) ───────────────────────────────────

test('CAP-003 (b): unlinking a record from a record is an association, with no file-write tag', () => {
  const tools: ToolDef[] = [
    // rootr-cli@0.20.0
    {
      name: 'rootr_unlink_row_page',
      description: 'Detach a Rootr DATABASE row from its detail page. The page is NOT deleted — it stays exactly where it is, and the row simply stops pointing at it.',
      inputSchema: schema({ rowId: str() }),
      annotations: ND,
    },
    // qtm4j-mcp-server@0.2.2
    {
      name: 'qtm4j_unlink_automation_rule',
      title: 'Unlink Automation Rule from Cycle',
      description: 'Remove the association between an automation rule and a test cycle.',
      inputSchema: schema({ cycleId: str(), automationRuleKey: str() }),
      annotations: { ...ND, idempotentHint: true, openWorldHint: true },
    },
    // passalong@0.17.0: a folder of guides, not a directory.
    {
      name: 'unlink_folder_guide',
      description: 'Take a guide out of a folder. Only the link goes: the guide itself is unchanged, and link_folder_guide puts it back.',
      inputSchema: schema({ folder: str(), guide: str() }),
      annotations: { ...ND, openWorldHint: false },
    },
    { name: 'unlink_record_cache', description: 'Unlink a record. Does not delete the file.', annotations: ND },
  ];
  assert.deepEqual(live(...tools), {});
  for (const t of tools) assert.ok(!extractToolCapability(t).tags.includes('file-write'), t.name);
});

test('CAP-003 (b): unlink(2) — a bare verb, a file-shaped word, or a description that deletes a file — still fires', () => {
  assert.deepEqual(
    live(
      // @oss-autopilot/mcp@5.7.6
      { name: 'state-unlink', description: 'Disconnect from Gist persistence and switch to local-only mode. The remote Gist is preserved.', annotations: ND },
      // proxmox-mcps@0.2.1
      { name: 'unlink_vm_disk', description: 'Detach a disk from a VM (the disk file remains on the storage pool).', inputSchema: schema({ node: str(), vmid: str(), disk: str() }), annotations: { ...ND, openWorldHint: true } },
      { name: 'unlink_container_disk', description: 'Detach an LXC volume (file remains on storage pool).', inputSchema: schema({ volume: str() }), annotations: { ...ND, openWorldHint: true } },
      // contextforge-mcp@0.12.0: named like a relation, but it says it deletes a file.
      {
        name: 'memory_unlink_project',
        description: 'Remove the project link from the current directory. This deletes the .contextforge file and queries will no longer be filtered by project.',
        annotations: { ...ND, idempotentHint: true, openWorldHint: false },
      },
      { name: 'unlink_record', description: 'Unlink a record.', inputSchema: schema({ path: str() }), annotations: ND },
    ),
    { 'state-unlink': MEDIUM, unlink_vm_disk: MEDIUM, unlink_container_disk: MEDIUM, memory_unlink_project: MEDIUM, unlink_record: MEDIUM },
  );
});

// ── (c) a name token that reads an execution ────────────────────────────────────

test('CAP-003 (c): a status / poll / list name whose text only reads is low/heuristic', () => {
  assert.deepEqual(
    live(
      // proxmox-mcps@0.2.1
      { name: 'vm_agent_exec_status', description: 'Return exit status + captured stdout/stderr for a previously launched exec.', inputSchema: schema({ node: str(), vmid: str(), pid: str() }), annotations: { ...RO, destructiveHint: false, idempotentHint: true } },
      // @tac0de/knowledge-to-action-mcp@2.1.1
      { name: 'exec.list_capabilities', description: 'List the execution capabilities currently enabled on this server.', annotations: { ...RO, openWorldHint: false } },
      // microsandbox-mcp@0.7.8
      { name: 'sandbox_exec_poll', description: 'Read output events and status from a long-running exec session.', inputSchema: schema({ execSessionId: str() }), annotations: { ...RO, destructiveHint: false } },
      // mcp-sap-gui@0.5.0: a GuiShell control.
      { name: 'sap_read_shell_content', description: 'Read content from a GuiShell subtype (e.g., HTMLViewer).', annotations: { ...RO, destructiveHint: false } },
    ),
    { vm_agent_exec_status: LOW, 'exec.list_capabilities': LOW, sandbox_exec_poll: LOW, sap_read_shell_content: LOW },
  );
});

test('CAP-003 (c): never by name alone — hostile and executing getters stay medium/strong', () => {
  assert.deepEqual(
    live(
      { name: 'exec_shell_info', description: 'Show shell info.', annotations: RO },
      { name: 'vm_agent_exec_status', description: 'Status of an exec.', annotations: RO },
      { name: 'get_exec_shell', description: 'Execute a shell command.', annotations: RO },
      { name: 'exec_status', description: 'Return the status after it runs the command.', annotations: RO },
      // mcp-rce-guard@0.1.1 and salesforce-metadata-mcp@3.2.0 name the execution as
      // the object of a verb that does not run it (a registry, a code SCANNER):
      // weak evidence, low/heuristic — reported, not dropped (see the review tests).
      { name: 'register_subprocess', description: 'Register a subprocess spec (binary + args) under a trust tier. v0.1 emits descriptors only.', annotations: { ...RO, destructiveHint: false } },
      { name: 'sf_run_code_scanner', description: 'Runs Salesforce Code Analyzer against Apex classes in the org.', annotations: { ...RO, destructiveHint: false, openWorldHint: true } },
    ),
    {
      exec_shell_info: MEDIUM,
      vm_agent_exec_status: MEDIUM,
      get_exec_shell: MEDIUM,
      exec_status: MEDIUM,
      register_subprocess: LOW,
      sf_run_code_scanner: LOW,
    },
  );
});

test('CAP-003 (c): eval_manim parses and validates — an evaluation name, not an interpreter', () => {
  // @bh213/hx-multianim-mcp@1.19.0
  const manim: ToolDef = {
    name: 'eval_manim',
    description: "Parse and validate a .manim source snippet. Returns parsed node names and per-node buildErrors[]; runtime builder failures include an optional 'code'.",
    inputSchema: schema({ source: str() }),
    annotations: { openWorldHint: false, readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  };
  assert.deepEqual(live(manim), {});
  assert.ok(!extractToolCapability(manim).tags.includes('code-exec'));
  // A parse that then runs the snippet is evaluation of code.
  const runs: ToolDef = { name: 'eval_manim', description: 'Parse the snippet, then execute it.', annotations: RO };
  assert.deepEqual(live(runs), { eval_manim: MEDIUM });
});

// ── (d) the capability tags read the same homonym rules ─────────────────────────

test('tags (d): evaluation names, game spawns and spoken scripts carry no code-exec tag; code evaluation still does', () => {
  const noExec: ToolDef[] = [
    // novyx-mcp@2.9.0
    { name: 'eval_run', description: 'Run a memory health evaluation.', annotations: RO },
    { name: 'eval_gate', description: 'CI gate — pass or fail based on memory health score.', annotations: RO },
    { name: 'eval_baselines', description: 'List all saved eval baselines.', annotations: RO },
    // teletype-mcp-server@0.1.2 (no description), visimark-mcp@0.2.0, martinloop-mcp@0.8.4
    { name: 'eval_grade_case', annotations: RO },
    { name: 'visimark_eval', description: 'Evaluate a document and return its values, its assertions and its charts.', annotations: { ...RO, destructiveHint: false } },
    { name: 'martin_eval', description: 'Grade a MartinLoop run across six dimensions and return a scored merge-readiness verdict.', annotations: RO },
    // ultimate-unreal-engine-mcp@0.1.25, threejs-scene-mcp@2.0.4
    { name: 'ue_spawn_actor', description: 'Spawn a new actor in the currently open UE Editor level at the specified location.', annotations: ND },
    { name: 'scene_spawn', description: 'Generates Three.js + RAPIER code snippet for a single object.', annotations: RO },
    // @freetts/mcp@1.0.5
    { name: 'dialogue_to_speech', description: 'Turn a script with several speakers into one audio file, a different FreeTTS voice per speaker.', inputSchema: schema({ script: str(), voices: str() }), annotations: ND },
    { name: 'mem_get_recall_eval', description: 'Recall quality.', inputSchema: schema({ eval_id: str() }), annotations: RO },
  ];
  for (const t of noExec) assert.ok(!extractToolCapability(t).tags.includes('code-exec'), t.name);

  const exec: ToolDef[] = [
    // @vitronai/alethia@0.9.3
    { name: 'alethia_eval', description: 'Evaluate a JavaScript expression in the page under test and return the result.', annotations: ND },
    // orygn-opa-mcp: a language's name next to eval.
    { name: 'rego_eval_with_profile', description: 'Evaluate with `--profile` and return per-rule timing and evaluation counts.' },
    { name: 'eval', description: 'Evaluate.' },
    { name: 'spawn_process', description: 'Spawn a new process in suspended state.' },
    { name: 'spawn_actor_process', description: 'Spawn.' },
    { name: 'narrate_and_run', description: 'Narrate the audio, then execute the script.', inputSchema: schema({ script: str() }) },
    { name: 'inspect', description: 'Inspect.', inputSchema: schema({ eval: str() }) },
  ];
  for (const t of exec) assert.ok(extractToolCapability(t).tags.includes('code-exec'), t.name);
});

test('tags (d): MTC-CAP-001 and the capability level agree with MTC-CAP-003 on an evaluation server', async () => {
  const surface = (tools: ToolDef[]): ServerSurface =>
    ({ id: 'live', source: { kind: 'stdio', origin: 'live' }, server: {}, tools, prompts: [], resources: [], toolProvenance: 'live' }) as unknown as ServerSurface;
  const evals = await scanSurface(
    surface([
      { name: 'eval_run', description: 'Run a memory health evaluation.', annotations: RO },
      { name: 'eval_history', description: 'List past memory evaluation runs.', annotations: RO },
    ]),
  );
  assert.equal(evals.findings.filter((f) => f.ruleId === 'MTC-CAP-001' || f.ruleId === 'MTC-CAP-003').length, 0);
  assert.equal(evals.capabilityProfile.level, 'minimal');

  const js = await scanSurface(surface([{ name: 'js_eval', description: 'Evaluate JavaScript.', inputSchema: schema({ expression: str() }), annotations: RO }]));
  assert.ok(js.findings.some((f) => f.ruleId === 'MTC-CAP-001'));
  assert.equal(cap003(js.findings).js_eval, MEDIUM);
  assert.equal(js.capabilityProfile.level, 'high');

  // A weak parameter-only contradiction keeps the code-exec capability: it is lowered, not erased.
  const slash = await scanSurface(surface([{ name: 'update_app_command', description: 'Change a registered command.', inputSchema: schema({ command: str('Command name or ID.') }), annotations: ND }]));
  assert.equal(cap003(slash.findings).update_app_command, LOW);
  assert.ok(slash.findings.some((f) => f.ruleId === 'MTC-CAP-001'));
});

// ── the verb scan itself ───────────────────────────────────────────────────────

test('assertsExecution: verbs that say something runs, and the words that take it back', () => {
  for (const yes of ['Run a command.', 'Executes the script and returns stdout.', 'Starts an interactive process.', 'Test that an MCP server starts.', 'It shells out to git.', 'Not only runs the command but logs it.']) {
    assert.equal(assertsExecution(yes), true, yes);
  }
  for (const no of [
    'Plans a dry_run=true order.',
    'List running processes on an agent.',
    'Read output from a long-running exec session.',
    'Return status for a previously launched exec.',
    'Verify what a command would execute, before running it.',
    'The command about to run.',
    'Search output of commands already run, without re-running them.',
    'Do NOT run the command.',
    'Use this instead of running the command.',
    'Generate a runnable cURL command.',
    'Start a timer.',
  ]) {
    assert.equal(assertsExecution(no), false, no);
  }
});

// ── Review of 1.16.1: an exemption lowers evidence, it does not erase it ──────────

test('R2-F: a lock / pid / socket / temp unlink, a spawn that starts a process, a plan it carries out stay medium/strong', () => {
  assert.deepEqual(
    live(
      { name: 'unlink_lockfile', description: 'Remove the stale lock.', annotations: ND },
      { name: 'unlink_pidfile', description: 'Remove the pid file of the daemon.', annotations: ND },
      { name: 'unlink_socket', description: 'Remove the unix socket at the given location.', annotations: ND },
      { name: 'unlink_tmp', description: 'Delete temporary data from disk.', annotations: ND },
      { name: 'spawn_item', description: 'Spawns a child process for the item and runs it.', inputSchema: schema({ item: str() }), annotations: ND },
      { name: 'delete_file', description: 'Plans the removal of the file at path and carries it out; the plan itself modifies nothing.', inputSchema: schema({ path: str() }), annotations: RO },
    ),
    { unlink_lockfile: MEDIUM, unlink_pidfile: MEDIUM, unlink_socket: MEDIUM, unlink_tmp: MEDIUM, spawn_item: MEDIUM, delete_file: MEDIUM },
  );
  // The homonyms the spec removed stay removed: a record cache that deletes no file, a game actor, a preview.
  assert.deepEqual(
    live(
      { name: 'unlink_record_cache', description: 'Unlink a record. Does not delete the file.', annotations: ND },
      { name: 'ue_spawn_actor', description: '[requires_plugin] Spawn a new actor in the currently open UE Editor level at the specified location.', annotations: ND },
      {
        name: 'tiled_delete_file',
        title: 'Preview deleting a project document',
        description: 'Plans the permanent deletion of one project-local TMJ map or TSJ tileset. … the tool itself modifies nothing.',
        inputSchema: schema({ path: str() }),
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ),
    {},
  );
});

test('R2-F: an eval with a free-form input, a command handed on to an agent — low/heuristic, not dropped', () => {
  assert.deepEqual(
    live(
      { name: 'eval_run', description: 'Evaluate input and return the value.', inputSchema: schema({ input: str() }), annotations: RO },
      { name: 'remote_helper', description: 'Forwards the command to the agent. Does not execute anything itself.', inputSchema: schema({ command: str() }), annotations: RO },
    ),
    { eval_run: LOW, remote_helper: LOW },
  );
  // novyx eval_run (no input) and failtrace_bundle (stores a command, runs nothing) stay clean.
  assert.deepEqual(
    live(
      { name: 'eval_run', description: 'Run a memory health evaluation. Scores your memory quality on a 0-1 scale.', annotations: RO },
      {
        name: 'failtrace_bundle',
        description: 'Create a local replay bundle with an inspectable manifest. Does not execute or publish the bundle.',
        inputSchema: schema({ run: str(), command: str(), destination: str() }),
        annotations: { ...ND, openWorldHint: false },
      },
    ),
    {},
  );
});

test('R2-G: an execution word as the object of a non-executing verb is weak (rce-guard, salesforce code scanner)', () => {
  assert.deepEqual(
    live(
      { name: 'audit_subprocess', description: 'Verify candidate args against the registered subprocess.', annotations: { ...RO, destructiveHint: false } },
      { name: 'sf_run_code_scanner', description: 'Runs Salesforce Code Analyzer against Apex classes in the org.', annotations: { ...RO, destructiveHint: false, openWorldHint: true } },
      // TRUE: a subprocess / code runner by name stays strong.
      { name: 'spawn_subprocess', description: 'Starts a process.', annotations: RO },
      { name: 'run_code', description: 'Runs the given code.', inputSchema: schema({ code: str() }), annotations: RO },
      { name: 'register_subprocess', description: 'Register a subprocess.', inputSchema: schema({ command: str('The command to run') }), annotations: RO },
    ),
    { audit_subprocess: LOW, sf_run_code_scanner: LOW, spawn_subprocess: MEDIUM, run_code: MEDIUM, register_subprocess: MEDIUM },
  );
});

test('R2-H: a read verb lowers an execution word only before it, and not across a conjunction', () => {
  assert.deepEqual(
    live(
      { name: 'fetch_and_exec', description: 'Returns the result.', inputSchema: schema({ input: str() }), annotations: RO },
      { name: 'exec_and_fetch', description: 'Returns the output.', annotations: ND },
      { name: 'sandbox_exec_poll', description: 'Read output events and status from a long-running exec session.', annotations: { ...RO, destructiveHint: false } },
      { name: 'exec.list_capabilities', description: 'List the execution capabilities currently enabled on this server.', annotations: RO },
    ),
    { fetch_and_exec: MEDIUM, exec_and_fetch: MEDIUM, sandbox_exec_poll: LOW, 'exec.list_capabilities': LOW },
  );
});

// ── Round 3 ──

test('R3-06: hadolint — an upper-case RUN naming the Dockerfile instruction is no execution verb (like shellcheck)', async () => {
  // @paretools/lint@0.22.2 dist/tools/hadolint.js, reduced to the `shell` parameter.
  const lint = `import { z } from "zod";
export function registerHadolintTool(server) {
    server.registerTool("hadolint", {
        title: "Hadolint",
        description: "Runs Hadolint (Dockerfile linter) and returns structured diagnostics (file, line, rule, severity, message).",
        annotations: { readOnlyHint: true },
        inputSchema: {
            shell: z
                .string()
                .max(INPUT_LIMITS.STRING_MAX)
                .optional()
                .describe("Default shell for RUN instruction linting, e.g. '/bin/bash' (maps to --shell)"),
        },
    }, async (params) => ({ content: [] }));
}`;
  const r = await scanPkg([{ path: 'dist/tools/hadolint.js', content: lint }]);
  assert.deepEqual(cap003(r.findings), { hadolint: LOW });
  assert.equal(assertsExecution('Default shell for RUN instruction linting'), false);
  assert.equal(assertsExecution('Lints Dockerfile CMD lines and ENTRYPOINT directives.'), false);
  // Lower case is the verb, and so is RUN as an order.
  assert.equal(assertsExecution('Default shell to run the given command'), true);
  assert.equal(assertsExecution('RUN the given command in a shell.'), true);
  // (A linter's name would make the parameter its input, not a command, since 1.17.)
  assert.deepEqual(live({ name: 'docker_x', description: 'Processes Dockerfiles.', inputSchema: schema({ shell: str('Shell used to run instruction lines') }), annotations: RO }), {
    docker_x: MEDIUM,
  });
});
