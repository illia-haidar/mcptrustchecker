#!/usr/bin/env node
/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * MCP Trust Checker command-line interface.
 *
 *   mcptrustchecker scan <target>       scan a manifest / URL / package / client config
 *   mcptrustchecker publish <package>   scan it, then submit it to the hosted registry
 *   mcptrustchecker pin <target>        scan and (re)pin the integrity lockfile
 *   mcptrustchecker diff <target>       fail if the surface drifted since the pin
 *   mcptrustchecker rules               list every rule
 *   mcptrustchecker explain <ruleId>    describe a rule
 *   mcptrustchecker version | help
 *
 * Uses only Node built-ins (node:util parseArgs) — no arg-parsing dependency.
 */

import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolveTargets, type ResolveOptions, type ResolvedTarget } from '../acquire/index.js';
import { discoverClientConfigs } from '../acquire/discover.js';
import { scanSurface } from '../engine.js';
import { loadConfigFile, loadConfigFromPath } from '../config.js';
import { evaluatePolicy } from '../policy.js';
import { readLockfile, writeLockfile, pinSurface, emptyLockfile } from '../lockfile.js';
import type { Grade, ScanReport, McpTrustCheckerConfig } from '../types.js';
import { renderTerminal } from '../report/terminal.js';
import { renderJson } from '../report/json.js';
import { renderSarif } from '../report/sarif.js';
import { renderMarkdown } from '../report/markdown.js';
import { renderBadge } from '../report/badge.js';
import { GRADE_RANK } from '../scoring/model.js';
import { RULE_CATALOG, findRule } from '../data/ruleCatalog.js';
import { isCapabilityRule } from '../scoring/model.js';
import { METHODOLOGY_VERSION, TOOL_VERSION } from '../version.js';
import { c } from '../util/ansi.js';
import { parseHeaderArgs } from '../util/headers.js';
import {
  DEFAULT_PUBLISH_URL,
  buildPublishRequest,
  publishScan,
  publishableTargets,
  type PublishTarget,
} from '../publish.js';

const KNOWN_COMMANDS = new Set(['scan', 'publish', 'pin', 'diff', 'rules', 'explain', 'version', 'help']);

function fail(msg: string, code = 2): never {
  process.stderr.write(`${c.red('mcptrustchecker: error')} ${msg}\n`);
  process.exit(code);
}

function printHelp(): void {
  process.stdout.write(
    `${c.bold('MCP Trust Checker')} ${TOOL_VERSION} — local-first MCP security scanner (methodology ${METHODOLOGY_VERSION})

${c.bold('Usage')}
  mcptrustchecker                         scan every installed MCP client config (zero-config)
  mcptrustchecker [scan] <target>         scan a specific target (see below)
  mcptrustchecker pin <target>            scan and (re)pin the integrity lockfile
  mcptrustchecker diff <target>           exit non-zero if the surface drifted since pin
  mcptrustchecker rules                   list every rule
  mcptrustchecker explain <ruleId>        describe a rule

${c.bold('Targets')}
  path/to/tools.json               a pre-generated manifest (offline)
  https://host/mcp                 a live Streamable-HTTP / SSE endpoint
  --login                          OAuth browser sign-in for a protected endpoint (opens your browser)
  --scope <scope>                  OAuth scope to request with --login (e.g. mcp:tools)
  --header "Authorization: Bearer …"   static auth header instead of --login (repeatable)
  claude_desktop_config.json       a client config (scans each server)
  owner/repo                       a GitHub repository — reads its source (also accepts a github.com URL)
  @scope/package                   package scan (--online fetches metadata + reads the published source)
  path/to/server.tgz|.whl|.zip     a packed release artifact — reads the shipped source (offline)
  --command "npx -y my-server"     spawn a local stdio server (sandboxed)
  --env KEY=VALUE                  env var for --command (repeatable)

${c.bold('Output')}
  --json                           machine-readable JSON report
  --sarif                          SARIF 2.1.0 (GitHub code scanning)
  --md, --markdown                 Markdown (PR comments / summaries)
  --badge                          shields.io endpoint JSON
  -o, --output <file>              write output to a file

${c.bold('CI gates')}
  --fail-under <0-100>             exit 1 if the Trust Score is below N
  --min-grade <A-F>                exit 1 if the grade is worse than this

${c.bold('publish <package>')} ${c.gray('— scan it, then submit it to the public MCP Trust Registry')}
  A separate command on purpose: a plain scan never publishes and never asks.
  Only npm and PyPI packages can be submitted. Running the command IS the consent.
  --token <key>                    API key, required (also MCPTRUSTCHECKER_TOKEN)
  --category <slug>                registry category (default: other)
  --publish-url <origin>           self-hosted deployment (also MCPTRUSTCHECKER_PUBLISH_URL)

${c.bold('Options')}
  --config <path>                  config file (default: auto-discovered)
  --lockfile <path>                integrity lockfile (default: mcptrustchecker.lock)
  --no-lock                        skip the integrity (rug-pull) check
  --pin                            re-pin the lockfile after scanning
  --include-builtins               assume client built-in tools in toxic-flow analysis
  --online                         allow network lookups: registry metadata + the verified published source
  --metadata-only                  with --online: skip downloading the package artifact
  --run                            allow spawning servers found in a client config
  --allow-any-command              permit stdio commands outside the allowlist (dangerous)
  --allowed-hosts <a,b>            restrict live HTTP acquisition to these hosts
  --github-token <t>               lift GitHub's anonymous rate limit (also GITHUB_TOKEN)
  --registry <npm|pypi>            registry for bare package targets (default: npm)
  --details                        include references and full evidence per finding
  --no-pager                       don't page long output (also NO_PAGER / $PAGER)
  --quiet                          only print the grade line
  -h, --help                       show this help
  -v, --version                    show version
`,
  );
}

async function main(): Promise<number | void> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        json: { type: 'boolean' },
        sarif: { type: 'boolean' },
        md: { type: 'boolean' },
        markdown: { type: 'boolean' },
        badge: { type: 'boolean' },
        output: { type: 'string', short: 'o' },
        'fail-under': { type: 'string' },
        'min-grade': { type: 'string' },
        config: { type: 'string' },
        lockfile: { type: 'string' },
        'no-lock': { type: 'boolean' },
        pin: { type: 'boolean' },
        command: { type: 'string' },
        args: { type: 'string' },
        env: { type: 'string', multiple: true },
        header: { type: 'string', multiple: true },
        login: { type: 'boolean' },
        scope: { type: 'string' },
        url: { type: 'string' },
        online: { type: 'boolean' },
        'metadata-only': { type: 'boolean' },
        run: { type: 'boolean' },
        'allow-any-command': { type: 'boolean' },
        'allowed-hosts': { type: 'string' },
        'github-token': { type: 'string' },
        'include-builtins': { type: 'boolean' },
        registry: { type: 'string' },
        token: { type: 'string' },
        'publish-url': { type: 'string' },
        category: { type: 'string' },
        quiet: { type: 'boolean' },
        details: { type: 'boolean' },
        'no-pager': { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (err) {
    fail(`${(err as Error).message}. Run "mcptrustchecker --help" for usage.`);
  }
  const { values, positionals } = parsed;

  if (values.version) {
    process.stdout.write(`mcptrustchecker ${TOOL_VERSION} (methodology ${METHODOLOGY_VERSION})\n`);
    return;
  }
  if (values.help) {
    printHelp();
    return;
  }

  // If the first positional is an explicit command, the target is the next one;
  // otherwise the command defaults to `scan` and the first positional is the target.
  const explicit = Boolean(positionals[0] && KNOWN_COMMANDS.has(positionals[0]));
  const command = explicit ? positionals[0]! : 'scan';
  const target = explicit ? positionals[1] : positionals[0];

  if (command === 'help') return printHelp();
  if (command === 'version') {
    process.stdout.write(`mcptrustchecker ${TOOL_VERSION} (methodology ${METHODOLOGY_VERSION})\n`);
    return;
  }
  if (command === 'rules') return printRules();
  if (command === 'explain') return printExplain(target);

  // scan / pin / diff
  const scanTarget = target;
  const autoDiscover = !scanTarget && !values.command && !values.url;

  // Reject silently-dropped extra positional targets.
  const extraFrom = explicit ? 2 : 1;
  if (positionals.length > extraFrom) {
    fail(
      `unexpected extra argument(s): ${positionals.slice(extraFrom).join(', ')}. ` +
        `Scan one target at a time, or point at a client config to scan several servers.`,
    );
  }

  // Validate CI-gate flags up front so a typo fails loudly, not silently.
  if (values['fail-under'] !== undefined) {
    const n = Number(values['fail-under']);
    if (!Number.isFinite(n) || n < 0 || n > 100) fail(`--fail-under must be a number 0–100 (got "${values['fail-under']}")`);
  }
  if (values['min-grade'] !== undefined && !(values['min-grade'].toUpperCase() in GRADE_RANK)) {
    fail(`--min-grade must be one of A, B, C, D, F (got "${values['min-grade']}")`);
  }

  const fileConfig = values.config ? loadConfigFromPath(values.config) : loadConfigFile(process.cwd());
  const config: McpTrustCheckerConfig = {
    ...fileConfig,
    includeBuiltins: values['include-builtins'] ?? fileConfig.includeBuiltins,
  };

  const lockfilePath = values.lockfile ?? fileConfig.lockfile ?? 'mcptrustchecker.lock';
  const lock = values['no-lock'] ? null : (readLockfile(lockfilePath) ?? null);

  const resolveOpts: ResolveOptions = {
    command: values.command ? values.command.trim().split(/\s+/)[0] : undefined,
    args: buildArgs(values.command, values.args),
    url: values.url,
    // `publish` always reads the real published source: submitting a package
    // graded from its name alone would be worse than not grading it at all.
    online: command === 'publish' ? true : values.online,
    metadataOnly: values['metadata-only'],
    run: values.run,
    envVars: parseEnvFlags(values.env),
    allowAnyCommand: values['allow-any-command'],
    allowedHosts: values['allowed-hosts'] ? values['allowed-hosts'].split(',').map((h) => h.trim()) : undefined,
    githubToken: values['github-token'],
    headers: parseHeaderArgs(values.header),
    login: values.login,
    scope: values.scope,
    registry: values.registry === 'pypi' ? 'pypi' : 'npm',
  };

  // --login and a static Authorization header are alternative auth methods;
  // combining them would silently clobber the freshly-minted OAuth token.
  if (
    values.login &&
    resolveOpts.headers &&
    Object.keys(resolveOpts.headers).some((h) => h.toLowerCase() === 'authorization')
  ) {
    fail('--login cannot be combined with a static --header "Authorization: …" — choose one auth method.');
  }

  let resolved: ResolvedTarget[] = [];
  if (autoDiscover) {
    // Zero-config: find and scan every installed MCP client config.
    const configs = discoverClientConfigs();
    if (configs.length === 0) {
      process.stdout.write(
        `${c.bold('MCP Trust Checker')} — no MCP client configs found to scan.\n\n` +
          `Point at something explicitly:\n` +
          `  mcptrustchecker scan ./tools.json                  ${c.gray('# a manifest')}\n` +
          `  mcptrustchecker scan https://host/mcp              ${c.gray('# a live endpoint')}\n` +
          `  mcptrustchecker scan --command "npx -y <server>"   ${c.gray('# a local stdio server')}\n` +
          `  mcptrustchecker scan <@scope/package> --online     ${c.gray('# a package name')}\n\n` +
          `Run ${c.bold('mcptrustchecker --help')} for all options.\n`,
      );
      return;
    }
    process.stderr.write(
      `${c.gray('Discovered')} ${configs.length} MCP config(s): ${configs.map((x) => x.client).join(', ')}\n` +
        (values.run ? '' : `${c.gray('(static scan; add')} ${c.bold('--run')}${c.gray(' to spawn servers and analyze tool descriptions)')}\n`),
    );
    for (const cfg of configs) {
      try {
        resolved.push(...(await resolveTargets(cfg.path, resolveOpts)));
      } catch (err) {
        process.stderr.write(`${c.yellow('!')} skipped ${cfg.path}: ${(err as Error).message}\n`);
      }
    }
    if (resolved.length === 0) fail('no MCP servers found in the discovered configs.');
  } else {
    try {
      resolved = await resolveTargets(scanTarget, resolveOpts);
    } catch (err) {
      fail((err as Error).message);
    }
  }

  // Publishing is never a side effect of scanning: only the `publish` command
  // submits anything, and invoking that command is itself the consent. Checked
  // here, before the scan runs, so a missing key fails in a second rather than
  // after a 30-second package download.
  const publish = preparePublish(command, values, fileConfig, resolved);
  if (publish.enabled) {
    if (!publish.token) {
      fail(
        'publish needs an API key. Pass --token <key> or set MCPTRUSTCHECKER_TOKEN. ' +
          'Get one free at https://mcptrustchecker.com/api',
      );
    }
    if (publish.targets.length === 0) {
      fail(
        'nothing to publish: only npm and PyPI packages can be submitted for now, ' +
          'and this target carries no registry identity.',
      );
    }
  }

  // Flat tool inventory across all resolved servers, for cross-server collision.
  const allTools = resolved.flatMap((r) => r.surface.tools.map((t) => ({ server: r.surface.id, name: t.name })));

  const reports: ScanReport[] = [];
  for (const { surface } of resolved) {
    const siblingTools = allTools.filter((t) => t.server !== surface.id);
    const report = await scanSurface(surface, {
      config,
      lockfile: values['no-lock'] ? undefined : lock,
      scannedAt: new Date().toISOString(),
      siblingTools,
    });
    reports.push(report);
  }

  // Submit the applications. A publish failure is never fatal: it must not
  // change the exit code, touch stdout, or abort a scan that already succeeded.
  if (publish.enabled) await runPublish(publish, resolved, reports);

  // pin — always read the existing lockfile first (even under --no-lock) so we
  // merge into it rather than clobbering previously-pinned servers.
  if (command === 'pin' || values.pin) {
    let updated = readLockfile(lockfilePath) ?? emptyLockfile();
    for (const { surface } of resolved) updated = pinSurface(updated, surface, new Date().toISOString());
    writeLockfile(lockfilePath, updated);
    process.stderr.write(`${c.green('✓')} pinned ${resolved.length} server(s) → ${lockfilePath}\n`);
  }

  // output
  const rendered = render(reports, values);
  if (values.output) {
    try {
      writeFileSync(values.output, rendered.endsWith('\n') ? rendered : rendered + '\n');
    } catch (err) {
      fail(`could not write ${values.output}: ${(err as Error).message}`);
    }
    process.stderr.write(`${c.green('✓')} wrote ${values.output}\n`);
    if (!values.json && !values.sarif && !values.badge) process.stdout.write(summaryLine(reports) + '\n');
  } else {
    // The human report can be long; page it (starting at the top, on the grade)
    // rather than letting the terminal scroll to the end of the findings.
    const isHumanReport =
      !values.json && !values.sarif && !values.badge && !values.md && !values.markdown && !values.quiet;
    paginate(rendered, isHumanReport && !values['no-pager']);
  }

  // Return the exit code instead of process.exit() — exit() can truncate a large
  // stdout write to a pipe before it flushes (invalid JSON/SARIF). Letting main
  // resolve lets Node flush stdout, then the entrypoint sets process.exitCode.
  return computeExitCode(command, reports, values, fileConfig);
}

/**
 * Write to stdout, paging through $PAGER (default `less`) when the output is an
 * interactive terminal and taller than the screen — so the view opens on the
 * grade at the top instead of auto-scrolling to the last finding.
 *
 * We use plain `less -R` (raw colors) on the standard alternate screen. We
 * deliberately avoid `-X`/`-F`: `-X` (no alternate screen) makes some terminals
 * dump every repaint into scrollback while scrolling (duplicated output), and
 * `-F` misbehaves on piped input. For default-less we also force `LESS=R` so a
 * user's global `$LESS` (which may contain -X/-F) can't reintroduce the bug.
 * Honors NO_PAGER / MCPTRUSTCHECKER_NO_PAGER and any custom $PAGER verbatim.
 */
function paginate(text: string, allow: boolean): void {
  const body = text.endsWith('\n') ? text : `${text}\n`;
  const rows = process.stdout.rows || 24;
  const tallerThanScreen = body.split('\n').length > rows - 1;
  const wantPager =
    allow &&
    Boolean(process.stdout.isTTY) &&
    !process.env.NO_PAGER &&
    !process.env.MCPTRUSTCHECKER_NO_PAGER &&
    tallerThanScreen;

  if (!wantPager) {
    process.stdout.write(body);
    return;
  }

  const pagerEnv = (process.env.PAGER ?? '').trim();
  const [cmd, ...preArgs] = (pagerEnv || 'less').split(/\s+/);
  const useDefaultLess = /(^|\/)less$/.test(cmd ?? '') && preArgs.length === 0;
  const args = useDefaultLess ? ['-R'] : preArgs;
  const env = useDefaultLess ? { ...process.env, LESS: 'R' } : process.env;

  try {
    const res = spawnSync(cmd ?? 'less', args, { input: body, stdio: ['pipe', 'inherit', 'inherit'], env });
    if (res.error) process.stdout.write(body); // pager missing → fall back
  } catch {
    process.stdout.write(body);
  }
}

/**
 * First value that is actually set. An exported-but-empty env var (`TOKEN=`)
 * counts as unset, so it can't shadow a config file that does have a value.
 */
function firstSet(...values: (string | undefined)[]): string {
  for (const v of values) if (typeof v === 'string' && v.trim() !== '') return v.trim();
  return '';
}

interface PublishState {
  /** True only for the `publish` command — scanning never sets this. */
  enabled: boolean;
  targets: PublishTarget[];
  token: string;
  origin: string;
  category?: string;
}

/**
 * Collect what the `publish` command needs. There is no decision to make and
 * nobody to ask: publishing happens when — and only when — the user typed
 * `publish`. Credentials still come from flag > environment > config file.
 */
function preparePublish(
  command: string,
  values: Record<string, unknown>,
  fileConfig: McpTrustCheckerConfig,
  resolved: ResolvedTarget[],
): PublishState {
  const enabled = command === 'publish';
  return {
    enabled,
    targets: enabled ? publishableTargets(resolved) : [],
    token: firstSet(
      values.token as string | undefined,
      process.env.MCPTRUSTCHECKER_TOKEN,
      fileConfig.publishToken,
    ),
    origin:
      firstSet(
        values['publish-url'] as string | undefined,
        process.env.MCPTRUSTCHECKER_PUBLISH_URL,
        fileConfig.publishUrl,
      ) || DEFAULT_PUBLISH_URL,
    category: (values.category as string | undefined) ?? fileConfig.publishCategory,
  };
}

/**
 * POST one application per publishable package. Every message goes to stderr so
 * `--json`/`--sarif`/`--badge`/`-o` output stays machine-clean, and every error
 * is a warning: the scan's verdict is the product, publishing is a side errand.
 */
async function runPublish(state: PublishState, resolved: ResolvedTarget[], reports: ScanReport[]): Promise<void> {
  // reports[i] corresponds to resolved[i]; map each identity to its local scan
  // so the application can carry an informational grade for comparison.
  const localReports = new Map<string, ScanReport>();
  resolved.forEach((r, i) => {
    const p = publishableTargets([r])[0];
    const report = reports[i];
    if (p && report) localReports.set(`${p.registry}:${p.spec}`, report);
  });

  for (const target of state.targets) {
    const body = buildPublishRequest(target, {
      category: state.category,
      report: localReports.get(`${target.registry}:${target.spec}`),
    });
    if (!body) continue;
    try {
      const result = await publishScan(body, { token: state.token, origin: state.origin });
      if (!result.ok) {
        process.stderr.write(`${c.yellow('!')} publish failed for ${target.spec}: ${result.error}\n`);
        continue;
      }
      const { status, url, message } = result.response ?? ({} as { status?: string; url?: string; message?: string });
      const tail = url ? ` → ${url}` : '';
      const label = status === 'already-listed' ? 'already listed' : 'queued for review';
      process.stderr.write(`${c.green('✓')} ${target.spec}: ${message ?? label}${tail}\n`);
    } catch (err) {
      // Belt and braces — publishScan already swallows its own errors.
      process.stderr.write(`${c.yellow('!')} publish failed for ${target.spec}: ${(err as Error).message}\n`);
    }
  }
}

function parseEnvFlags(list?: string[]): Record<string, string> | undefined {
  if (!list || list.length === 0) return undefined;
  const out: Record<string, string> = {};
  for (const kv of list) {
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return Object.keys(out).length ? out : undefined;
}

function buildArgs(command?: string, args?: string): string[] | undefined {
  const fromCommand = command ? command.trim().split(/\s+/).slice(1) : [];
  const fromArgs = args ? args.trim().split(/\s+/) : [];
  const all = [...fromCommand, ...fromArgs];
  return all.length ? all : undefined;
}

function render(reports: ScanReport[], values: Record<string, unknown>): string {
  const single = reports.length === 1;
  if (values.json) return single ? renderJson(reports[0]!) : JSON.stringify(reports, null, 2);
  if (values.sarif) return renderSarifMerged(reports);
  if (values.badge) return single ? renderBadge(reports[0]!) : JSON.stringify(reports.map((r) => JSON.parse(renderBadge(r))));
  if (values.md || values.markdown) return reports.map(renderMarkdown).join('\n\n---\n\n');
  if (values.quiet) return summaryLine(reports);
  return reports.map((r) => renderTerminal(r, { details: Boolean(values.details) })).join('\n');
}

function renderSarifMerged(reports: ScanReport[]): string {
  if (reports.length === 1) return renderSarif(reports[0]!);
  const runs = reports.flatMap((r) => JSON.parse(renderSarif(r)).runs);
  return JSON.stringify({ $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs }, null, 2);
}

function summaryLine(reports: ScanReport[]): string {
  return reports
    .map(
      (r) =>
        `${r.target.id}: Trust ${r.score.grade} (${r.score.score}/100) · Capability ${r.capabilityProfile.level.toUpperCase()}`,
    )
    .join('\n');
}

function computeExitCode(
  command: string,
  reports: ScanReport[],
  values: Record<string, unknown>,
  fileConfig: McpTrustCheckerConfig,
): number {
  if (command === 'diff') {
    if (reports.some((r) => r.integrity?.status === 'drift')) return 1;
  }
  const failUnder = values['fail-under'] !== undefined ? Number(values['fail-under']) : fileConfig.failUnder;
  const rawMinGrade = (values['min-grade'] as string | undefined) ?? fileConfig.minGrade;
  const minGrade = rawMinGrade ? String(rawMinGrade).toUpperCase() : undefined;
  let gated = 0;
  for (const r of reports) {
    if (failUnder !== undefined && r.score.score < failUnder) gated = 1;
    if (minGrade && minGrade in GRADE_RANK && GRADE_RANK[r.score.grade] < GRADE_RANK[minGrade as Grade]) gated = 1;
    // Policy-as-code: report every violation, then fail.
    const violations = evaluatePolicy(r, fileConfig.policy);
    for (const v of violations) {
      process.stderr.write(`${c.red('policy')} ${r.target.id}: ${v.message}\n`);
      gated = 1;
    }
  }
  return gated;
}

function printRules(): void {
  const lines = [`${c.bold('MCP Trust Checker rules')} (${RULE_CATALOG.length})`, ''];
  let lastCat = '';
  for (const r of RULE_CATALOG) {
    if (r.category !== lastCat) {
      lines.push(c.gray(`— ${r.category} —`));
      lastCat = r.category;
    }
    // Mirror docs/rules.md: mark the rules that describe blast radius rather than
    // a trust threat, so the listing shows which axis each rule feeds.
    const cap = isCapabilityRule(r.id) ? c.gray(' [capability]') : '';
    lines.push(`  ${c.bold(r.id.padEnd(16))} ${c.gray(`[${r.severity}]`)} ${r.title}${cap}`);
  }
  process.stdout.write(lines.join('\n') + '\n');
}

function printExplain(id: string | undefined): void {
  if (!id) fail('usage: mcptrustchecker explain <ruleId>');
  const rule = findRule(id!);
  if (!rule) fail(`unknown rule "${id}". Run "mcptrustchecker rules" to list them.`);
  // Which AXIS the rule feeds is the single most load-bearing fact about it: a
  // capability rule describes blast radius and never lowers the Trust grade,
  // while a threat rule does. Stating it here keeps the CLI in step with
  // docs/rules.md (which marks the same rules **[capability]**).
  // `info` carries weight 0 and is filtered out before any penalty, so calling
  // it scored would be false: these rules report coverage and hygiene facts the
  // reader needs, and deliberately move no points.
  const axis = isCapabilityRule(rule!.id)
    ? 'capability — raises the Capability level, never lowers the Trust grade'
    : rule!.severity === 'info'
      ? 'informational — reported for honesty, carries no penalty'
      : 'trust threat — scored, can lower the Trust grade';
  process.stdout.write(
    `${c.bold(rule!.id)} — ${rule!.title}\n` +
      `  axis: ${axis}\n  category: ${rule!.category}\n  severity: ${rule!.severity}\n\n  ${rule!.summary}\n`,
  );
}

main()
  .then((code) => {
    if (typeof code === 'number' && code !== 0) process.exitCode = code;
  })
  .catch((err) => fail((err as Error).message ?? String(err), 2));
