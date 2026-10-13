# Changelog

All notable changes to `mcptrustchecker` are recorded here. The scanner is
deterministic: the **methodology version** is bumped whenever a change could
move a score, so a grade is always reproducible against the version that
produced it.

## 1.16.0 — methodology `mcptrustchecker-1.16`

**Scores move in both directions, each for a stated reason.** A server that
declares — or visibly performs — writes is no longer rated as if it had none,
and a server is no longer charged with the dynamic code of a dependency its
bundler inlined. This release answers a publisher ticket (p_4774) and an appeal
(APL-0012) filed on a marketplace that runs this engine; both were reproduced
from the published artifacts before anything changed. Re-scan stored results
before comparing them with 1.15.

### Tools registered through a helper are recovered (p_4774)

`@prerenderbuddy/mcp@0.3.1` registers three tools directly and eleven through a
local helper — `function register(server, name, definition, handler) {
server.registerTool(name, { ...definition, annotations: definition.annotations
|| ANNOTATIONS }, …) }` — and two of the eleven declare and perform writes to
its API (`readOnlyHint: false`, `client.post(…)`). 1.15 recovered three tools
and rated the server `minimal`. The static extractor now reads registrations the
way the language runs them:

- a **helper** — a function that passes its own parameter as the tool name to
  `registerTool` / `tool` / `addTool` — and a helper calling a helper; each call
  with a literal name is a tool, with its description, schema and annotations
  read from the definition passed at that call;
- a **loop** over a definitions table: `for (const [name, def] of
  Object.entries(TOOLS))`, `TOOLS.forEach(t => server.tool(t.name, …))`;
- the TS SDK's positional `server.tool(name, description, schema, annotations,
  cb)`, `{ ...DEFAULTS, ...hints }` in the annotations slot included;
- Python decorators with nested calls (`@mcp.tool(annotations=ToolAnnotations(…))`,
  which the line matcher missed entirely), `{**BASE, **WRITE}`, decorator
  wrappers that pass their keywords through, `add_tool(…)`, `Tool(…, annotations=…)`.

### Annotations are read for every tool — and unknown stays unknown

Every recovered tool now carries the hints it declares, evaluated rather than
grepped: object literals and spreads in source order, `||` / `??` fallbacks,
`Object.freeze` / `Object.assign`, same-file constants, helper parameters bound
to each call's arguments. Each records where its hints came from
(`capabilities[].hintSource`: `declared`, `default`, `merged`, `unreadable`,
`none`). The order is the language's:

- the tool's own `annotations` first; a helper's default (`def.annotations ||
  DEFAULTS`, `?? DEFAULTS`, through `Object.freeze` too) only where the call site
  has **no** `annotations` key at all;
- merges are layered as written — `{ ...DEFAULTS, ...def.annotations }`,
  `...(P ?? {})`, `...(P || {})`, `Object.assign({}, DEFAULTS, P)` — defaults
  first, the tool on top.

The traps a reader of annotations falls into are closed and pinned by tests:
annotations that exist but cannot be read (an imported constant, a definition
from another file, a function call, a spread of an unknown object) are
**unknown** and never replaced by the default; an unreadable spread **resets**
the hints written before it; `annotations: {}` is truthy, so the default does
not apply; a call chained on a Python constructor (`ToolAnnotations(…).model_copy(
update=…)`) is unreadable.

### Hints and handlers raise the capability level — and nothing lowers it

Before 1.16 the annotations were read only to catch a contradiction. An explicit
hint now adds a role, and never removes one:

| The tool declares | Role added |
|---|---|
| `openWorldHint: true`, no write hint | `untrusted-input` — its answers come from outside |
| `readOnlyHint: false` / `destructiveHint: true` with `openWorldHint: true` | `external-sink` — it acts on an external service |
| `readOnlyHint: false` / `destructiveHint: true` without it | `state-write` (new) — it changes the state it holds |

For a statically recovered tool, a handler that visibly sends an HTTP
`POST`/`PUT`/`PATCH`/`DELETE` to an API raises `external-sink` the same way; a
POST that only asks (GraphQL, a search endpoint) and `Map.prototype.delete` do
not. The rule that matters most: **a hint can only raise a tool's level, never
lower it below what its name and behaviour show** — `delete_file` or a handler
calling `api.delete(…)` stays a writer under `readOnlyHint: true`, and the
contradiction is still `MTC-CAP-003`. Otherwise a scan would under-state the
risk, and a gateway's read-only key would reach a writing tool.

`state-write` is a new capability tag; like `process-spawn` it raises the blast
radius to `moderate` at most. One tool's hints cannot complete a trifecta on
their own: the open-world branches above are exclusive.

### Conditional registration is part of the surface

An early `if (!client.enabled) return`, an `if (apiKey) { … }` block, a Python
`if os.getenv(…):` — the tools behind them are still the server's surface and
are analysed. The report lists them by condition (`coverage.conditionalTools`)
and a caveat says what a server started without that configuration exposes
("11 of the 14 recovered tools are registered only when `options.enabled ===
false || !client.enabled` is false … a server started without that
configuration exposes only the other 3").

### Every way the source arrives recovers the same tools

Static tool recovery ran for `--online` packages and GitHub repositories but not
for a local directory or a packed artifact, so a tarball of a server an online
scan credited with three tools reported none. All four paths now share one step.

### Bundled code generators are no longer the server's dynamic code (APL-0012)

Single-file `dist` bundles inline their dependencies — above all Ajv's JSON-schema
compiler, which arrives with `@modelcontextprotocol/sdk`. Its
``new Function(`${…self}`, `${…scope}`, …)(this, this.scope.get())`` was reported as
the server's MTC-SRC-001 and inflated the capability level of hundreds of servers
(on the marketplace that filed the appeal, 726 of 1,754 servers with MTC-SRC-001
matched the Ajv shape).

A MTC-SRC-001/010 site in generated JavaScript (`.js`/`.mjs`/`.cjs`) is now
**discounted** — `info`, titled "in bundled dependency <pkg>@<version>", with
`data.vendored` and `capabilityTag: null`, so the capability level is recomputed
without it — only when the call at the site matches a verified signature of a code
generator, taken from its published source: Ajv's validator and JTD compilers
(pinned to Ajv's own `CodeGen` in the same file), depd's `wrapfunction`, or
get-intrinsic's evalled-constructor probe. Each signature pins the call and the
provenance of every runtime value in it, and is corroborated either by the
bundle's source map — sidecar, `sourceMappingURL` target or inline `data:` map,
kept under its own byte budget and never scanned as source — tracing the site into
that package's `node_modules/` directory (and an embedded original showing the
same call), or, with no usable map, by the file being a real bundle that carries
the generator's own identifying text in code. Fingerprints are unchanged.

Code a map traces to **any other** package — other generators included — is named
(`data.vendored.discounted: false`, and `codeExecutionLibrary: true` for evaluators
and template engines such as vm2, safe-eval, ses, handlebars, ejs, jsdom) but
counted in full: dependency code runs in the server process, and what reaches it
is the server's choice. A pnpm, bun or yarn store is believed only when it agrees
with the package directory; maps never apply to Python or TypeScript sources.

Maps and bundles are written by the package's author, so a deliberate full copy of
a generator inside a genuine bundle can still lower the capability level.
Attribution therefore moves **only the capability axis**: no threat-axis rule
(MTC-SRC-004/007/008/009/011, every non-source rule) is relaxed by it, and a site a
decode-and-execute dropper covers is never attributed.

### Hardened before release

The new readers were attacked directly over four rounds — correctness bugs,
hostile packages, forged source maps, then the fixes themselves — and every
reproduced case was fixed and is pinned by a test (`test/appeals-1.16.test.ts`,
`test/vendored-1.16.test.ts`). Among them:

- only the exact hint names the SDKs read count — a `read_only_hint: true` twin no
  longer overrides `readOnlyHint: false`;
- the evaluation budget is per registration and constants are evaluated once, so
  an expensive decoy early in a file cannot make a later (poisoned) tool vanish; a
  helper that decorates the description (`` `[x] ${def.description}` ``, `+`) keeps
  the call site's text, so tool-poisoning still sees it;
- the TS SDK's positional `server.tool(...)` is read by arity, as the SDK reads it:
  a referenced or wrapped callback and an unreadable description no longer shift
  the annotations into the schema;
- a tool registered twice (an if/else pair, a legacy file) merges toward the write,
  unites the handler evidence and keeps BOTH descriptions, so a poisoned one beside
  a longer clean one is still scanned; an if/else pair is not "conditional";
- caps count distinct tools, helpers are read before direct calls, and a file that
  hits a cap says so (`Tool recovery stopped early in …`), so decoy registrations
  cannot hide a tool silently;
- rest destructuring, per-key defaults, explicit `undefined`, TypeScript generics
  and typed arrows in helper parameters; a helper that rewrites its parameter
  (`def.annotations ??= …`, `kwargs.setdefault(…)`) makes it unreadable; a constant
  changed after its declaration, aliased, or written through a function is not its
  initializer; a definitions table longer than 4,000 characters is read whole;
- handler evidence needs an HTTP client — `Map#delete`, `Headers#delete`, KV
  bindings and route definitions (`app.post('/x', handler)`) are not requests, and a
  token-refresh POST in a shared helper is not every tool's write; an ORM or SQL
  write in the handler is `state-write`;
- conditions: entry guards (`require.main === module`), argument guards (`if
  (!server) throw`), idempotency flags and callers in both branches are not
  configuration; braceless `if`, `&&`, ternaries, an exit after a log line, a
  callback inside an `if`, and `if (t.disabled) continue` in a loop are;
- Python: positional names (`@mcp.tool("name")`, `add_tool(fn, "name")`),
  `dict(WRITE)`, Python truthiness for `or`, and only MCP code — a LangChain
  `Tool(func=…)` or a pydantic-ai `@agent.tool` is not an MCP tool;
- a minified bundle is recognised by lines dense with code, not by its average
  line length — an embedded base64 logo or a one-line lookup table no longer
  switches helper recovery off;
- a `tools/list` object is a tool only with an `inputSchema`, as the protocol
  requires: prompts, their arguments and resources listed in the same file are no
  longer reported as tools (1.15 did);
- source maps (part two): a forged map — even with a generator's real source as
  `sourcesContent` — can no longer discount the server's own `eval`: a verified
  signature must match at the generated site in every case; signatures can no
  longer be satisfied by a comment, a decoy class or code that passes runtime
  input; maps apply to generated JavaScript only, are parsed
  once per scan (a shared 30 MB map stalled a scan for minutes, a crafted
  `sourceRoot` ran out of memory), and their paths are normalized before deciding.

### Also

- `FileCtx` (1.15) builds its function index in linear time: a file of deeply
  nested callbacks took seconds to minutes; it now takes milliseconds, and the
  1.15 analyses benefit too. Generic arguments (`Map<string, unknown>`) no longer
  shift parameter positions, and a constant passed before an arrow callback
  (`f(x, NAME, async () => …)`) is no longer mistaken for a destructuring
  assignment of `NAME` — that made it unreadable for the whole file.
- `FileCtx.mutated` (1.15) read `...x }, async () =>` as a destructuring
  assignment — the `=>` of an arrow — and refused to fold `x` as a constant.
  Fixed; it matters wherever a constant is spread next to a callback.
- The registration reader is linear on hostile input: a step budget bounds
  spreads of spreads, `if` statements are indexed once per file, and the import
  and Python-condition scans no longer use overlapping quantifiers (a crafted
  400 KB file took 0.7 s in an intermediate build; pinned under a timing test).

### Measured movement

- **p_4774** — `@prerenderbuddy/mcp@0.3.1`: 1.15 recovered three tools from an online
  scan (none from the tarball) and rated it A 100 / `minimal`; 1.16 recovers all
  fourteen — the two writers as `external-sink`, the three crawlers as
  `untrusted-input`, nine readers with no role — reports the eleven key-gated tools
  as conditional, and rates it **A 97 / `moderate`**.
- **APL-0012** — `@scorezilla/mcp@0.4.2`: A 94 / `high` → **A 100 / `minimal`**;
  its MTC-SRC-001 is `info`, "in bundled dependency ajv@8.20.0" (source map).
- **A population of 531 published servers** (a deterministic sample of the
  registry: 400 with statically recovered tools, 111 with MTC-SRC-001, 20 widely
  used ones), the same versions scanned by 1.15.0 and 1.16.0: 123 changed. The
  capability level went down for 41 (bundled Ajv, depd, get-intrinsic) and up for
  37 (declared writes, `openWorldHint`, handler writes, newly recovered tools).
  Twenty-four lost tools 1.15 had invented — prompts, prompt arguments, parameter
  names. **No threat finding disappeared anywhere.** Five grades moved, each for a
  reason the published package states: `proxmox-mcps` A 93 → B 81 and
  `@oss-autopilot/mcp` A 94 → B 88 (MTC-CAP-003 — tools that unlink disks or run
  commands declare `destructiveHint: false` or `readOnlyHint: true`, which a client
  uses to skip the confirmation prompt); `@wundervault/mcp-server` A 93 → C 77,
  `@lerianstudio/matcher-mcp` A 96 → F 58 and `@quackai/q402-mcp` A 97 → F 50 (the
  injection rules now read the full description a running server sends — a
  concatenated string, or a tool 1.15 did not recover). The full list is attached
  to the release.
- The 81-server benchmark holds at 100% precision and 100% recall. 666 tests pass (113 new).

## 1.15.0 — methodology `mcptrustchecker-1.15`

**Scores move**, and almost always toward what the code actually does. This
release answers ten publisher appeals (six packages) filed against scans on a
marketplace that runs this engine. Each one was reproduced from the published
artifact, line by line, before anything changed. Re-scan stored results before
comparing them with 1.14.

### Process execution is graded per call, not per import (MTC-SRC-002)

The rule fired on the first `child_process` token in a file — almost always the
import — and called every file "high · command injection / RCE". It now finds
each call (`execFile`, `spawn`, `exec`, `fork`, `promisify` aliases, compiled
`(0, ns.execFile)(…)`, `cross-spawn`, `execa`; Python `subprocess`/`os.system`)
and grades it by shape: a runtime-built shell command or a runtime-chosen program
is still **high** code execution; a fixed program spawned without a shell is a
`process-spawn` capability (**low**, or **info** with fixed arguments, **medium**
when a tool's input visibly reaches the argv). The finding now sits on the call,
its evidence is the call, and `data.callShape` / `data.calls` say why.

`process-spawn` is a new capability tag. It raises the blast radius to
`moderate` at most; only `code-exec` reaches `high`.

### What a downgrade must never miss

Grading by shape creates a new way to be wrong: calling a fixed-looking call
harmless when it is not. Before release the new logic was attacked directly — in
two passes, one hunting correctness bugs and one writing hostile packages against
it. Every reproduced case (46 in all) was closed and is pinned by a test. Among
them:

- an interpreter handed runtime code or a runtime script (`node -e`, `python -c`,
  `perl -e`, `process.execPath` with a runtime path) is code execution, not a
  "fixed program";
- wrappers are looked through (`env bash -c …`, `sudo`, `nohup`, `timeout`), and
  `.exe` names of shells count as shells;
- a package runner or manager given a runtime package (`npx <pkg>`,
  `npm install <pkg>`, `npm exec`) runs code chosen at runtime;
- `shell: true` hidden in a `const` options object is read, and options the
  scanner cannot see (a parameter, a spread) together with runtime arguments are
  treated as a possible shell;
- a file loaded through `createRequire(...)`, a bundler's `__require`, a
  `new Worker(...)` or `fork(...)` is part of what the server runs; `require` handed
  on as a value marks the graph incomplete, so nothing outside it can be declared
  unreachable;
- an install hook that calls into a dependency whose code was not read gets no
  "reviewed" verdict, and a hook that loads any networking module or mutates the
  filesystem (`rmSync`, `unlinkSync`, `cpSync`, `chmod`…) cannot read as harmless;
- a shell or an interpreter started with no command reads it from stdin
  (`spawn('/bin/sh')` piped to a socket is a reverse shell), so it is code execution;
- a parameter's DEFAULT value is folded when the argument is omitted; methods and
  object properties are never folded from in-file call sites; block-scoped `const`,
  for-of / catch / destructured bindings and Python locals all shadow an outer
  constant; a mutated `const` array or options object is not a constant;
- `require('child_process').spawn` held in a variable, `import('child_process')
  .then(cp => …)`, bundler numeric requires (webpack/ncc), `cp['exec']`, and in
  Python `import os.path`, `from subprocess import *`, `importlib`, multi-line
  imports are all process calls;
- the import graph treats an import map (`#x`), a self-reference through
  `exports`, a path alias or a trailing-slash directory correctly, adds every branch
  of a ternary `import()`, and when the server's graph is incomplete calls nothing
  else unreachable; code a server's entry loads at startup can hand functions to
  the server, so it is never called unreachable either;
- two regular expressions were quadratic or worse on long runs of blank lines or
  spaces (a minute on a crafted file); both are now linear, and the lexer no longer
  miscounts brackets after a `${…}` interpolation.

### Reach from the MCP server

A package that ships a CLI, a daemon or a client next to its server used to have
all of it reported as "the server's implementation". The engine now builds the
import graph from the declared entry points, finds the files that build or
*handle* an MCP server (a client that sends `tools/call` is not one), and follows
a CLI's lazily-loaded `mcp serve` branch when the server is a subcommand. Capability
sinks outside the server's closure are downgraded like tooling and stop raising the
capability level. Findings carry `data.reachable` and `data.entry`. With no
declared entry that reaches a server, everything is `unknown` and nothing changes.

### One constant folder for every rule

The program of a process call, the path of a dynamic `import()`, the elements of a
deny-list and the edges of the import graph are all decided by one folder
(`src/util/constFold.ts`). It is scope-aware: in a bundle where names repeat, a
same-named constant in another function is never borrowed — resolving the wrong
one would have turned a runtime value into a "constant". A wrapper's parameter is
folded from its call sites only when the wrapper is local; an exported one could
be called with anything.

### The other appeals

- **MTC-SUP-012** read only the legacy PyPI `license` field. PEP 639 moved the
  declaration to `license_expression` and forbids filling the legacy field next to
  it, so every package built by setuptools ≥ 77, hatchling or uv was "unlicensed".
  The rule now reads `license_expression`, the free-text field (ignoring the
  `UNKNOWN` setuptools writes), and `License ::` classifiers on PyPI; the
  deprecated `licenses` array and `{type, url}` object on npm (the object used to
  print as `[object Object]`); pyproject.toml and setup.cfg in a source tree; and
  a shipped `LICENSE` file. The rule is exported (`licenseFromPypiInfo`,
  `licenseFromNpmManifest`, …) so a page that prints a license next to the report
  can give the same answer.
- **MTC-SRC-006** no longer reads a deny-list as a read. A set of credential file
  names that is only ever membership-tested (`BLOCKED.has(…)`, `name in DENY`) is
  protection. Iterating the list and reading each entry is still a read.
- **MTC-SRC-005** no longer flags a module of the package itself loaded by a
  computed path (`import(pathToFileURL(join(findPackageRoot(moduleDir), "dist",
  "mcp", "server.js")).href)`). A path with any runtime segment still fires.
- **MTC-SUP-010** reads the hook. A single `node <file>` hook that ships in the
  package is classified: does it exit early in CI or without a terminal, does it
  fetch anything, does it run anything but its own CLI, does it write outside the
  package — and into another AI tool's configuration or agent rules. A
  self-disabling hook that only runs its own CLI is `info`; one that writes another
  tool's rules into the home directory says which paths. Verified on npm 11: npm 7+
  runs install scripts without a terminal unless `--foreground-scripts` is set, so a
  terminal-gated hook does nothing on an ordinary install, and the finding says so.
- **MTC-SUP-011**: a pinned version's repository now comes from that version's own
  manifest. The packument's top level mirrors the latest release, so a scan of
  `1.3.0` borrowed the repository that `1.3.4` added and passed a release that
  declared none.

### The cap keeps what matters

The ten-findings-per-rule cap used to fill in alphabetical order, so CLI scraps
crowded out the one call that earned a server its capability level. Candidates are
now ordered — reachable from the server first, then by danger, runtime before
tooling, then path — before the cap is applied, and the last kept finding says how
many were left out (`data.omitted`).

### A file that is not read is named

A wanted source file over the per-file limit used to vanish silently, and the
report then advised "add `--online`" for a package it had downloaded. Skipped
files are now recorded (`coverage.skipped`) and named in the caveats. The per-file
limit is raised from 4 MB to 16 MB under the unchanged 24 MB total: the per-file
analyses are linear — the string-state lexer that ran once per candidate match now
runs once per file — and a 6 MB single-file bundle scans in about a second.

### Wording, fingerprints

Every capability observation now says, in its own text, that it does not lower
the trust grade; "in server code" appears only when the file is reachable from the
server, and "command injection / RCE" only for a runtime-chosen command or program.
Every finding carries `data.fingerprint` — rule, location and normalized evidence,
never a line number — so a marketplace can suppress one location instead of a
whole rule, and the suppression survives the code moving.

### Security

`@modelcontextprotocol/sdk` moves to `^1.32.1`. Versions before 1.31.0 let an MCP
server choose the authorization server that received the OAuth client's
credentials (GHSA-6qxp-vccf-f47h, published 6 Oct). The scanner uses that client
for `--login` against remote servers it does not trust. Its provider holds tokens in
memory for a single scan, which limits the exposure, but the condition the advisory
describes holds. `proxy-addr` (reached through the SDK's server transport, which the
scanner does not run) moves to 2.0.8.

### Measured movement

On the six appealed packages: `server-noonien@1.0.2` A 94 / capability high → **A
100 / minimal** (its only process call is a fixed `tailscale status --json` in a
daemon the server never imports); `standup-mr@1.0.1` A 93 / high → **A 96 /
moderate**; `@flotic/minitok@1.5.1` unchanged at A 93 / high — correctly, it runs
repository scripts — but the report now names `src/pipeline/check.js` instead of
seven CLI files; `fpl-context-mcp` and `guard-core-mcp` lose the false "no
license"; `@string-utility-belt/mcp@1.3.0` A 91 → **B 88**, because its 6 MB bundle
is now read and the repository it never declared is no longer borrowed from a later
release. On twenty widely used MCP servers, one grade moved
(`@executeautomation/playwright-mcp-server` A 93 / high → A 96 / moderate: its only
process call is `spawn('npx', ['playwright', 'install', browserType])`) and no
threat finding disappeared anywhere. 553 tests pass (87 new); the 81-server
benchmark holds at 100% precision and 100% recall.

## 1.14.0 — methodology `mcptrustchecker-1.14`

**Scores move.** One coverage input was wrong, and it was wrong in the most
expensive direction: it let targets the scanner had never successfully looked at
report a grade as if it had. Re-scan anything you have stored from an earlier
version before comparing; reports carry `score.methodologyVersion` precisely so
the two are never silently mixed.

- **A package name is no longer mistaken for a registry record.** The coverage
  axis asked whether the surface carried package metadata, and answered yes when
  `packageMeta.name` was set. That name is not something the registry returned —
  it is the string the caller typed, copied onto the surface before any lookup
  happens, and it is still there after an offline run or a `404`. So a package
  that does not exist landed in the `metadata` tier (`E_cov = 8`) instead of
  `empty` (25), and a threat-clean scan of a name nobody has ever published came
  back **92, grade A**: a clean bill of health for something that was never
  inspected, which is the exact failure the `empty` tier was introduced to stop.
  The tier now requires a fact the registry supplied — a resolved version, a
  declared dependency, or the artifact's tarball digest. The same target now
  reports **75, grade C**, with `Coverage EMPTY` and the caveat that says why.

  A declared-empty dependency array deliberately does not qualify: it is
  indistinguishable from the default an unfetched surface already carries.

  This is scored, so it changes grades, and it changes them wherever the registry
  was never successfully read. That includes the plain `mcptrustchecker <package>`
  with no `--online`: that run contacts nothing at all, so it now reports
  `Coverage EMPTY` and a **C**, where it used to claim "registry metadata only"
  and an **A** without having read a single byte from the registry. Add
  `--online` (or scan the running server) and the scan has real material to work
  with, and the grade reflects it. Stored scans that did reach the registry keep
  their version and dependencies and are unaffected: in the catalog behind
  mcptrustchecker.com this moves roughly 487 of 30,436 entries (1.6%), nearly all
  of them from B to C.

- **The remedy no longer disappears with the coverage.** "Add `--online`" was
  only ever attached to tiers that had already inspected something, so the change
  above would have removed the report's most actionable line from exactly the
  scan that inspected the least. An empty *package* surface now says that the
  registry was not contacted, that a name on its own is not a scan, and which
  flag fixes it. Empty surfaces with no registry behind them are not told to go
  fetch one.

- The other three coverage tiers were audited for the same class of mistake and
  are sound. `live` cannot be claimed without a completed handshake — a failed
  connect throws rather than producing a surface — and a server declared in a
  client config is recorded as `client-config`, not as a transport that was
  actually opened.

- Six tests pin the new boundary, including that each registry fact
  independently reaches `metadata`, that an empty dependency list does not, and
  that a nonexistent package cannot reach the A band offline. 466 tests pass;
  the 81-server benchmark holds at 100% precision and 100% recall.

## 1.13.1 — methodology `mcptrustchecker-1.13` (unchanged)

Distribution and metadata only. No rule, weight, gate or detector changed, so a
`1.13.0` score and a `1.13.1` score are directly comparable.

- The package points at its repository again. `repository` and `bugs` were
  dropped while the previous account was unavailable; npm shows the repository
  link once more, and `npm publish` can carry build provenance because the
  registry has a repository to bind the attestation to.

- Every generated report links to the repository rather than to the registry
  page. The Markdown footer and the SARIF `informationUri` both moved.

- Four transitive dependencies were advanced to patched releases after advisories
  were published against them — `fast-uri`, `hono`, `ip-address` and `qs`, all
  reached through the MCP SDK's server-side transports, which this scanner does
  not execute. `npm audit` is clean at the `high` level again.

- The bundled action is documented with a usable address, and the docs no longer
  promise a GitHub Action while showing a CLI-only example.

- A crash and a usage error are no longer the same exit code. Both used to exit
  2, so a pipeline could not tell "fix the flag you passed" from "the scanner
  itself fell over" — the first is the caller's bug, the second is ours. An
  unexpected failure now exits **3**, says so, and points at the issue tracker;
  `MCPTC_DEBUG=1` adds the stack. Usage errors keep exiting 2, and a test pins
  the documented table to the code so the two cannot drift.

- Published from CI through OIDC trusted publishing: no long-lived npm token
  exists for this package any more, and the right to publish is pinned to this
  repository and this workflow file.

## 1.13.0 — methodology `mcptrustchecker-1.13`

Verification told the truth about the wrong thing. Two fixes to the strongest
positive signal in the model, plus a corrected invariant and a hardened action.

### The vendor badge is no longer forgeable

`classifyPublisher` derived `vendor` from the package's own `repository` field
whenever npm published *any* build attestation for it — and nothing parsed the
attestation payload to learn which repository the signature actually binds to.
The consequence was a one-line forgery:

```json
{ "name": "totally-not-ms", "repository": "https://github.com/microsoft/vscode" }
```

Published with `npm publish --provenance` from the attacker's own public
workflow, that returned `{ vendor: "Microsoft", verification: "vendor" }` and the
report printed *"published under a known vendor's authority"*. Both halves are
free to obtain, and this file's own header names that exact attack as the reason
identity must rest on unforgeable signals.

Vendor now rests **solely on npm scope ownership**, which npm enforces at publish
time and a stranger cannot claim. A provenance-signed package keeps
`verification: 'source'` — an attestation does prove those bytes were built by a
workflow; it just does not prove whose. `PublisherIdentity.provenanceRepo` is
renamed `declaredRepo` so the field stops asserting more than was checked.

**Score impact: none.** `VERIFICATION_DISCOUNT.vendor` and `.source` are both 0,
so every package that moves from one tier to the other keeps its exact score and
grade. What changes is the published `verification` value and the report label.

### Provenance is read for the version actually scanned

The attestation was read off `dist-tags.latest` regardless of which version the
scan resolved, so a pinned `1.0.0` inherited a badge from a `2.0.0` published
later — the report claimed *"cryptographic build provenance ties the artifact to
its source"* about bytes whose provenance was never examined. `classifyPublisher`
now takes the resolved version and falls back to `latest` only when none was
resolved, which reproduces the previous result for every unpinned scan.

**Score impact: pinned non-latest scans only** (the CI/lockfile case), by at most
one point in either direction. A sweep that scans `latest` is byte-identical.

### The constants file contradicted itself about the clean floor

`model.ts` asserted that a threat-clean server "can never be dragged below B by
exposure alone (clean floor = 87)" thirty-five lines above a constant documented
as being sized to keep a clean-but-empty scan out of A and B. Both could not be
true; the second was correct. Enumerated over the 70 states the engine can
actually reach with zero findings, the lattice is **52 A / 13 B / 5 C**, floor
**70**. The prose is replaced by that measurement and pinned in
`test/scoring-invariants.test.ts`, so a future constant change fails a test
instead of leaving a comment to rot. No constant changed; no row moves.

### The project's own GitHub Action no longer interpolates inputs into a shell

All seven inputs were substituted into a `run:` block by the Actions expression
evaluator *before* bash parsed the line, which makes the surrounding quotes
decoration: a consumer wiring a PR title or dispatch payload into `target` got
arbitrary command execution in their runner under their `GITHUB_TOKEN`. Inputs
now arrive through `env:` and are read as quoted shell variables, arguments are
assembled in a bash array, and `test/hardening.test.ts` fails if `${{` ever
appears inside a `run:` block again. No shipped or documented usage was
affected — every example passes static literals — and no engine behaviour
changes.
