# Changelog

All notable changes to `mcptrustchecker` are recorded here. The scanner is
deterministic: the **methodology version** is bumped whenever a change could
move a score, so a grade is always reproducible against the version that
produced it.

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
