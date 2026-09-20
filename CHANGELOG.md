# Changelog

All notable changes to `mcptrustchecker` are recorded here. The scanner is
deterministic: the **methodology version** is bumped whenever a change could
move a score, so a grade is always reproducible against the version that
produced it.

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
