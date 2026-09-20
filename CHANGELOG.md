# Changelog

All notable changes to `mcptrustchecker` are recorded here. The scanner is
deterministic: the **methodology version** is bumped whenever a change could
move a score, so a grade is always reproducible against the version that
produced it.

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
