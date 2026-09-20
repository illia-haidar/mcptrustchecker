# Architecture & extending MCP Trust Checker

MCP Trust Checker is a small, dependency-light TypeScript package. The core engine has **zero runtime dependencies** (only live scanning uses the MCP SDK, loaded lazily), which keeps a *security* tool from shipping a large attack surface of its own.

## Layout

```
src/
  types.ts              the whole data model (ServerSurface, Finding, Score, …)
  version.ts            tool + methodology versions
  config.ts             config resolution & file discovery
  engine.ts             orchestrates the pipeline → ScanReport
  lockfile.ts           rug-pull (TOFU) integrity lockfile
  acquire/              turn a target into a normalized surface
    manifest.ts           static tools.json
    live.ts               sandboxed stdio / HTTP via the MCP SDK
    oauth.ts              OAuth 2.0 browser sign-in for protected endpoints (--login)
    clientConfig.ts       claude_desktop_config.json etc.
    discover.ts           find installed MCP client configs (zero-config scan)
    npm.ts                package metadata + artifact URL/hash (--online)
    archive.ts            bounded in-memory tar/gzip/zip readers (no deps, no exec)
    packageSource.ts      fetch + verify + read the published npm/PyPI source
    source.ts             read a local package directory's source files
    repo.ts               fetch a GitHub repository archive as a scan target
    toolExtract.ts        reconstruct the tool surface from published source
    publisher.ts          classify verification (vendor / provenance / repo / none)
    index.ts              resolveTargets(): pick the safest acquisition path
  detectors/            one file per stage; each emits Finding[]
    unicode.ts injection.ts capability.ts toxicFlow.ts flowGraph.ts
    source.ts             implementation-level analysis (the MTC-SRC-* family)
    collision.ts supplyChain.ts posture.ts meta.ts
    index.ts              the detector registry
  scoring/
    model.ts              all weights / caps / gates (the auditable constants)
    capability.ts         capability level from capability findings
    coverage.ts           how much of the target the scan could read
    index.ts              computeScore()
  data/                 bundled, version-pinned threat intelligence (plain data)
    unicode.ts injectionPatterns.ts semanticClasses.ts capabilityLexicon.ts
    sourcePatterns.ts protectedPackages.ts knownCves.ts confusables.ts
    ruleCatalog.ts
  report/               terminal | json | sarif | markdown | badge
  util/                 text extraction, decode ladder, distance, hashing,
                        capabilities, transport headers, ansi
  policy.ts             policy-as-code gates (minGrade / denyRules / maxCapability)
  publish.ts            `mcptrustchecker publish` — submit to the Trust Registry
  cli/index.ts          the `mcptrustchecker` binary (node:util parseArgs, no deps)
  index.ts              the public library API
test/                   node:test suites + fixtures (incl. a real mock MCP server)
```

## Data flow

```
resolveTargets(target)  →  ServerSurface
        │
        ▼
   scanSurface(surface, { config, lockfile })
        │  extractCapabilities()  (shared, computed once)
        │  for each detector: run(ctx) → Finding[]
        │  analyzeToxicFlows(ctx) → ToxicFlow[] + Finding[]
        │  checkIntegrity(surface, lockfile) → drift Finding?
        │  filter (disabled / allowlist / dedupe) → computeScore()
        ▼
   ScanReport  →  renderTerminal / renderJson / renderSarif / renderMarkdown / renderBadge
```

The engine ([`src/engine.ts`](../src/engine.ts)) does no I/O of its own beyond what the caller passes in (the lockfile), so it is trivially testable and deterministic.

## Add a detector

A detector implements one interface ([`src/types.ts`](../src/types.ts)):

```ts
import type { Detector } from '../types.js';

export const myDetector: Detector = {
  id: 'my-detector',
  stage: 9,
  title: 'My check',
  run(ctx) {
    // ctx.surface, ctx.config, ctx.capabilities are available
    return [
      {
        ruleId: 'MTC-XYZ-001',
        title: '…',
        category: 'hygiene',
        severity: 'low',
        confidence: 'strong',
        description: '…',
        remediation: '…',
        location: { kind: 'tool', name: '…' },
      },
    ];
  },
};
```

Then:
1. register it in [`src/detectors/index.ts`](../src/detectors/index.ts);
2. add its rule ids to [`src/data/ruleCatalog.ts`](../src/data/ruleCatalog.ts) (a test asserts every emitted rule id is catalogued);
3. add a test under `test/`.

## Add threat data

Most improvements are *data*, not code — and they're the most valuable contributions:

- **Injection patterns** → [`src/data/injectionPatterns.ts`](../src/data/injectionPatterns.ts)
- **Capability keywords** → [`src/data/capabilityLexicon.ts`](../src/data/capabilityLexicon.ts)
- **Protected package list** → [`src/data/protectedPackages.ts`](../src/data/protectedPackages.ts)
- **Known CVEs** → [`src/data/knownCves.ts`](../src/data/knownCves.ts)
- **Unicode ranges** → [`src/data/unicode.ts`](../src/data/unicode.ts)

Add a fixture/test alongside any data change so behavior is pinned.

## Determinism rules for contributors

- No `Date.now()` / `Math.random()` inside scoring or detectors — reports must be reproducible. (The CLI stamps `scannedAt`; the engine omits it when not provided.)
- Any change that can move a score bumps `METHODOLOGY_VERSION` in [`src/version.ts`](../src/version.ts).
- Findings must carry a `confidence`; reserve `confirmed` for things that are decoded/observed/exact-matched, because only `confirmed` findings can fire a grade gate.
- **The score is monotone, and that is not a convention — it is tested.** Adding a
  finding, or making one more severe or more certain, must never raise the score
  or improve the grade. `test/scoring-invariants.test.ts` asserts both directions
  over 40 000 random finding sets, and `test/evasion.test.ts` asserts the detector-
  level form (hiding a payload never beats shipping it in the clear). Both have
  caught real regressions: the diminishing series was once keyed by rule while the
  cap is keyed by category, which made a finding in an already-capped category
  free *and* demoted a same-rule finding elsewhere — so adding a finding raised the
  score. If you touch `src/scoring/`, assume the invariant is the specification.
- **The scanned surface must equal the model's view.** The model receives the whole
  tool definition, so every string in it is an instruction channel — both schemas,
  every composition branch (`oneOf`/`anyOf`/`allOf`/`$defs`/…), the value channels,
  the annotations, and the prompt/resource entries. `test/surface-coverage.test.ts`
  pins the collector field by field. Adding a field to `ServerSurface` without
  adding it to [`collectTextFields`](../src/util/text.ts) is a silent bypass: the
  scan returns A and reports nothing at all.

## Build & test

```bash
npm install
npm run build       # tsc → dist/ (ESM + .d.ts)
npm test            # node:test (460 tests, incl. a live SDK integration test)
npm run typecheck   # tsc --noEmit
```
