# Contributing to MCP Trust Checker

Thank you for helping make MCP safer to use. Contributions of all sizes are welcome — especially to the **threat data**, which is plain, reviewable, and high-impact.

## Ways to contribute

- **Report a false positive / false negative.** Open an issue with the offending tool metadata (redacted as needed) and the finding (or the finding you expected). These are gold.
- **Add threat data.** New injection patterns, capability keywords, protected packages, or known CVEs are just data files — see [docs/architecture.md](docs/architecture.md#add-threat-data). Include a test.
- **Add a detector.** Implement the small `Detector` interface, register it, catalogue its rules, add tests — see [docs/architecture.md](docs/architecture.md#add-a-detector).
- **Improve docs or output.**

## Development

```bash
npm install
npm run build
npm test          # node:test — all suites must pass
npm run typecheck
```

Run the tool locally without building:

```bash
npx tsx src/cli/index.ts scan test/fixtures/poisoned-server.json
```

## Ground rules

1. **Determinism is sacred.** No `Date.now()` / `Math.random()` in scoring or detectors. Same methodology version + same target must produce the same score.
2. **Bump the methodology version** (`src/version.ts`) for any change that can move a score, so historical scores remain comparable.
3. **Every finding needs a `confidence`.** Reserve `confirmed` for decoded/observed/exact-matched evidence — only `confirmed` findings can fire a hard grade gate.
4. **Catalogue new rules** in `src/data/ruleCatalog.ts` (a test enforces this).
5. **Add a test** for every behavior change. Prefer a small fixture over prose.
6. Keep the runtime dependency footprint near zero — this is a security tool.

## Pull requests

- Keep PRs focused. One detector or one data theme per PR is ideal.
- Describe the threat you're addressing and cite a source where possible.
- CI must be green (`typecheck`, `build`, `test` on Node 20/22/24).

## Reporting a security issue

See [SECURITY.md](SECURITY.md) — please do **not** open a public issue for a vulnerability in MCP Trust Checker itself.

By contributing you agree your work is licensed under the project's [MIT license](LICENSE).
