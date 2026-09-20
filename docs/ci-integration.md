# CI integration

MCP Trust Checker is CI-native: SARIF 2.1.0 for GitHub's Security tab, exit codes for gating, and Markdown for PR comments.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | scan completed; gates passed |
| `1` | a gate failed (`--fail-under`, `--min-grade`, or `diff` drift) |
| `2` | usage error — a bad flag, an unreadable target, a refused host |
| `3` | internal error — the scanner itself failed. Set `MCPTC_DEBUG=1` for the stack, and please report it |

```bash
mcptrustchecker scan ./tools.json --min-grade B        # exit 1 if worse than B
mcptrustchecker scan ./tools.json --fail-under 80       # exit 1 if score < 80
mcptrustchecker diff ./tools.json                        # exit 1 if the surface drifted since pin
```

## GitHub Action (bundled)

```yaml
# .github/workflows/mcptrustchecker.yml
name: MCP Trust Checker
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write     # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: illia-haidar/mcptrustchecker@main
        with:
          target: ./tools.json
          min-grade: B
          sarif: true            # uploads to the Security tab
```

The action pins nothing for you: `@main` follows the default branch. Pin a commit
SHA instead if you want a build to stay reproducible after the action changes.

See [`action.yml`](../action.yml) for all inputs. If you would rather not depend on
the action at all, the next section does the same work with the CLI directly.

## Raw CLI + SARIF upload

If you prefer to drive it yourself:

```yaml
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx mcptrustchecker scan ./tools.json --sarif -o mcptrustchecker.sarif --min-grade B
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: mcptrustchecker.sarif }
```

## PR comment with the Markdown report

```yaml
      - run: npx mcptrustchecker scan ./tools.json --md -o report.md
      - uses: marocchino/sticky-pull-request-comment@v2
        with: { path: report.md }
```

## Rug-pull gate for a config you depend on

Commit `mcptrustchecker.lock`, then fail the build if any server's surface changed:

```yaml
      - run: npx mcptrustchecker diff ./mcp.config.json     # exit 1 on drift
```

## Trust badge

Emit a shields.io endpoint document and host it (e.g. commit to a `gh-pages` branch or a gist):

```bash
mcptrustchecker scan ./tools.json --badge -o badge.json
```

```markdown
![MCP Trust](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/gh-pages/badge.json)
```
