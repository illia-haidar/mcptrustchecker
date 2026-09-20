# Security Policy

## Scope

MCP Trust Checker is a security tool, so two kinds of issues matter:

1. **A vulnerability in MCP Trust Checker itself** — e.g. a way to make the scanner execute untrusted code during acquisition, a ReDoS in a pattern, or a path that leaks environment secrets. Please report these privately.
2. **A detection gap or false result** — a real attack MCP Trust Checker misses, or a benign server it wrongly flags. These are fine to file as public issues and are very welcome.

## Reporting a vulnerability

Please report vulnerabilities in MCP Trust Checker **privately** via GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository (Security → Report a vulnerability), rather than opening a public issue.

Include: affected version, a minimal reproduction (a crafted manifest or config is ideal), and the impact. We aim to acknowledge within a few days.

If Private Vulnerability Reporting is unavailable, email **support@mcptrustchecker.com**.

## Safe-by-default acquisition

Scanning an MCP server is inherently risky — a stdio config can run arbitrary commands. MCP Trust Checker mitigates this by default:

- stdio executables are **allow-listed** (`npx, uvx, python, python3, node, docker, deno`); others are refused without `--allow-any-command`.
- child processes receive a **minimal environment** (never your full `process.env`), a controlled `cwd`, captured stderr, and aggressive timeouts.
- servers found in a client config are **not spawned** unless you pass `--run`.
- HTTP targets are scheme-validated, and the host is checked **against its resolved
  addresses** before connecting — private, loopback, link-local, CGNAT, multicast and
  reserved ranges are refused, including a public name that resolves inward (DNS
  rebinding). Every redirect hop and every OAuth discovery/token host is re-checked,
  because those are chosen by the target server’s own metadata.

- **Repository archives are fetched, never cloned.** `owner/repo` downloads GitHub's
  own archive over https from pinned hosts (`api.github.com`, `codeload.github.com`),
  size-capped and unpacked in memory by the same bounded reader used for registry
  artifacts. No git binary runs, nothing is written to disk, no hook executes.

Even so: **only scan servers you have some reason to run.** Prefer scanning a static `tools.json` manifest when you just want to inspect metadata.

## Known limitations (threat-model boundaries)

Documented honestly rather than hidden:

- **`--run` against a live HTTP endpoint follows redirects with re-validation** (each hop's host is re-checked by the SSRF guard). SSE fallback relies on the client's `EventSource`; if it does not honor the injected fetch, prefer `--allowed-hosts` to pin the destination.
- **A malicious `--run` server that floods stdout with no newline** can grow parent memory (buffered by the MCP SDK). Connect/request timeouts bound latency, not bytes; scan untrusted stdio servers in a constrained environment.
- **Version-range/`latest` package specs are not evaluated for CVEs** — only a concrete pinned version is matched, to avoid false positives.
- **The SSRF guard resolves the host, but cannot pin the connection.** A name that fails to resolve is not treated as blocked — the connect would fail anyway, and failing closed would break split-horizon DNS. And because the check runs before the socket opens, a sub-TTL rebind between the lookup and the connect stays theoretically possible; pinning the resolved address needs a custom dispatcher. The lookup itself is time-boxed so a black-holing nameserver cannot stall a scan.
- **Publisher identity proves authorization, not authorship.** A `vendor` tier means the package sits in an npm scope whose publish rights npm enforces. A `source` tier means the registry publishes a build attestation for the scanned artifact — it proves those bytes were produced by a workflow, **not** which repository the signature binds to, because the attestation subject is not fetched or parsed. The repository shown alongside it is the one the package *declares*. Until 1.13.0 the `vendor` badge was derived from that declared field, so a stranger could claim it with one line of `package.json` plus `--provenance`; see the 1.13.0 changelog entry.
- **The GitHub Action passes inputs through `env:`, never into a `run:` block.** Before 1.13.0 all seven inputs were interpolated by the Actions expression evaluator ahead of bash, so a caller who wired untrusted text (a PR title, a dispatch payload) into `target` could execute commands in their own runner. No shipped or documented usage was affected — every example passes static literals — but an action input is a contract whose bindings the author does not control, so the boundary is now enforced by a test rather than by convention. `extra-args` remains intentionally unquoted: it is documented as raw CLI arguments and must word-split, which splits and globs but does not perform command substitution.
- Determinism and the SSRF guard are covered by regression tests; the acquisition sandbox is defense-in-depth, not a substitute for isolating truly hostile servers.

## Supported versions

Security fixes land on the **latest released version**. There is no back-porting to older
minor versions — upgrade to the newest `1.x` to receive them.
