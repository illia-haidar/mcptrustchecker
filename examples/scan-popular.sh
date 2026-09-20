#!/usr/bin/env bash
# Scan the top-10 popular free MCP servers individually with MCP Trust Checker and print
# a one-line summary per server. Each server is scanned on its own (no
# cross-server collision noise), so the grades reflect each server in isolation.
#
# Usage:  ./examples/scan-popular.sh
# Needs:  the `mcptrustchecker` command on PATH (npm i -g mcptrustchecker, or `npm link` in the repo).
# Note:   the first run downloads packages via npx and some may time out; just
#         run it again (now cached). Dummy keys only let servers boot to list tools.

set -uo pipefail

row() { # label  "npx command"  [--env K=V ...]
  local label="$1" cmd="$2"; shift 2
  local line
  line=$(mcptrustchecker scan --command "$cmd" "$@" --quiet --no-pager 2>/dev/null | tail -1)
  [ -z "$line" ] && line="(no connection — run again to use the npx cache)"
  printf "  %-22s %s\n" "$label" "${line#*: }"
}

echo "MCP Trust Checker · top-10 popular MCP servers (each scanned in isolation)"
echo "----------------------------------------------------------------"
row "memory"              "npx -y @modelcontextprotocol/server-memory"
row "sequential-thinking" "npx -y @modelcontextprotocol/server-sequential-thinking"
row "filesystem"          "npx -y @modelcontextprotocol/server-filesystem /tmp"
row "everything"          "npx -y @modelcontextprotocol/server-everything"
row "context7"            "npx -y @upstash/context7-mcp"
row "github"              "npx -y @modelcontextprotocol/server-github"  --env GITHUB_PERSONAL_ACCESS_TOKEN=dummy
row "tavily"              "npx -y tavily-mcp"                            --env TAVILY_API_KEY=dummy
row "firecrawl"           "npx -y firecrawl-mcp"                         --env FIRECRAWL_API_KEY=dummy
row "playwright"          "npx -y @playwright/mcp"                       --env PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
row "desktop-commander"   "npx -y @wonderwhy-er/desktop-commander"
echo "----------------------------------------------------------------"
echo "Deep-dive any one:  mcptrustchecker scan --command \"npx -y <pkg>\" [--env K=V]"
