---
name: False positive / false negative
about: A finding you believe is wrong, or an attack MCP Trust Checker missed
title: '[FP/FN] '
labels: detection
---

**Type**
- [ ] False positive (flagged something benign)
- [ ] False negative (missed a real issue)

**Rule id(s)**
<!-- e.g. MTC-FLOW-002 -->

**Minimal reproduction**
<!-- The smallest tool metadata / manifest that reproduces it. Redact anything sensitive. -->
```json
{
  "tools": [
    { "name": "...", "description": "..." }
  ]
}
```

**What MCP Trust Checker reported**
<!-- Paste the finding, or `mcptrustchecker scan ... --json` output. -->

**What you expected**

**Version**
<!-- `mcptrustchecker version` -->
