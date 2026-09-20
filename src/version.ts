/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/** Package version. Keep in sync with package.json. */
export const TOOL_VERSION = '1.13.0';

/**
 * Methodology version. Bump this whenever scoring weights, gates, rule
 * severities, or bundled threat data change in a way that could move a score.
 * The reproducibility contract is: same methodology version + same target ⇒
 * identical Trust Score.
 */
export const METHODOLOGY_VERSION = 'mcptrustchecker-1.13';

/** Version of the bundled Unicode/confusables tables. */
export const UNICODE_DATA_VERSION = '17.0.0';

export const TOOL_NAME = 'mcptrustchecker';
