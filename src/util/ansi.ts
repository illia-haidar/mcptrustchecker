/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Tiny zero-dependency ANSI helper. Respects NO_COLOR and non-TTY output.
 * A security tool should not pull a coloring library into its dependency tree.
 */

const enabled = (() => {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(process.stdout.isTTY);
})();

function wrap(open: number, close: number) {
  return (s: string): string => (enabled ? `[${open}m${s}[${close}m` : s);
}

export const c = {
  enabled,
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  underline: wrap(4, 24),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
  white: wrap(37, 39),
  bgRed: wrap(41, 49),
  bgGreen: wrap(42, 49),
  bgYellow: wrap(43, 49),
};

/** Visible length of a string, ignoring ANSI escapes. */
export function visibleLength(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\[[0-9;]*m/g, '').length;
}

/** Pad a (possibly colored) string to a visible width. */
export function padVisible(s: string, width: number): string {
  const pad = Math.max(0, width - visibleLength(s));
  return s + ' '.repeat(pad);
}
