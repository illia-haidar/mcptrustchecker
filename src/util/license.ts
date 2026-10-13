/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * What license does a package DECLARE? One rule for every place a declaration
 * can live — the npm manifest, the PyPI JSON, pyproject.toml, setup.cfg — and
 * exported, so a marketplace that prints a license beside the scan report can
 * use the same answer instead of a second opinion.
 *
 * Built after MTC-SUP-012 told 1,850 PyPI packages they had "no license" while
 * the page above the report printed "MIT": PEP 639 moved the declaration to
 * `license_expression` and FORBIDS filling the legacy `license` field alongside
 * it, so every package built by setuptools ≥ 77, hatchling or uv looked
 * unlicensed to a reader of `info.license` alone.
 *
 * Returns the declared string, or null when nothing is declared. It does not
 * judge the license; that is not a security question.
 */

/** setuptools writes `UNKNOWN` when a project declares nothing; these mean "no license". */
const PLACEHOLDER = /^(?:unknown|none|n\/a|null|undefined)$/i;

/** License files that ship at a package root (their presence is a declaration too). */
export const LICENSE_FILE = /^(?:licen[cs]e|copying|unlicense)(?:[-._][\w.-]*)?$/i;

const MAX = 200;

function clean(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s || PLACEHOLDER.test(s)) return null;
  return s.slice(0, MAX);
}

/**
 * npm: a version manifest or a package.json object. `license` as a string
 * (including `SEE LICENSE IN <file>` and `UNLICENSED`, which ARE declarations),
 * the deprecated `{type, url}` object, or the deprecated `licenses` array.
 */
export function licenseFromNpmManifest(v: unknown): string | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const pick = (x: unknown): string | null => {
    if (typeof x === 'string') return clean(x);
    if (Array.isArray(x)) {
      for (const item of x) {
        const got = pick(item);
        if (got) return got;
      }
      return null;
    }
    if (x && typeof x === 'object') {
      const r = x as Record<string, unknown>;
      return clean(r.type) ?? clean(r.name);
    }
    return null;
  };
  return pick(o.license) ?? pick(o.licenses);
}

/**
 * PyPI JSON `info`: PEP 639 `license_expression` first, then the legacy free-text
 * `license` (a short name; a long value is usually the whole license text, so
 * a classifier is preferred if there is one), then the last `License :: …`
 * classifier (its last segment; a bare `OSI Approved` names nothing).
 */
export function licenseFromPypiInfo(info: unknown): string | null {
  if (!info || typeof info !== 'object') return null;
  const i = info as Record<string, unknown>;
  const strict = clean(i.license_expression);
  if (strict) return strict;
  const own = clean(i.license);
  if (own && own.length <= 60) return own;
  const classifiers = Array.isArray(i.classifiers) ? i.classifiers.filter((c): c is string => typeof c === 'string') : [];
  const lic = classifiers.filter((c) => c.startsWith('License ::'));
  if (lic.length) {
    const last = lic[lic.length - 1]!.split('::').pop()!.trim();
    if (last && !/^OSI Approved$/i.test(last)) return last.slice(0, MAX);
  }
  return own;
}

/**
 * pyproject.toml: `[project] license` as a PEP 639 string or the older
 * `{ text = "…" }` / `{ file = "…" }` table, `license-files`, or Poetry's
 * `[tool.poetry] license`.
 */
export function licenseFromPyproject(text: unknown): string | null {
  if (typeof text !== 'string') return null;
  for (const section of ['project', 'tool.poetry']) {
    const body = tomlSection(text, section);
    if (body === undefined) continue;
    const str = /^\s*license\s*=\s*(["'])([^"'\n]+)\1/m.exec(body);
    if (str) {
      const v = clean(str[2]);
      if (v) return v;
    }
    const tbl = /^\s*license\s*=\s*\{([^}\n]*)\}/m.exec(body);
    if (tbl) {
      const t = /\btext\s*=\s*(["'])([^"'\n]+)\1/.exec(tbl[1]!);
      if (t && clean(t[2])) return clean(t[2]);
      const f = /\bfile\s*=\s*(["'])([^"'\n]+)\1/.exec(tbl[1]!);
      if (f) return `SEE LICENSE IN ${f[2]}`;
    }
    const files = /^\s*license-files\s*=\s*\[([^\]]*)\]/m.exec(body);
    if (files && /["'][^"']+["']/.test(files[1]!)) return `SEE LICENSE IN ${/["']([^"']+)["']/.exec(files[1]!)![1]}`;
  }
  return null;
}

/** setup.cfg: `[metadata] license`, or a declared `license_files` / `license_file`. */
export function licenseFromSetupCfg(text: unknown): string | null {
  if (typeof text !== 'string') return null;
  const body = iniSection(text, 'metadata');
  if (body === undefined) return null;
  const lic = /^\s*license\s*=\s*([^\n]+)$/m.exec(body);
  if (lic && clean(lic[1])) return clean(lic[1]);
  const files = /^\s*license_files?\s*=\s*([^\n]*)$/m.exec(body);
  if (files) {
    const first = files[1]!.trim() || /^\s+(\S+)/m.exec(body.slice(files.index + files[0].length))?.[1];
    if (first) return `SEE LICENSE IN ${first}`;
  }
  return null;
}

function tomlSection(text: string, name: string): string | undefined {
  const re = new RegExp(`^\\[${name.replace(/\./g, '\\.')}\\]\\s*$`, 'm');
  const m = re.exec(text);
  if (!m) return undefined;
  const rest = text.slice(m.index + m[0].length);
  const next = /^\[[^\]]+\]\s*$/m.exec(rest);
  return next ? rest.slice(0, next.index) : rest;
}

function iniSection(text: string, name: string): string | undefined {
  return tomlSection(text, name);
}
