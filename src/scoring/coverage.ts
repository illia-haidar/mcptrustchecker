/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Coverage — a third, honest axis alongside Trust (grade) and Capability (blast
 * radius). It states how much of the target the scan could actually inspect, so
 * a clean grade from a shallow scan is never mistaken for a thorough one.
 *
 * Purely descriptive and deterministic: derived only from what the acquired
 * surface contains. It never changes the score — it explains the score's reach.
 */

import type { Coverage, CoverageLevel, ServerSurface, Verification } from '../types.js';
import { SOURCE_LIMITS } from '../acquire/source.js';

const SOURCE_FILE_LIMIT_MB = SOURCE_LIMITS.maxFileBytes / (1024 * 1024);

/**
 * Derive the coverage descriptor from an acquired surface.
 *
 * `verification` is optional context: when it is `unknown` on a package target,
 * provenance was not checked (an offline scan), so the verification term was not
 * applied — an honest caveat records that, matching how offline and online scans
 * deliberately differ.
 */
export function computeCoverage(surface: ServerSurface, verification?: Verification): Coverage {
  const toolSurface =
    (Array.isArray(surface.tools) && surface.tools.length > 0) ||
    (Array.isArray(surface.prompts) && surface.prompts.length > 0) ||
    (Array.isArray(surface.resources) && surface.resources.length > 0);
  const implementationSource = Array.isArray(surface.sourceFiles) && surface.sourceFiles.length > 0;
  const m = surface.packageMeta;
  // `m.name` is NOT evidence. It is the target string the caller typed, echoed
  // back — present even when the registry was never reached, or reached and
  // answered 404. Counting it as metadata meant an offline scan of a package
  // that does not exist reported coverage `metadata` (−8) instead of `empty`
  // (−25), and so scored 92/A: a clean bill of health for something the scanner
  // never looked at, which is exactly what COVERAGE_HONESTY.empty exists to
  // prevent. The other three are facts the registry supplied.
  const packageMetadata = Boolean(
    m && (m.version || (Array.isArray(m.dependencies) && m.dependencies.length > 0) || m.tarballSha256),
  );
  const liveTransport = surface.source?.kind === 'stdio' || surface.source?.kind === 'http';
  // Source files that exist but were not read (a size limit). Reported by name:
  // "add --online" is the wrong advice for a package whose artifact WAS fetched.
  const skipped = Array.isArray(surface.packageLayout?.skipped) ? surface.packageLayout!.skipped : [];
  const artifactRead = Boolean(m?.tarballSha256) || Boolean(surface.packageLayout);

  // Richest signal wins for the headline label; `inputs` keeps the full detail.
  let level: CoverageLevel;
  if (liveTransport) level = 'live';
  else if (implementationSource) level = 'source';
  else if (toolSurface) level = 'manifest';
  else if (packageMetadata) level = 'metadata';
  else level = 'empty';

  const caveats: string[] = [];
  const conditional = conditionalGroups(surface);
  const conditionalCount = conditional.reduce((n, g) => n + g.tools.length, 0);
  if (level === 'empty') {
    caveats.push('Nothing scannable was found on this target — an empty surface is not a clean bill of health.');
    // A package name on its own is the commonest way to land here, and it is
    // the one case with an obvious remedy: nothing was fetched, so say that
    // plainly and name the flag that fixes it. Without this the most
    // actionable advice the report has would be missing from precisely the
    // scan that inspected the least.
    if (surface.source?.kind === 'package' && !artifactRead) {
      caveats.push(
        'The registry was not contacted, so not even the package record was read — the name alone is not a scan. ' +
          'Add --online to fetch the published package and analyze its source, or scan the running server: ' +
          '--command "npx -y <package>".',
      );
    }
  } else {
    if (!toolSurface) {
      caveats.push(
        'No tools were enumerated, so prompt-injection, capability and toxic-flow analysis had no tool surface to inspect. ' +
          'To grade a package’s real runtime tools, scan the running server: --command "npx -y <package>".',
      );
    } else if (surface.toolProvenance === 'static') {
      caveats.push(
        `Tools were statically extracted from the published source (${surface.tools.length} recovered), not enumerated from a ` +
          'running server. Tool-poisoning, Unicode-smuggling, capability and toxic-flow analysis ran on this inferred surface, ' +
          'but a mis-parsed registration could be missed or mis-attributed, so tool-derived findings are capped below ' +
          '“confirmed”. To grade the real runtime surface, scan the running server: --command "npx -y <package>".',
      );
      if (surface.staticToolsTruncated?.length) {
        caveats.push(
          `Tool recovery stopped early in ${surface.staticToolsTruncated.slice(0, 3).map((f) => `\`${f}\``).join(', ')}` +
            `${surface.staticToolsTruncated.length > 3 ? ` and ${surface.staticToolsTruncated.length - 3} more` : ''} — the file registers more ` +
            'tools than the scanner reads in one file, so some may be missing from this surface.',
        );
      }
      for (const g of conditional) {
        const always = surface.tools.length - conditionalCount;
        const when = g.kind === 'if' ? `when \`${g.condition}\` holds` : `when \`${g.condition}\` is false`;
        // The if and the else of one statement: one of the two groups is always registered.
        const partner = conditional.some((o) => o !== g && o.file === g.file && o.line === g.line && o.condition === g.condition && (o.kind === 'if') !== (g.kind === 'if'));
        const exposes = partner
          ? 'the other branch of the same condition registers the rest'
          : `a server started without that configuration exposes ${always === 0 ? 'none of the recovered tools' : `only the other ${always}`}`;
        caveats.push(
          `${g.tools.length} of the ${surface.tools.length} recovered tools are registered only ${when} (${g.file}:${g.line}) — ` +
            `typically when a key or option is configured. They are part of the server's surface and were analysed; ${exposes}.`,
        );
      }
    }
    if (!implementationSource && !liveTransport) {
      caveats.push(
        artifactRead && skipped.length
          ? 'The implementation source was not read — the package was fetched, but its code is in files over the per-file size limit (listed below).'
          : packageMetadata && !artifactRead
            ? 'The implementation source was not read — this reflects registry metadata only. Add --online to fetch and analyze the published package source.'
            : packageMetadata
              ? 'The implementation source was not read — the published package was fetched but contains no source files the scanner reads.'
              : 'The implementation source was not read — this reflects the declared tool metadata only.',
      );
    }
    // Provenance (npm/PyPI attestations) can only be checked with network
    // access. When it was not, say so and note the verification term was not
    // applied — an honest scan never lets an unchecked signal read as clean.
    if (packageMetadata && verification === 'unknown') {
      caveats.push(
        'Publisher verification was not checked (provenance requires --online); the verification term was not applied to the score.',
      );
    }
  }

  for (const k of skipped.slice(0, 5)) {
    const mb = k.bytes / (1024 * 1024);
    const size = mb >= 1 ? `${mb.toFixed(1)} MB` : `${Math.max(1, Math.round(k.bytes / 1024))} KB`;
    const why =
      k.reason === 'over-per-file-limit'
        ? `over the ${Math.round(SOURCE_FILE_LIMIT_MB)} MB per-file limit`
        : k.reason === 'over-total-limit'
          ? 'over the total source-size budget'
          : 'over the file-count budget';
    caveats.push(`\`${k.path}\` (${size}) was not read: ${why}.`);
  }
  if (skipped.length > 5) caveats.push(`…and ${skipped.length - 5} more file(s) were not read for the same reasons.`);

  return {
    level,
    inputs: { toolSurface, implementationSource, packageMetadata, liveTransport },
    caveats,
    ...(skipped.length ? { skipped: skipped.map((k) => ({ ...k })) } : {}),
    ...(conditional.length ? { conditionalTools: conditional } : {}),
  };
}

/** Statically recovered tools registered behind a condition, grouped by that condition. */
function conditionalGroups(surface: ServerSurface): NonNullable<Coverage['conditionalTools']> {
  if (surface.toolProvenance !== 'static' || !surface.staticTools) return [];
  const groups = new Map<string, NonNullable<Coverage['conditionalTools']>[number]>();
  for (const t of surface.tools) {
    const o = typeof t?.name === 'string' && Object.hasOwn(surface.staticTools, t.name) ? surface.staticTools[t.name] : undefined;
    const c = o?.condition;
    if (!o || !c) continue;
    const key = `${o.file}\u0000${c.line}\u0000${c.kind}\u0000${c.expr}`;
    const g = groups.get(key) ?? { condition: c.expr, kind: c.kind, file: o.file, line: c.line, tools: [] };
    g.tools.push(t.name);
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
}

/** A short human label for a coverage level (terminal/markdown headline). */
export function coverageLabel(level: CoverageLevel): string {
  switch (level) {
    case 'live':
      return 'running server — real runtime tools';
    case 'source':
      return 'published/local source read';
    case 'manifest':
      return 'static tool list only — no source';
    case 'metadata':
      return 'registry metadata only — no tools, no source';
    case 'empty':
      return 'nothing inspected';
  }
}
