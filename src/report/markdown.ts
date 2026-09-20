/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Markdown report — for PR comments, job summaries, and README embeds.
 */

import type { ScanReport, Severity } from '../types.js';
import { ALL_CATEGORIES } from '../scoring/model.js';
import { coverageLabel } from '../scoring/coverage.js';

const COVERAGE_EMOJI = { live: '🟢', source: '🟢', manifest: '🟡', metadata: '🟡', empty: '🔴' } as const;

const SEV_EMOJI: Record<Severity, string> = {
  critical: '🟥',
  high: '🟧',
  medium: '🟨',
  low: '🟦',
  info: '⬜',
};

function gradeEmoji(grade: string): string {
  return { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴' }[grade] ?? '⚪';
}

export function renderMarkdown(report: ScanReport): string {
  const s = report.score;
  const md: string[] = [];

  const capEmoji = { minimal: '🟢', moderate: '🔵', high: '🟠', critical: '🔴' }[report.capabilityProfile.level] ?? '⚪';
  md.push(`## ${gradeEmoji(s.grade)} MCP Trust Checker — Trust ${s.grade} (${s.score}/100) · ${capEmoji} Capability ${report.capabilityProfile.level.toUpperCase()}`);
  md.push('');
  md.push(`> **Trust** = malice/negligence signals (drives the grade) · **Capability** = blast radius if the model is manipulated (not a verdict).`);
  if (report.capabilityProfile.reasons.length) {
    md.push('>');
    md.push(`> Capability: ${report.capabilityProfile.reasons.join('; ')}.`);
  }
  md.push('');
  md.push(
    `**Target:** \`${mdInline(report.target.id)}\` (${report.target.source.kind}) · ` +
      `**Surface:** ${report.stats.tools} tools, ${report.stats.prompts} prompts, ${report.stats.resources} resources · ` +
      `**Methodology:** \`${s.methodologyVersion}\``,
  );
  md.push('');

  const cov = report.coverage;
  md.push(`**Coverage:** ${COVERAGE_EMOJI[cov.level] ?? '⚪'} ${cov.level.toUpperCase()} — ${coverageLabel(cov.level)}`);
  if (cov.caveats.length) {
    md.push('');
    md.push('> [!NOTE]');
    md.push('> This grade reflects only what was inspected:');
    for (const note of cov.caveats) md.push(`> - ${mdInline(note)}`);
  }
  md.push('');

  const bs = report.stats.findingsBySeverity;
  md.push(
    `**Findings:** ${bs.critical} critical · ${bs.high} high · ${bs.medium} medium · ${bs.low} low · ${bs.info} info`,
  );
  md.push('');

  if (s.gatesFired.length) {
    md.push('> [!WARNING]');
    for (const g of s.gatesFired) md.push(`> ${g}`);
    md.push('');
  }

  const cats = ALL_CATEGORIES.filter((c) => s.categorySubtotals[c] > 0);
  if (cats.length) {
    md.push('| Category | Penalty |');
    md.push('| --- | ---: |');
    for (const c of cats) md.push(`| ${c} | -${s.categorySubtotals[c]} |`);
    md.push('');
  }

  // Client-adoption-risk: how the threat score becomes the client score, itemised.
  const clientTerms = s.vector.filter((v) => v.kind === 'client');
  if (clientTerms.length) {
    md.push('### Client-adoption-risk');
    md.push('');
    md.push('| Term | Level | Points |');
    md.push('| --- | --- | ---: |');
    md.push(`| threat score | — | ${s.threatScore} |`);
    for (const t of clientTerms) {
      if (t.kind !== 'client') continue;
      md.push(`| ${t.term} | ${t.level} | ${t.appliedPenalty > 0 ? `-${t.appliedPenalty}` : '0'} |`);
    }
    md.push(`| **client score** | — | **${s.score}** |`);
    md.push('');
  }

  if (report.toxicFlows.length) {
    md.push('### Toxic flows');
    md.push('');
    for (const f of report.toxicFlows) {
      md.push(`- ${SEV_EMOJI[f.severity]} **${f.severity}** — ${mdInline(f.description)}`);
    }
    md.push('');
  }

  if (report.integrity && report.integrity.status === 'drift') {
    md.push('### ⚠️ Integrity drift (possible rug pull)');
    md.push('');
    for (const ch of report.integrity.changes ?? []) md.push(`- ${mdInline(ch.detail)}`);
    md.push('');
  }

  if (report.integrity && report.integrity.status === 'stale-pin') {
    md.push('### Integrity not evaluated — the pin predates this methodology');
    md.push('');
    md.push(
      `- Pinned under \`${mdInline(report.integrity.pinnedMethodologyVersion ?? 'an older version')}\`; ` +
        'the fingerprints are not comparable. Re-pin with `mcptrustchecker pin` to restore drift detection.',
    );
    for (const ch of report.integrity.changes ?? []) md.push(`- ${mdInline(ch.detail)}`);
    md.push('');
  }

  if (report.findings.length) {
    md.push('### Findings');
    md.push('');
    md.push('| Sev | Rule | Finding | Location |');
    md.push('| --- | --- | --- | --- |');
    for (const f of report.findings) {
      const loc = f.location
        ? `${f.location.kind}${f.location.name ? ` \`${cell(f.location.name)}\`` : ''}`
        : '';
      md.push(`| ${SEV_EMOJI[f.severity]} ${f.severity} | \`${cell(f.ruleId)}\` | ${cell(f.title)} | ${loc} |`);
    }
    md.push('');
  } else {
    md.push('_No findings. This surface looks clean by the current ruleset._');
    md.push('');
  }

  md.push(`<sub>Scanned with [MCP Trust Checker](https://github.com/illia-haidar/mcptrustchecker) ${report.tool.version} · digest \`${report.surfaceDigest.slice(0, 12)}…\`</sub>`);
  return md.join('\n');
}


/**
 * Make an untrusted string safe for inline Markdown prose (list items, code
 * spans). Kills newlines/control (so it can't break out into a forged heading),
 * neutralizes code spans and raw HTML, and escapes link brackets (so a
 * `[approve](evil)` phishing link can't render). Tool names/descriptions reach
 * these paths unfiltered, so this is a security boundary for PR-comment output.
 */
function mdInline(s: unknown): string {
  return String(s ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ')
    .replace(/`/g, '‘')
    .replace(/[<>]/g, '')
    .replace(/[[\]]/g, '\\$&')
    .trim();
}

/** Make an untrusted string safe for a single Markdown table cell. */
function cell(s: string): string {
  return String(s)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ') // newlines & control chars break the row
    .replace(/\|/g, '\\|')
    .replace(/`/g, '‘')
    .replace(/[<>]/g, '')
    .replace(/[[\]]/g, '\\$&') // link brackets → no phishing link renders in a cell
    .trim();
}
