/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Human-facing terminal report. Zero-dependency ANSI, degrades to plain text
 * when piped or under NO_COLOR.
 */

import type { CapabilityLevel, CoverageLevel, Finding, Grade, ScanReport, Severity } from '../types.js';
import { coverageLabel } from '../scoring/coverage.js';
import { c, padVisible } from '../util/ansi.js';
import { ALL_CATEGORIES, isCapabilityRule } from '../scoring/model.js';

const SEV_LABEL: Record<Severity, (s: string) => string> = {
  critical: (s) => c.bold(c.red(s)),
  high: (s) => c.red(s),
  medium: (s) => c.yellow(s),
  low: (s) => c.cyan(s),
  info: (s) => c.gray(s),
};

const SEV_TAG: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED ',
  low: 'LOW ',
  info: 'INFO',
};

function gradeColor(grade: Grade, s: string): string {
  switch (grade) {
    case 'A':
      return c.bold(c.green(s));
    case 'B':
      return c.bold(c.green(s));
    case 'C':
      return c.bold(c.yellow(s));
    case 'D':
      return c.bold(c.yellow(s));
    case 'F':
      return c.bold(c.red(s));
  }
}

function capColor(level: CapabilityLevel, s: string): string {
  switch (level) {
    case 'minimal':
      return c.green(s);
    case 'moderate':
      return c.cyan(s);
    case 'high':
      return c.yellow(s);
    case 'critical':
      return c.bold(c.red(s));
  }
}

/** A deep scan (live/source) reads normal; a shallow one (manifest/metadata/empty) is a caution. */
function coverageColor(level: CoverageLevel, s: string): string {
  if (level === 'live' || level === 'source') return c.green(s);
  if (level === 'empty') return c.red(s);
  return c.yellow(s);
}

/** Usable terminal width (clamped), for wrapping detailed descriptions. */
const TERM = Math.max(64, Math.min(process.stdout.columns || 100, 118));

function line(char = '─', width = Math.min(TERM, 72)): string {
  return c.gray(char.repeat(width));
}

/** Word-wrap a string to a width, preserving explicit newlines. */
function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  for (const para of text.split('\n')) {
    const words = para.replace(/\s+/g, ' ').trim().split(' ');
    let cur = '';
    for (const w of words) {
      if (cur && (cur + ' ' + w).length > width) {
        out.push(cur);
        cur = w;
      } else {
        cur = cur ? `${cur} ${w}` : w;
      }
    }
    out.push(cur);
  }
  return out;
}

const LABEL_W = 9;

/** A labeled, wrapped field with a hanging indent aligned under the text column. */
function labeled(label: string, text: string, color: (s: string) => string): string {
  const head = `   ${c.gray(padVisible(label, LABEL_W))}`;
  const cont = ' '.repeat(3 + LABEL_W);
  const lines = wrap(text, TERM - 3 - LABEL_W);
  return lines.map((ln, i) => (i === 0 ? head : cont) + color(ln)).join('\n');
}

export function renderTerminal(report: ScanReport, opts: { details?: boolean } = {}): string {
  const out: string[] = [];
  const { score } = report;
  const threatFindings = report.findings.filter((f) => !isCapabilityRule(f.ruleId) && f.severity !== 'info');
  const capabilityFindings = report.findings.filter((f) => isCapabilityRule(f.ruleId));

  out.push('');
  out.push(`${c.bold('MCP Trust Checker')} ${c.gray('· MCP security scan')}`);
  out.push(line());
  out.push(`${c.gray('Target ')} ${clean(report.target.id)}  ${c.gray(`(${report.target.source.kind})`)}`);
  if (report.target.server?.name) {
    out.push(
      `${c.gray('Server ')} ${clean(report.target.server.name)}${report.target.server.version ? ` v${clean(report.target.server.version)}` : ''}`,
    );
  }
  out.push(
    `${c.gray('Surface')} ${report.stats.tools} tools · ${report.stats.prompts} prompts · ${report.stats.resources} resources`,
  );
  out.push('');

  // Grade badge (TRUST) + capability level (BLAST RADIUS) — two axes.
  const badge = `  GRADE  ${score.grade}  `;
  const cap = report.capabilityProfile;
  out.push(`   ${gradeColor(score.grade, `╭${'─'.repeat(badge.length)}╮`)}`);
  out.push(`   ${gradeColor(score.grade, `│${badge}│`)}   ${c.bold(`Trust Score ${score.score}/100`)}   ${c.gray(`(client adoption risk · threat ${score.threatScore})`)}`);
  out.push(`   ${gradeColor(score.grade, `╰${'─'.repeat(badge.length)}╯`)}   ${capColor(cap.level, `Capability ${cap.level.toUpperCase()}`)}   ${c.gray('(blast radius)')}`);
  const cov = report.coverage;
  // Align under "Capability": 3 leading spaces + the 2 box borders + badge width + 3-space gap.
  const pad = ' '.repeat(badge.length + 8);
  out.push(`${pad}${coverageColor(cov.level, `Coverage ${cov.level.toUpperCase()}`)}   ${c.gray('(' + coverageLabel(cov.level) + ')')}`);
  if (cap.reasons.length) {
    out.push(`   ${c.gray('methodology ' + score.methodologyVersion)} · ${c.gray(cap.reasons.slice(0, 2).join('; '))}`);
  } else {
    out.push(`   ${c.gray('methodology ' + score.methodologyVersion)}`);
  }
  out.push('');

  // Threat severity counts (what drives the grade) + capability count.
  const tc: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of threatFindings) tc[f.severity] += 1;
  const counts = (['critical', 'high', 'medium', 'low'] as Severity[])
    .filter((s) => tc[s] > 0)
    .map((s) => SEV_LABEL[s](`${tc[s]} ${s}`))
    .join(c.gray(' · '));
  out.push(`${c.gray('Threats   ')} ${counts || c.green('none')}`);
  out.push(`${c.gray('Capability')} ${capColor(cap.level, cap.level)} ${c.gray(`(${capabilityFindings.length} observation${capabilityFindings.length === 1 ? '' : 's'})`)}`);

  // Coverage caveats — what the scan could NOT see, so a clean grade on a shallow
  // scan is never read as a thorough all-clear.
  if (cov.caveats.length) {
    out.push('');
    out.push(`${coverageColor(cov.level, '⚑')} ${c.gray('Coverage — this grade reflects only what was inspected:')}`);
    for (const note of cov.caveats) {
      for (const wl of wrap(note, TERM - 4)) out.push(`  ${c.gray(wl)}`);
    }
  }

  // Category penalties.
  const cats = ALL_CATEGORIES.filter((cat) => score.categorySubtotals[cat] > 0);
  if (cats.length) {
    out.push('');
    out.push(c.gray('Penalty by category'));
    for (const cat of cats) {
      const pts = score.categorySubtotals[cat];
      out.push(`  ${padVisible(cat, 16)} ${c.red(`-${pts}`)}`);
    }
  }

  // Client-adoption-risk terms — how the threat score EVOLVES into the score a
  // user should read before adopting the server. Itemised so nothing is a black
  // box: threat score, then each subtract-only term, then the client score.
  const clientTerms = score.vector.filter((v) => v.kind === 'client');
  if (clientTerms.length) {
    out.push('');
    out.push(c.gray('Client-adoption-risk (from the threat score)'));
    out.push(`  ${padVisible('threat score', 22)} ${c.bold(`${score.threatScore}`)}`);
    for (const t of clientTerms) {
      if (t.kind !== 'client') continue;
      const sign = t.appliedPenalty > 0 ? c.red(`-${t.appliedPenalty}`) : c.green('  0');
      out.push(`  ${padVisible(`${t.term} (${t.level})`, 22)} ${sign}`);
    }
    out.push(`  ${padVisible('client score', 22)} ${c.bold(`${score.score}/100`)}`);
  }

  // Gates.
  if (score.gatesFired.length) {
    out.push('');
    out.push(c.gray('Hard gates'));
    for (const g of score.gatesFired) out.push(`  ${c.magenta('▸')} ${g}`);
  }

  // Toxic flows.
  if (report.toxicFlows.length) {
    out.push('');
    out.push(`${c.bold('Toxic flows')} ${c.gray('(untrusted-input → sensitive-source → external-sink)')}`);
    for (const f of report.toxicFlows) {
      out.push(
        `  ${SEV_LABEL[f.severity](`[${f.severity}]`)} ${clean(f.description)}` +
          (f.selfContained ? c.gray('  (single tool)') : ''),
      );
    }
  }

  // Integrity.
  if (report.integrity) {
    out.push('');
    const st = report.integrity.status;
    const label =
      st === 'drift'
        ? c.bold(c.red('DRIFT — surface changed since pin'))
        : st === 'unchanged'
          ? c.green('unchanged (matches pin)')
          : st === 'stale-pin'
            ? c.yellow('not evaluated — pin predates the current methodology (re-pin)')
            : c.gray('first seen (not yet pinned)');
    out.push(`${c.gray('Integrity')} ${label}`);
    for (const ch of report.integrity.changes ?? []) out.push(`  ${c.red('▸')} ${clean(ch.detail)}`);
  }

  // THREAT findings — drive the Trust grade. Detailed, most severe first.
  if (report.findings.length) {
    out.push('');
    out.push(line());
    out.push(`${c.bold('Threat findings')} ${c.gray('— affect the Trust grade (most severe first)')}`);
    if (threatFindings.length === 0) {
      out.push('');
      out.push(`  ${c.green('none')} ${c.gray('— no malice/negligence signals detected')}`);
    }
    let lastSev: Severity | null = null;
    for (const f of threatFindings) {
      if (f.severity !== lastSev) {
        out.push('');
        out.push(c.gray(`── ${f.severity.toUpperCase()} ──`));
        lastSev = f.severity;
      }
      out.push('');
      out.push(renderFinding(f, opts.details ?? false));
    }

    // CAPABILITY observations — blast radius, NOT a verdict on trust.
    if (capabilityFindings.length) {
      out.push('');
      out.push(line());
      out.push(
        `${c.bold('Capability observations')} ${c.gray('— what this server can do; informational, not a trust verdict')}`,
      );
      if (opts.details) {
        let last: Severity | null = null;
        for (const f of capabilityFindings) {
          if (f.severity !== last) {
            out.push('');
            out.push(c.gray(`── ${f.severity.toUpperCase()} ──`));
            last = f.severity;
          }
          out.push('');
          out.push(renderFinding(f, true));
        }
      } else {
        out.push('');
        for (const f of capabilityFindings) {
          out.push(`  ${SEV_LABEL[f.severity](`[${SEV_TAG[f.severity].trim()}]`)} ${c.gray(f.ruleId)}  ${clean(f.title)}`);
        }
        out.push('');
        out.push(c.gray('   (run with --details for the full description of each)'));
      }
    }
  } else {
    out.push('');
    out.push(c.green('No findings. This surface looks clean by the current ruleset.'));
  }

  out.push('');
  out.push(line());
  out.push(
    c.gray(
      `${report.findings.length} finding(s) · digest ${report.surfaceDigest.slice(0, 12)}… · ` +
        `${report.tool.name} ${report.tool.version}`,
    ),
  );
  out.push('');
  return out.join('\n');
}

function locationString(f: Finding): string | undefined {
  if (!f.location) return undefined;
  const l = f.location;
  return `${l.kind}${l.name ? ` "${l.name}"` : ''}${l.field ? ` → ${l.field}` : ''}`;
}

/**
 * Strip control & escape sequences from attacker-controlled text before printing
 * it. Tool metadata is untrusted; echoing its raw ANSI/OSC/control bytes would
 * let a malicious server rewrite the terminal (consent phishing / title spoof).
 */
export function clean(s: unknown): string {
  // eslint-disable-next-line no-control-regex
  return String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ');
}

function renderFinding(f: Finding, details: boolean): string {
  const lines: string[] = [];
  // Header: [SEV · confidence]  RULE-ID  Title
  lines.push(
    `${SEV_LABEL[f.severity](`[${SEV_TAG[f.severity].trim()} · ${f.confidence}]`)}  ` +
      `${c.gray(f.ruleId)}  ${c.bold(clean(f.title))}`,
  );
  const loc = locationString(f);
  if (loc) lines.push(labeled('where', clean(loc), c.gray));
  // Full (wrapped) description — the "more detail" the report is about.
  lines.push(labeled('what', clean(f.description), c.white));
  if (f.evidence) lines.push(labeled('evidence', clean(details ? f.evidence : truncate(f.evidence, 200)), c.yellow));
  if (f.remediation) lines.push(labeled('fix', clean(f.remediation), c.green));
  const maps = [f.owasp, `category: ${f.category}`].filter(Boolean).join(' · ');
  if (maps) lines.push(labeled('maps', maps, c.gray));
  if (details && f.references?.length) lines.push(labeled('refs', f.references.join('  '), c.blue));
  return lines.join('\n');
}

function truncate(s: string, n: number): string {
  const flat = String(s).replace(/\s+/g, ' ').trim();
  return flat.length > n ? `${flat.slice(0, n)}…` : flat;
}
