/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The scoring model — every constant that can move a Trust Score lives here so
 * the methodology is auditable in one place. A plain weighted average is
 * gameable, so we use additive penalties from 100 with diminishing returns,
 * per-category caps, and weakest-link gates — severity is kept distinct from
 * risk, and the result is fully deterministic.
 */

import type { CapabilityLevel, Category, Confidence, CoverageLevel, Grade, Severity, Verification } from '../types.js';

/** Points for the FIRST finding of a severity, before modifiers. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 45,
  high: 22,
  medium: 9,
  low: 3,
  info: 0,
};

/** Confidence multiplier — a guess must not carry a confirmed finding's weight. */
export const CONFIDENCE_MULT: Record<Confidence, number> = {
  confirmed: 1.0,
  strong: 0.7,
  heuristic: 0.4,
  speculative: 0.2,
};

/** Diminishing returns for the Nth finding of the same rule (index clamped to last). */
export const DIMINISHING = [1.0, 0.5, 0.25, 0.1];

/** Maximum points any single category may subtract. */
export const CATEGORY_CAP: Record<Category, number> = {
  injection: 50,
  exfiltration: 50,
  permissions: 35,
  'supply-chain': 30,
  network: 25,
  hygiene: 10,
};

/**
 * CLIENT-ADOPTION-RISK terms. The Trust Score asks one question — "how safe is
 * this MCP for the USER who wants to adopt it?" — so three small, subtract-only,
 * itemised terms EVOLVE the threat score into the client score. They do NOT
 * revert the capability/threat separation: the threat machinery above is
 * unchanged; these layer on top, and each is one auditable line in score.vector.
 *
 * clientScore = clamp(0..100, round( threatScore − E_cap − E_ver − E_cov ))
 *
 * All terms are >= 0, so the client score can never RISE above the threat score.
 *
 * THE CLEAN LATTICE. Enumerated over the states the engine can actually produce —
 * 70 of the 4x5x5 grid, because coverage `metadata`/`empty` both require a target
 * with no tools AND no source, and capability is raised only by findings that
 * need one or the other, so those two tiers force capability `minimal` and the
 * remaining 30 cells are unreachable. With zero threat findings:
 *
 *     52 A / 13 B / 5 C / 0 D / 0 F      floor 70 at minimal + empty + none
 *
 * So exposure alone cannot produce a D or an F, but it CAN reach C — an earlier
 * comment here claimed a floor of 87 and "never below B", which contradicted
 * COVERAGE_HONESTY.empty thirty-five lines below, whose whole purpose is to keep
 * a scan that inspected nothing out of the A and B bands. The second comment was
 * the correct one. `test/scoring-invariants.test.ts` now pins this lattice, so a
 * future constant change fails a test instead of leaving prose to drift.
 */

/** E_cap — the client's blast radius if the model driving the server is hijacked. */
export const CAPABILITY_EXPOSURE: Record<CapabilityLevel, number> = {
  minimal: 0,
  moderate: 3,
  high: 6,
  critical: 10,
};

/** E_ver — how much the client can trust the SOURCE (less trust ⇒ more subtracted).
 *  Not applied when verification is `unknown` (an offline scan couldn't check it). */
// Client-adoption-risk verification discount. Ordered by what the client can
// actually verify before trusting the artifact. The two verified states cost
// nothing — provenance/vendor IS the reward. Only the two UNVERIFIED states are
// discounted, and they are split honestly: a public, inspectable repository (the
// ecosystem norm — ~75% of unverified packages have one) is a light −1, because
// the client can still read the code; a package whose source cannot even be
// located is the real unknown at −5.
export const VERIFICATION_DISCOUNT: Record<Exclude<Verification, 'unknown'>, number> = {
  vendor: 0,
  source: 0,
  repo: 1,
  none: 5,
};

/**
 * E_cov — inspection depth: the shallower the scan, the less a clean grade proves.
 *
 * `empty` is the one tier that is not a matter of degree. The other four all
 * inspected *something* — a running server, the shipped source, the advertised
 * tool list, the registry record — so a clean result there is evidence, just of
 * varying reach. `empty` inspected nothing at all: no tools, no prompts, no
 * resources, no source, no package metadata. Its penalty is therefore sized to
 * keep a threat-clean empty scan out of the A and B bands entirely, because
 * `MTC-META-001` and the coverage caveat both say in prose that an empty surface
 * is NOT a clean bill of health — and at −10 the score said the opposite,
 * handing an A(90) to a target the scanner never looked at.
 */
export const COVERAGE_HONESTY: Record<CoverageLevel, number> = {
  live: 0,
  source: 0,
  manifest: 4,
  metadata: 8,
  empty: 25,
};

export const ALL_CATEGORIES: Category[] = [
  'injection',
  'exfiltration',
  'permissions',
  'supply-chain',
  'network',
  'hygiene',
];

/** Higher score = safer. Bands are fixed and published. */
export const GRADE_BANDS: { grade: Grade; min: number }[] = [
  { grade: 'A', min: 90 },
  { grade: 'B', min: 80 },
  { grade: 'C', min: 70 },
  { grade: 'D', min: 60 },
  { grade: 'F', min: 0 },
];

/** Strictness ordering: F is worst (0), A is best (4). */
export const GRADE_RANK: Record<Grade, number> = { F: 0, D: 1, C: 2, B: 3, A: 4 };

export function bandForScore(score: number): Grade {
  for (const b of GRADE_BANDS) if (score >= b.min) return b.grade;
  return 'F';
}

/** Return the stricter (worse) of two grades. */
export function stricterGrade(a: Grade, b: Grade): Grade {
  return GRADE_RANK[a] <= GRADE_RANK[b] ? a : b;
}

/**
 * MCP Trust Checker scores two independent axes:
 *
 *  - TRUST (the A–F grade): does anything suggest the server is malicious or
 *    negligent? Driven by *threat* findings (poisoning, secrets, unicode
 *    smuggling, typosquat, CVEs, rug-pull, annotation lies, a single tool built
 *    as an exfiltration primitive).
 *  - CAPABILITY (a level): how much could this server do if the model driving
 *    it were manipulated? Driven by *capability* findings (code execution,
 *    filesystem writes, network egress, the cross-tool toxic-flow surface).
 *
 * A legitimate but powerful server (a scraper, a browser, a filesystem tool) is
 * high-CAPABILITY but should still be high-TRUST — it isn't a bad actor, it just
 * has a large blast radius. Keeping the axes separate is what stops the grade
 * from collapsing every capable server into "F".
 *
 * These rules describe *capability* and therefore do NOT lower the trust grade;
 * they raise the capability level and are shown as "capability observations".
 */
export const CAPABILITY_RULES = new Set<string>([
  'MTC-CAP-001', // command/code execution
  'MTC-CAP-002', // filesystem mutation
  'MTC-CAP-004', // open-world + sensitive read
  'MTC-CAP-005', // missing destructiveHint
  'MTC-CAP-006', // unconstrained command param
  'MTC-CAP-007', // unconstrained URL/host param
  'MTC-CAP-008', // unconstrained path param
  'MTC-CAP-009', // declared sampling capability
  'MTC-CAP-010', // declared elicitation capability (the secret-seeking variant is MTC-CAP-011, a threat)
  'MTC-FLOW-002', // cross-tool trifecta (capability co-presence, not malice)
  'MTC-FLOW-003', // read + egress in one tool
  'MTC-FLOW-004', // source + sink co-exist
  'MTC-FLOW-005', // untrusted input reaches an action
  'MTC-NET-005', // remote endpoint (informational)
  // Implementation-level sinks found by the source scan. Their PRESENCE is what
  // the server is built to do — a browser driver spawns processes, an API
  // wrapper hardcodes its provider's endpoint, a cloud connector reads its CLI's
  // credential store. That is blast radius, not evidence of malice, so these
  // raise the capability level instead of lowering the grade. The threat-side
  // source rules stay scored: MTC-SRC-004 (obfuscated payloads), MTC-SRC-007
  // (unsafe deserialization) and MTC-SRC-008 (hardcoded live secrets).
  'MTC-SRC-001', // dynamic code execution present in implementation
  'MTC-SRC-002', // shell/process execution present in implementation
  'MTC-SRC-003', // hardcoded egress endpoint in implementation
  'MTC-SRC-005', // dynamic module load from a non-literal
  'MTC-SRC-006', // credential-path read / environment dump in implementation
  // `eval(var)` / `new Function(var)` is the SAME primitive as SRC-001 (which is
  // already capability-only): evaluating a runtime value is what an honest
  // code-runner / interpreter / template engine DOES — it is blast radius, not
  // proof of malice. The genuine THREAT is untrusted tool input REACHING the eval
  // sink, which the flow layer (MTC-FLOW-005) and the decode+exec dropper rule
  // (MTC-SRC-004) carry; the assembled-command + eval co-presence dropper still
  // scores via the compound MTC-SRC-011. Keeping SRC-010 scored double-charged the
  // capability and drove ~231 honest code-runners below B.
  'MTC-SRC-010', // dynamic evaluation of a non-literal present in implementation
]);

/** True if a rule describes capability/blast-radius rather than a trust threat. */
export function isCapabilityRule(ruleId: string): boolean {
  return CAPABILITY_RULES.has(ruleId);
}
