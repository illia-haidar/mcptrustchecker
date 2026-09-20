import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeCoverage } from '../src/scoring/coverage.js';
import { computeCapabilityProfile } from '../src/scoring/capability.js';
import { makeSurface } from './helpers.js';
import type { CapabilityLevel, CoverageLevel, Verification } from '../src/types.js';
import { computeScore } from '../src/scoring/index.js';
import { GRADE_RANK } from '../src/scoring/model.js';
import type { Category, Confidence, Finding, Severity } from '../src/types.js';

// THE SCORER'S OWN MONOTONICITY INVARIANT.
//
// `test/evasion.test.ts` pins the invariant at the DETECTOR level: hiding a
// payload must not improve its grade. This file pins it one layer down, on the
// arithmetic itself, over the whole input space rather than one corpus:
//
//   • adding a finding must never raise the score or improve the grade;
//   • making a finding more severe, or more certain, must never do either.
//
// Both held for the detectors and failed for the scorer. The diminishing series
// was keyed by rule while the cap is per-category, so a finding landing in an
// already-capped category consumed a full-weight rank slot for free — the cap
// swallowed its own penalty — and demoted a same-rule finding in an uncapped
// category to a smaller factor. Net: adding a finding IMPROVED the score, on
// 141 of 20 000 random inputs.

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const CONFIDENCES: Confidence[] = ['confirmed', 'strong', 'heuristic', 'speculative'];
const CATEGORIES: Category[] = ['injection', 'exfiltration', 'permissions', 'supply-chain', 'network', 'hygiene'];
// Deliberately NOT capability rules — those are excluded before scoring.
const RULES = ['MTC-INJ-POISON', 'MTC-INJ-AUTH-2', 'MTC-SUP-001', 'MTC-NET-001', 'MTC-UNI-001', 'MTC-FLOW-001'];

/** A seeded LCG, so a failure is reproducible rather than a flake. */
function rng(seed: number): () => number {
  let s = seed;
  return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
}

function finding(rnd: () => number): Finding {
  const pick = <T>(a: T[]): T => a[Math.floor(rnd() * a.length)]!;
  return {
    ruleId: pick(RULES),
    title: 'test finding',
    category: pick(CATEGORIES),
    severity: pick(SEVERITIES),
    confidence: pick(CONFIDENCES),
    description: 'test',
    location: { kind: 'server' },
  };
}

const describe = (f: Finding): string => `${f.ruleId}/${f.severity}/${f.confidence}/${f.category}`;

test('INVARIANT: adding a finding never raises the score or improves the grade', () => {
  const rnd = rng(12345);
  for (let i = 0; i < 20_000; i++) {
    const set = Array.from({ length: Math.floor(rnd() * 6) }, () => finding(rnd));
    const extra = finding(rnd);
    const before = computeScore(set);
    const after = computeScore([...set, extra]);
    const ctx = () => `\n  set:   ${set.map(describe).join('\n         ')}\n  added: ${describe(extra)}`;
    assert.ok(
      after.threatScore <= before.threatScore,
      `threat score rose from ${before.threatScore} to ${after.threatScore}${ctx()}`,
    );
    assert.ok(
      GRADE_RANK[after.grade] <= GRADE_RANK[before.grade],
      `grade improved from ${before.grade} to ${after.grade}${ctx()}`,
    );
  }
});

test('INVARIANT: a more severe or more certain finding never raises the score', () => {
  const rnd = rng(67890);
  const worse: Record<string, Partial<Record<string, string>>> = {
    severity: { low: 'medium', medium: 'high', high: 'critical' },
    confidence: { speculative: 'heuristic', heuristic: 'strong', strong: 'confirmed' },
  };
  for (let i = 0; i < 20_000; i++) {
    const set = Array.from({ length: 1 + Math.floor(rnd() * 4) }, () => finding(rnd));
    const idx = Math.floor(rnd() * set.length);
    for (const axis of ['severity', 'confidence'] as const) {
      const upgraded = worse[axis]![set[idx]![axis]];
      if (!upgraded) continue;
      const escalated = set.map((f, j) => (j === idx ? { ...f, [axis]: upgraded } : f)) as Finding[];
      const before = computeScore(set);
      const after = computeScore(escalated);
      const ctx = `${axis} ${set[idx]![axis]} → ${upgraded}\n  set: ${set.map(describe).join('\n       ')}`;
      assert.ok(after.threatScore <= before.threatScore, `threat rose ${before.threatScore}→${after.threatScore}: ${ctx}`);
      assert.ok(GRADE_RANK[after.grade] <= GRADE_RANK[before.grade], `grade improved ${before.grade}→${after.grade}: ${ctx}`);
    }
  }
});

test('the diminishing series is keyed by rule AND category', () => {
  // The exact shape that broke it: rule A spans two categories, and a third
  // finding fills the hygiene cap (10) so a fourth in hygiene is free.
  const f = (ruleId: string, severity: Severity, confidence: Confidence, category: Category): Finding => ({
    ruleId, title: 't', category, severity, confidence, description: 'd', location: { kind: 'server' },
  });
  const base = [
    f('MTC-A', 'critical', 'speculative', 'injection'),
    f('MTC-A', 'medium', 'speculative', 'exfiltration'),
    f('MTC-B', 'critical', 'speculative', 'hygiene'),
  ];
  const before = computeScore(base);
  const after = computeScore([...base, f('MTC-A', 'low', 'confirmed', 'hygiene')]);
  assert.ok(after.threatScore <= before.threatScore, `${before.threatScore} → ${after.threatScore}`);
  // The exfiltration finding must keep its rank-0 slot: the hygiene one is a
  // different (rule, category) series and cannot demote it.
  const exfil = after.vector.find((v) => v.kind === 'threat' && v.category === 'exfiltration');
  assert.equal(exfil?.diminishingFactor, 1);
});

// --- Coverage honesty -------------------------------------------------------

test('a scan that inspected nothing cannot earn an A or a B', () => {
  // `MTC-META-001` and the coverage caveat both say in prose that an empty
  // surface is not a clean bill of health. At E_cov = 10 the score said the
  // opposite: a target the scanner never looked at graded A(90).
  for (const verification of ['vendor', 'source', 'repo', 'none', 'unknown'] as const) {
    const s = computeScore([], { capabilityLevel: 'minimal', coverageLevel: 'empty', verification });
    assert.ok(
      GRADE_RANK[s.grade] <= GRADE_RANK.C,
      `empty coverage + ${verification} verification graded ${s.grade}(${s.score})`,
    );
  }
});

test('inspection depth is ordered: a deeper scan never scores worse', () => {
  const LEVELS = ['empty', 'metadata', 'manifest', 'source', 'live'] as const;
  let previous = -1;
  for (const coverageLevel of LEVELS) {
    const s = computeScore([], { capabilityLevel: 'minimal', coverageLevel, verification: 'unknown' });
    assert.ok(s.score >= previous, `${coverageLevel} scored ${s.score}, below the shallower tier's ${previous}`);
    previous = s.score;
  }
});

// --- The client score never exceeds the threat score ------------------------

test('every client term is subtract-only', () => {
  const rnd = rng(4242);
  for (let i = 0; i < 2_000; i++) {
    const set = Array.from({ length: Math.floor(rnd() * 4) }, () => finding(rnd));
    for (const coverageLevel of ['empty', 'metadata', 'manifest', 'source', 'live'] as const) {
      for (const capabilityLevel of ['minimal', 'moderate', 'high', 'critical'] as const) {
        const s = computeScore(set, { capabilityLevel, coverageLevel, verification: 'none' });
        assert.ok(s.score <= s.threatScore, `client ${s.score} exceeded threat ${s.threatScore}`);
        for (const v of s.vector) assert.ok(v.appliedPenalty >= 0, `negative penalty on ${JSON.stringify(v)}`);
      }
    }
  }
});

test('the score is fully reconstructable from the vector and the subtotals', () => {
  const rnd = rng(999);
  for (let i = 0; i < 2_000; i++) {
    const set = Array.from({ length: Math.floor(rnd() * 6) }, () => finding(rnd));
    const s = computeScore(set, { capabilityLevel: 'high', coverageLevel: 'manifest', verification: 'repo' });
    const threat = Math.max(0, Math.min(100, Math.round(100 - Object.values(s.categorySubtotals).reduce((a, b) => a + b, 0))));
    assert.equal(threat, s.threatScore);
    const client = s.vector.filter((v) => v.kind === 'client').reduce((a, v) => a + v.appliedPenalty, 0);
    assert.equal(Math.max(0, Math.min(100, Math.round(s.threatScore - client))), s.score);
  }
});

// ---------------------------------------------------------------------------
// The clean lattice — what a scan with ZERO threat findings can score.
//
// The three client terms are the only thing separating a clean scan from 100, so
// the shape of that lattice IS the model's honesty claim: it decides whether "we
// found nothing" may still be reported as an A. That claim used to live in a
// prose comment in model.ts, and the comment was WRONG — it asserted a floor of
// 87 and "never below B" while COVERAGE_HONESTY.empty, thirty-five lines below
// it, exists precisely to push a nothing-was-inspected scan out of A and B.
// Prose drifts; this does not.
// ---------------------------------------------------------------------------
const CAPABILITIES: CapabilityLevel[] = ['minimal', 'moderate', 'high', 'critical'];
const COVERAGES: CoverageLevel[] = ['live', 'source', 'manifest', 'metadata', 'empty'];
const VERIFICATIONS: Verification[] = ['vendor', 'source', 'repo', 'none', 'unknown'];

/**
 * `metadata` and `empty` are only chosen when the target has no tool surface and
 * no implementation source; capability is raised only by findings that require
 * one or the other. The two tiers therefore force `minimal`, and 30 of the 100
 * cells describe states the engine cannot produce. Enumerating them anyway would
 * pin an impossible floor (critical capability on a target with nothing in it).
 */
const reachable = (capability: CapabilityLevel, coverage: CoverageLevel): boolean =>
  coverage === 'metadata' || coverage === 'empty' ? capability === 'minimal' : true;

test('the reachability constraint itself: nothing to inspect ⇒ minimal capability', () => {
  // The thin coverage tiers are chosen only when there is no tool surface AND no
  // implementation source. Capability is derived from per-tool capabilities,
  // toxic flows and MTC-SRC-* findings — all three of which require exactly what
  // those tiers say is absent. So the coupling is structural, not incidental.
  const bare = makeSurface({ tools: [], prompts: [], resources: [], sourceFiles: [] });
  const coverage = computeCoverage(bare);
  assert.ok(
    coverage.level === 'empty' || coverage.level === 'metadata',
    `expected a thin coverage tier, got ${coverage.level}`,
  );

  // No tool capabilities, no flows, no findings — the only inputs that can bump.
  const capability = computeCapabilityProfile([], [], []);
  assert.equal(
    capability.level,
    'minimal',
    'with no tools and no source there is nothing that can raise capability',
  );
});

test('clean lattice: 70 reachable states ⇒ 52 A / 13 B / 5 C, floor 70', () => {
  const grades: Record<string, number> = {};
  let floor = 100;
  let floorAt = '';
  let states = 0;

  for (const capabilityLevel of CAPABILITIES) {
    for (const coverageLevel of COVERAGES) {
      if (!reachable(capabilityLevel, coverageLevel)) continue;
      for (const verification of VERIFICATIONS) {
        const r = computeScore([], { capabilityLevel, coverageLevel, verification });
        grades[r.grade] = (grades[r.grade] ?? 0) + 1;
        states += 1;
        if (r.score < floor) {
          floor = r.score;
          floorAt = `${capabilityLevel}/${coverageLevel}/${verification}`;
        }
        assert.equal(r.threatScore, 100, 'no findings ⇒ the threat score is untouched');
        assert.ok(r.score <= r.threatScore, 'client terms subtract only');
      }
    }
  }

  assert.equal(states, 70);
  assert.deepEqual(grades, { A: 52, B: 13, C: 5 });
  assert.equal(floor, 70);
  assert.equal(floorAt, 'minimal/empty/none');
  assert.equal(grades.D, undefined, 'exposure alone must not manufacture a D');
  assert.equal(grades.F, undefined, 'exposure alone must not manufacture an F');
});

test('the two ends of the lattice are the ones the methodology promises', () => {
  const best = computeScore([], { capabilityLevel: 'minimal', coverageLevel: 'source', verification: 'vendor' });
  assert.equal(best.score, 100);
  assert.equal(best.grade, 'A');

  // A scan that inspected nothing must not be reported as an A or a B, which is
  // the entire purpose of COVERAGE_HONESTY.empty.
  const nothing = computeScore([], { capabilityLevel: 'minimal', coverageLevel: 'empty', verification: 'none' });
  assert.equal(nothing.grade, 'C');
  assert.ok(nothing.score < 80, 'an empty surface is not a clean bill of health');
});
