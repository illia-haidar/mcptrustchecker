/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Policy-as-code. A team declares what "acceptable" means once (in
 * `mcptrustchecker.config.json` under `policy`) and every scan is gated against
 * it in CI — beyond a single grade/score threshold. Pure and deterministic.
 */

import type { CapabilityLevel, Policy, ScanReport } from './types.js';
import { GRADE_RANK } from './scoring/model.js';

const CAP_ORDER: CapabilityLevel[] = ['minimal', 'moderate', 'high', 'critical'];

export interface PolicyViolation {
  policy: 'minGrade' | 'maxCapability' | 'denyRules' | 'denyCapabilities';
  message: string;
}

/** Evaluate a report against a policy; empty array means it passes. */
export function evaluatePolicy(report: ScanReport, policy: Policy | undefined): PolicyViolation[] {
  if (!policy) return [];
  const violations: PolicyViolation[] = [];

  // Normalize case so a miscased config value ("b", "Critical") can't silently
  // fail OPEN (disabling the gate) or fail CLOSED (blocking every scan).
  const minGrade = policy.minGrade ? (String(policy.minGrade).toUpperCase() as keyof typeof GRADE_RANK) : undefined;
  if (minGrade && minGrade in GRADE_RANK && GRADE_RANK[report.score.grade] < GRADE_RANK[minGrade]) {
    violations.push({
      policy: 'minGrade',
      message: `Trust grade ${report.score.grade} is worse than the required minimum ${minGrade}.`,
    });
  }

  const maxCapability = policy.maxCapability ? (String(policy.maxCapability).toLowerCase() as CapabilityLevel) : undefined;
  if (maxCapability && CAP_ORDER.includes(maxCapability)) {
    const level = report.capabilityProfile.level;
    if (CAP_ORDER.indexOf(level) > CAP_ORDER.indexOf(maxCapability)) {
      violations.push({
        policy: 'maxCapability',
        message: `Capability level "${level}" exceeds the allowed maximum "${maxCapability}".`,
      });
    }
  }

  if (policy.denyRules?.length) {
    const denied = new Set(policy.denyRules);
    const hit = [...new Set(report.findings.map((f) => f.ruleId).filter((id) => denied.has(id)))];
    if (hit.length) {
      violations.push({ policy: 'denyRules', message: `Denied rule(s) fired: ${hit.join(', ')}.` });
    }
  }

  if (policy.denyCapabilities?.length) {
    const present = new Set(report.capabilityProfile.tags);
    const hit = policy.denyCapabilities.filter((t) => present.has(t));
    if (hit.length) {
      violations.push({ policy: 'denyCapabilities', message: `Denied capability(ies) present: ${hit.join(', ')}.` });
    }
  }

  return violations;
}
