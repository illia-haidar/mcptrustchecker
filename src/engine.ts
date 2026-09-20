/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * The scan engine — orchestrates the pipeline over a normalized surface:
 *   detectors → toxic-flow graph → integrity (TOFU) → filter → score → report.
 * Pure and synchronous-in-spirit (detectors may be async), with no I/O of its
 * own beyond what a caller passes in (the lockfile). That keeps it fully
 * testable and deterministic.
 */

import type {
  Finding,
  ScanReport,
  ServerSurface,
  Severity,
  McpTrustCheckerConfig,
  Verification,
} from './types.js';
import { resolveConfig } from './config.js';
import { extractCapabilities } from './util/capabilities.js';
import { DETECTORS } from './detectors/index.js';
import { analyzeToxicFlows } from './detectors/toxicFlow.js';
import { checkIntegrity, type Lockfile } from './lockfile.js';
import { surfaceDigest } from './util/hash.js';
import { computeScore } from './scoring/index.js';
import { computeCapabilityProfile } from './scoring/capability.js';
import { computeCoverage } from './scoring/coverage.js';
import { METHODOLOGY_VERSION, TOOL_NAME, TOOL_VERSION } from './version.js';

export interface ScanOptions {
  config?: McpTrustCheckerConfig;
  /**
   * Pre-loaded lockfile for the integrity check. `undefined` skips integrity;
   * `null` means "no pin yet" (first-seen). Load with `readLockfile`.
   */
  lockfile?: Lockfile | null;
  /** ISO timestamp to stamp the report with. Omit for a reproducible report. */
  scannedAt?: string;
  /** Tool names from other servers in the same scan (cross-server collision). */
  siblingTools?: { server: string; name: string }[];
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function findingKey(f: Finding): string {
  // Include the title so distinct findings that share a rule+location but differ
  // in detail (e.g. two different squatting dependencies of one package) are not
  // collapsed by dedup. Title carries the discriminating name/target.
  return [f.ruleId, f.location?.kind, f.location?.name, f.location?.field, f.title, f.evidence].join('|');
}

function isObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Verification is an ENGINE signal, computed input-dependently so every mode
 * agrees. An `--online` scan already classified the fetched package document
 * (npm/pypi meta path) and stamped `packageMeta.verification`. When it is
 * absent — an OFFLINE scan, or a target with no package identity — provenance
 * was not (could not be) checked, so verification is `unknown` and the
 * verification term is skipped (a coverage caveat records why).
 */
function resolveVerification(surface: ServerSurface): Verification {
  return surface.packageMeta?.verification ?? 'unknown';
}

/**
 * Defensively normalize a surface at the engine boundary so a hand-built
 * (library-API) surface or a non-compliant live server can't crash any stage:
 * tools/prompts/resources become arrays of objects, and the server object is
 * always present. Field-level type quirks are handled by the individual stages.
 */
function sanitizeSurface(s: ServerSurface): ServerSurface {
  const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
  return {
    ...s,
    source: isObject(s.source) ? s.source : { kind: 'manifest', origin: '' },
    server: isObject(s.server) ? s.server : {},
    tools: arr(s.tools).filter(isObject) as unknown as ServerSurface['tools'],
    prompts: arr(s.prompts).filter(isObject) as unknown as ServerSurface['prompts'],
    resources: arr(s.resources).filter(isObject) as unknown as ServerSurface['resources'],
  };
}

/** Run the full pipeline over a normalized surface. */
export async function scanSurface(rawSurface: ServerSurface, options: ScanOptions = {}): Promise<ScanReport> {
  const surface = sanitizeSurface(rawSurface);
  const config = resolveConfig(options.config);
  const capabilities = extractCapabilities(surface, config);
  const ctx = { surface, config, capabilities, siblingTools: options.siblingTools ?? [] };

  const raw: Finding[] = [];
  for (const detector of DETECTORS) {
    if (config.disabledRules.includes(detector.id)) continue;
    raw.push(...(await detector.run(ctx)));
  }

  const { flows, findings: flowFindings } = analyzeToxicFlows(ctx);
  raw.push(...flowFindings);

  // Integrity (rug-pull) check, if a lockfile context was provided.
  let integrity: ScanReport['integrity'];
  if (options.lockfile !== undefined) {
    integrity = checkIntegrity(surface, options.lockfile);
    if (integrity.status === 'stale-pin') {
      // The pin predates a methodology change, so the schema comparison is not
      // evaluable. Say that rather than either accusing (a false rug pull on
      // every upgrade) or staying silent (an un-evaluated check reading as a
      // clean one) — the same honesty rule as MTC-TOFU-004.
      raw.push({
        ruleId: 'MTC-TOFU-005',
        title: 'Pin predates the current methodology — drift not evaluated',
        category: 'supply-chain',
        severity: 'info',
        confidence: 'strong',
        description:
          `This server was pinned under methodology \`${integrity.pinnedMethodologyVersion}\`, but this scan runs ` +
          `\`${METHODOLOGY_VERSION}\`, which fingerprints a different set of fields. The two digests are not ` +
          `comparable, so surface drift since the pin was NOT checked — this is not evidence that the server is ` +
          `unchanged. The byte-level artifact pin does not depend on the fingerprint and was still checked.`,
        remediation: 'Re-pin against the current methodology (`mcptrustchecker pin`) after reviewing the surface once.',
        location: { kind: 'server' },
        evidence: `pinned under ${integrity.pinnedMethodologyVersion}, scanning under ${METHODOLOGY_VERSION}`,
        data: { pinnedMethodologyVersion: integrity.pinnedMethodologyVersion },
      });
    }
    if (integrity.status === 'drift' || integrity.status === 'stale-pin') {
      const allChanges = integrity.changes ?? [];
      const packageChanges = allChanges.filter((ch) => ch.kind === 'package-changed');
      const surfaceChanges = allChanges.filter((ch) => ch.kind !== 'package-changed');
      // Only a comparable pin can prove drift. On `stale-pin` the digests differ
      // because the projection changed, not because the server did.
      if (integrity.status === 'drift' && (surfaceChanges.length > 0 || integrity.currentDigest !== integrity.previousDigest)) {
        raw.push({
          ruleId: 'MTC-TOFU-001',
          title: 'Server surface changed since it was pinned (possible rug pull)',
          category: 'supply-chain',
          severity: 'high',
          confidence: 'confirmed',
          description:
            `The canonical fingerprint of this server no longer matches its pinned value in the lockfile. ` +
            `Tool definitions can change silently after you approve them (a rug pull); review every change before ` +
            `trusting it again.\n` +
            surfaceChanges.map((c) => `  • ${c.detail}`).join('\n'),
          remediation: 'Review the diff; re-pin only after confirming the changes are legitimate (`mcptrustchecker pin`).',
          location: { kind: 'server' },
          owasp: 'LLM03:2025 Supply Chain',
          evidence: `${surfaceChanges.length} change(s) since pin`,
          data: { changes: surfaceChanges },
        });
      }
      if (packageChanges.length > 0) {
        raw.push({
          ruleId: 'MTC-TOFU-002',
          title: 'Package republished with different content at the same version',
          category: 'supply-chain',
          severity: 'critical',
          confidence: 'confirmed',
          description:
            `The registry artifact for the pinned version no longer contains the bytes that were verified at pin ` +
            `time. The tool surface can look completely unchanged while the implementation behind it was swapped — ` +
            `the byte-level rug pull that metadata-only checks cannot see.\n` +
            packageChanges.map((c) => `  • ${c.detail}`).join('\n'),
          remediation:
            'Treat this as a potential supply-chain compromise: diff the published code against the version you ' +
            'approved before trusting it again, and re-pin (`mcptrustchecker pin`) only after review.',
          location: { kind: 'package', name: packageChanges[0]!.name },
          owasp: 'LLM03:2025 Supply Chain',
          evidence: packageChanges[0]!.detail,
          data: { changes: packageChanges },
        });
      }
    }
  }

  // Filter: disabled rules, whole-rule allowlist waivers, and location-scoped
  // baseline suppressions (rule + optional tool/field, with a reason).
  const disabled = new Set(config.disabledRules);
  const allowed = new Set(config.allowlist);
  const suppressions = config.suppress ?? [];
  const isSuppressed = (f: Finding): boolean =>
    suppressions.some(
      (s) =>
        s.rule === f.ruleId &&
        (s.tool === undefined || s.tool === f.location?.name) &&
        (s.field === undefined || s.field === f.location?.field),
    );
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const f of raw) {
    if (disabled.has(f.ruleId) || allowed.has(f.ruleId) || isSuppressed(f)) continue;
    const key = findingKey(f);
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(f);
  }

  // STATIC-PROVENANCE CONFIDENCE CAP. When the tool surface was reconstructed from
  // source (a package scan that never ran the server), a mis-parsed registration
  // could mis-attribute text to a tool and raise a spurious finding. So no finding
  // derived from a statically-inferred tool may claim `confirmed`: it is capped at
  // `strong`. Effect on gates — a `confirmed`-critical F-gate cannot be triggered by
  // an inferred tool (it becomes a `strong` critical, which floors the grade at D,
  // not F), so a parser slip can never F-grade a legitimate package; a live scan
  // (`--command`) is what escalates a real tool-poisoning to `confirmed`/F. Findings
  // from the trustworthy channels (source code, supply-chain metadata, rug-pull
  // drift) are untouched — their evidence did not come from the inferred surface.
  if (surface.toolProvenance === 'static') {
    const toolDerived = (f: Finding): boolean =>
      f.location?.kind === 'tool' || /^MTC-(INJ|UNI|FLOW|CAP|COL)/.test(f.ruleId);
    for (const f of findings) {
      if (f.confidence === 'confirmed' && toolDerived(f)) {
        f.confidence = 'strong';
        f.data = { ...(f.data ?? {}), staticProvenanceCap: true };
      }
    }
  }

  findings.sort((a, b) => {
    if (SEVERITY_ORDER[a.severity] !== SEVERITY_ORDER[b.severity])
      return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (a.category !== b.category) return a.category < b.category ? -1 : 1;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });

  // The three client-adoption-risk inputs are all known here, so the final
  // score assembly lives at the point where capability, coverage and
  // verification are settled — the score EVOLVES the threat score with them.
  const capabilityProfile = computeCapabilityProfile(capabilities, flows, findings);
  const verification = resolveVerification(surface);
  const coverage = computeCoverage(surface, verification);
  const score = computeScore(findings, {
    capabilityLevel: capabilityProfile.level,
    coverageLevel: coverage.level,
    verification,
  });

  const findingsBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) findingsBySeverity[f.severity] += 1;

  return {
    tool: { name: TOOL_NAME, version: TOOL_VERSION, methodologyVersion: METHODOLOGY_VERSION },
    target: {
      id: surface.id,
      source: surface.source,
      server: { name: surface.server.name, version: surface.server.version },
    },
    ...(options.scannedAt ? { scannedAt: options.scannedAt } : {}),
    findings,
    score,
    capabilities,
    capabilityProfile,
    coverage,
    toxicFlows: flows,
    integrity,
    surfaceDigest: surfaceDigest(surface),
    stats: {
      tools: surface.tools.length,
      prompts: surface.prompts.length,
      resources: surface.resources.length,
      findingsBySeverity,
    },
  };
}
