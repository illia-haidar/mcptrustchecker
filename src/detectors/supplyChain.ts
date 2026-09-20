/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Stage 5 — Supply-chain & typosquatting.
 *
 * Multi-signal, not a single edit-distance number: known-squat table, fake
 * official scope, unscoped shadowing, confusable skeleton, Damerau-Levenshtein
 * gated by a download anomaly, combosquat suffix stripping, plus install-script
 * / provenance risk. Anchored to the curated protected list (never all-pairs).
 */

import type { Detector, DetectorContext, Finding, PackageMeta, ResolvedConfig } from '../types.js';
import {
  COMBOSQUAT_SUFFIXES,
  GENERIC_COMBO_TOKENS,
  FAKE_SCOPE_PATTERNS,
  KNOWN_SQUATS,
  PROTECTED_PACKAGES,
  UNSCOPED_SHADOWS,
} from '../data/protectedPackages.js';
import { skeleton } from '../data/confusables.js';
import { KNOWN_VULNS } from '../data/knownCves.js';
import { bareName, damerauLevenshtein, isKeyboardTypo } from '../util/distance.js';

const SUP_REF = ['https://github.com/ossf/package-analysis', 'https://owasp.org/www-project-top-10-ci-cd-security-risks/'];

function protectedNames(config: ResolvedConfig): string[] {
  return [...PROTECTED_PACKAGES.map((p) => p.name), ...config.protectedPackages];
}

function downloadsFor(name: string): number | undefined {
  return PROTECTED_PACKAGES.find((p) => p.name === name)?.weeklyDownloads;
}

/** Pure typosquat analysis for a single package name. Exported for tests. */
export function analyzeTyposquat(name: string, meta: PackageMeta | undefined, config: ResolvedConfig): Finding[] {
  const findings: Finding[] = [];
  if (typeof name !== 'string' || name.length === 0) return findings;
  const lower = name.toLowerCase();
  const protectedList = protectedNames(config);
  const protectedSet = new Set(protectedList.map((p) => p.toLowerCase()));

  // It IS a protected package — nothing to squat.
  if (protectedSet.has(lower)) return findings;

  const push = (
    ruleId: string,
    severity: Finding['severity'],
    confidence: Finding['confidence'],
    title: string,
    description: string,
    target?: string,
  ): void => {
    findings.push({
      ruleId,
      title,
      category: 'supply-chain',
      severity,
      confidence,
      description,
      remediation: target
        ? `Confirm you meant "${target}". Install packages only from their documented, official name.`
        : 'Verify the package name against its official source before installing.',
      location: { kind: 'package', name },
      owasp: 'LLM03:2025 Supply Chain',
      references: SUP_REF,
      data: { candidate: name, target },
    });
  };

  // 1) Known pre-computed squat.
  if (KNOWN_SQUATS[lower]) {
    push('MTC-SUP-001', 'high', 'strong', `Known typosquat of ${KNOWN_SQUATS[lower]}`,
      `"${name}" is a known impersonation of the popular package "${KNOWN_SQUATS[lower]}".`, KNOWN_SQUATS[lower]);
    return findings; // definitive; don't pile on
  }

  // 2) Fake official scope.
  for (const re of FAKE_SCOPE_PATTERNS) {
    if (re.test(name)) {
      push('MTC-SUP-002', 'high', 'strong', 'Impersonated official scope',
        `"${name}" uses a scope crafted to look like the official @modelcontextprotocol namespace.`, '@modelcontextprotocol/*');
      return findings;
    }
  }

  // 3) Unscoped shadow of an official scoped package.
  if (UNSCOPED_SHADOWS.has(lower)) {
    push('MTC-SUP-003', 'high', 'strong', 'Unscoped shadow of an official package',
      `"${name}" is an unscoped name that shadows an official scoped @modelcontextprotocol package.`);
    return findings;
  }

  const bare = bareName(lower);
  const skel = skeleton(bare);

  for (const prot of protectedList) {
    const protLower = prot.toLowerCase();
    const protBare = bareName(protLower);
    if (bare === protBare) continue; // same bare name, different scope handled above

    // 4) Confusable skeleton collision (homoglyph squat).
    if (skel === skeleton(protBare) && bare !== protBare) {
      push('MTC-SUP-004', 'high', 'strong', `Homoglyph squat of ${prot}`,
        `"${name}" is visually confusable with "${prot}" (identical confusable skeleton "${skel}").`, prot);
      continue;
    }

    // 5) Edit-distance near-miss, gated by download anomaly.
    if (protBare.length >= 5) {
      const dist = damerauLevenshtein(bare, protBare);
      if (dist >= 1 && dist <= 2) {
        const dl = downloadsFor(prot);
        const highTraffic = dl !== undefined && dl >= 50_000;
        const keyboardSlip = isKeyboardTypo(bare, protBare);
        const severity = dist === 1 && highTraffic ? 'high' : 'medium';
        const confidence = dist === 1 ? 'strong' : 'heuristic';
        push('MTC-SUP-005', severity, confidence, `Near-miss of ${prot} (edit distance ${dist})`,
          `"${name}" is edit-distance ${dist} from the ${highTraffic ? 'high-traffic ' : ''}package "${prot}"` +
            `${keyboardSlip ? ' (keyboard-adjacent slip)' : ''}. ${meta?.weeklyDownloads != null && meta.weeklyDownloads < 500 ? 'Its own download count is negligible, consistent with a squat.' : 'Verify this is the intended package.'}`,
          prot);
        continue;
      }
    }

    // 6) Combosquat: strip decorative suffixes and re-compare. Two gates stop the
    //    dominant false positive — every idiomatic `@vendor/mcp-server` matched the
    //    bare protected token "mcp" (3 chars), billing 4× across protected entries
    //    that share that bareName. A residue MUST be >=5 chars AND not a generic
    //    ecosystem token, so "mcp"/"server"/"api" can never be a squat base.
    let stripped = bare;
    for (const suf of COMBOSQUAT_SUFFIXES) if (stripped.endsWith(suf)) stripped = stripped.slice(0, -suf.length);
    if (stripped !== bare && stripped === protBare && stripped.length >= 5 && !GENERIC_COMBO_TOKENS.has(stripped)) {
      push('MTC-SUP-006', 'medium', 'heuristic', `Possible combosquat of ${prot}`,
        `"${name}" is "${prot}" with a decorative suffix — a common combosquat pattern.`, prot);
    }
  }

  return findings;
}

/** Install-script & provenance risk from package metadata. */
export function analyzeProvenance(meta: PackageMeta): Finding[] {
  const findings: Finding[] = [];
  const name = meta.name ?? 'package';

  const scripts = meta.scripts ?? {};
  const lifecycle = ['preinstall', 'install', 'postinstall'].filter((s) => scripts[s]);
  if (lifecycle.length > 0) {
    // Severity by the script CONTENT, not by mere presence. An install hook is
    // ubiquitous and mostly benign (npm rebuild, only-allow pnpm, husky, node-gyp,
    // patch-package, a version guard) — charging those the same as a remote-binary
    // dropper inverts severity vs risk. Escalate only on real danger signals.
    const cmds = lifecycle.map((s) => scripts[s] ?? '').join(' ; ');
    const c = cmds.toLowerCase();
    // Unwrap `node -e "<body>"` / `node --eval '<body>'`, then blank out every
    // string/backtick literal. What remains is the CODE the hook actually runs —
    // so a URL, a `.sh`, or an ANSI escape that lives only inside a printed string
    // (a `console.log('… https://memoir.sh')` install banner) no longer reads as a
    // download or an executable artifact.
    const unwrapped = c.replace(/\bnode\s+(?:-e|--eval)\s+(['"])([\s\S]*?)\1/g, ' $2 ');
    const codeOnly = unwrapped.replace(/(['"`])(?:\\.|(?!\1)[\s\S])*?\1/g, '""');
    const pipedToShell =
      /\b(curl|wget|fetch|iwr|invoke-webrequest)\b[^\n]*\|\s*(sh|bash|zsh|node|python\d?|ruby|perl)\b/.test(codeOnly) ||
      /\b(base64\s+(-d|--decode)|atob\s*\(|\beval\s*\(|iex\b|powershell\b[^\n]*-enc)/.test(codeOnly);
    // A real remote-binary dropper needs BOTH a network fetch AND an
    // execute-of-the-fetched-artifact — tested on CODE only (strings blanked), so
    // a printed URL cannot manufacture either half.
    const fetchTok = /\b(curl|wget|iwr|invoke-webrequest|node-fetch|axios)\b|\bfetch\s*\(|\bdownload\s*\(|https?:\/\/\S+\.(?:sh|exe|bin|zip|gz|tgz|dll|dylib|so)\b/.test(codeOnly);
    const execArtifact = /\bchmod\s+\+?x\b|\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash)\s+-c\b|\bspawn(?:sync)?\s*\(|\bexec(?:sync)?\s*\(|&&\s*\.?\/|\.\/[\w./-]+\.(?:sh|bin)\b/.test(codeOnly);
    // A real remote-binary dropper needs BOTH halves; a hook that only PRINTS a
    // banner (its URL/`.sh`/ANSI live inside a blanked string) trips neither and
    // falls through to the honest low/heuristic base tier below.
    const remoteBinary = fetchTok && execArtifact;
    let severity: Finding['severity'];
    let confidence: Finding['confidence'];
    let title: string;
    let why: string;
    if (pipedToShell) {
      severity = 'high';
      confidence = 'confirmed';
      title = 'Install script pipes a remote download into a shell / evals a payload';
      why = 'The install hook fetches and executes remote code before you ever import the package — the canonical supply-chain compromise.';
    } else if (remoteBinary) {
      severity = 'medium';
      confidence = 'strong';
      title = 'Install script downloads and runs a remote binary';
      why = 'The install hook fetches an external artifact and makes it executable — vet the source and the binary before trusting it.';
    } else {
      // Benign one-liner (npm rebuild, only-allow, husky…) or a script FILE whose
      // body is not in the manifest: a mild, worth-noting signal, never an F-driver.
      severity = 'low';
      confidence = 'heuristic';
      title = 'Package runs install-time scripts';
      why = 'An install hook runs at install time; most are routine build/setup, but review what it does before trusting it.';
    }
    findings.push({
      ruleId: 'MTC-SUP-010',
      title: `${title} (${lifecycle.join(', ')})`,
      category: 'supply-chain',
      severity,
      confidence,
      description: `"${name}" executes ${lifecycle.join('/')} script(s) at install time. ${why}`,
      remediation: 'Review the scripts; install with --ignore-scripts where possible and vet what they do.',
      location: { kind: 'package', name },
      evidence: cmds.slice(0, 160),
      owasp: 'LLM03:2025 Supply Chain',
      references: SUP_REF,
      data: { scripts: lifecycle },
    });
  }

  // Only meaningful when the CALLER explicitly asked for a floating spec
  // (`foo@latest`, `^1`, `*`). A bare "scan <name>" has no requested spec — it is
  // unpinned by construction, so reporting it would fire on essentially every
  // package and tell the reader nothing about THIS one. Suppressed in that case.
  if (meta.pinned === false && meta.requestedSpec) {
    findings.push({
      ruleId: 'MTC-SUP-013',
      title: `Package is not version-pinned (${meta.requestedSpec})`,
      category: 'supply-chain',
      // Advice-only (info) — unless install scripts make silent drift dangerous.
      severity: lifecycle.length > 0 ? 'medium' : 'info',
      confidence: 'strong',
      description:
        `"${name}" is installed with a floating/latest spec (${meta.requestedSpec}), so its tool ` +
        `definitions and code can change silently after you approve it — the rug-pull enabler. Pinning is the ` +
        `recommended static control.`,
      remediation: 'Pin an exact version (and commit mcptrustchecker.lock so drift is caught on rescan).',
      location: { kind: 'package', name },
      owasp: 'LLM03:2025 Supply Chain',
      data: { requestedSpec: meta.requestedSpec },
    });
  }

  if (meta.repositoryUrl === null) {
    // When an --online scan already classified verification (repo/none/source/
    // vendor), the missing-repository fact is ALREADY priced by the verification
    // client term (none = -5). Re-charging it here as a scored supply-chain finding
    // double-taxes the same fact, so demote to `info` (recorded, never scored) —
    // mirroring MTC-SUP-012 (license). Offline (`unknown`) the term is skipped, so
    // keep the low signal there as the only repository evidence.
    const known = meta.verification !== undefined && meta.verification !== 'unknown';
    findings.push({
      ruleId: 'MTC-SUP-011',
      title: 'Package declares no source repository',
      category: 'supply-chain',
      severity: known ? 'info' : 'low',
      confidence: 'strong',
      description: `"${name}" declares no repository URL, so its published artifact cannot be compared against reviewable source.`,
      remediation: 'Prefer packages that link to public, reviewable source.',
      location: { kind: 'package', name },
    });
  }
  if (meta.license === null) {
    findings.push({
      ruleId: 'MTC-SUP-012',
      title: 'Package has no license',
      category: 'hygiene',
      // A missing license is a legal/packaging matter, not a security defect:
      // it says nothing about whether the server is safe to run. Recorded for
      // completeness, never scored — a security grade must not be moved by it.
      severity: 'info',
      confidence: 'strong',
      description: `"${name}" has no declared license. This is a legal/reuse concern, not a security finding.`,
      location: { kind: 'package', name },
    });
  }

  return findings;
}

/** Check a package's declared dependencies for squats / known-vuln names. */
export function analyzeDependencies(meta: PackageMeta, config: ResolvedConfig): Finding[] {
  const findings: Finding[] = [];
  const deps = (Array.isArray(meta.dependencies) ? meta.dependencies : []).filter(
    (d): d is string => typeof d === 'string',
  );
  if (deps.length === 0) return findings;
  const protectedList = protectedNames(config);

  for (const dep of deps) {
    const lower = dep.toLowerCase();
    if (protectedList.some((p) => p.toLowerCase() === lower)) continue; // it's a real one

    let squatOf: string | undefined;
    if (KNOWN_SQUATS[lower]) squatOf = KNOWN_SQUATS[lower];
    else if (FAKE_SCOPE_PATTERNS.some((re) => re.test(dep))) squatOf = '@modelcontextprotocol/*';
    else {
      const sk = skeleton(bareName(lower));
      for (const p of protectedList) {
        const pb = bareName(p.toLowerCase());
        if (pb !== bareName(lower) && skeleton(pb) === sk) {
          squatOf = p;
          break;
        }
      }
    }
    if (squatOf) {
      findings.push({
        ruleId: 'MTC-SUP-014',
        title: `Dependency "${dep}" resembles ${squatOf}`,
        category: 'supply-chain',
        severity: 'medium',
        confidence: 'heuristic',
        description: `A declared dependency "${dep}" looks like a squat of "${squatOf}" — a transitive supply-chain risk.`,
        remediation: `Confirm the dependency is the intended "${squatOf}".`,
        location: { kind: 'package', name: meta.name ?? dep },
        owasp: 'LLM03:2025 Supply Chain',
        data: { dependency: dep, target: squatOf },
      });
      continue;
    }
    const vuln = KNOWN_VULNS.find((v) => v.package === dep);
    if (vuln) {
      findings.push({
        ruleId: 'MTC-SUP-014',
        title: `Dependency "${dep}" has a known advisory (${vuln.id})`,
        category: 'supply-chain',
        severity: 'low',
        confidence: 'heuristic',
        description: `Declared dependency "${dep}" matches a known-vulnerable package (${vuln.id}); the pinned version is not resolvable from metadata, so verify it is patched.`,
        remediation: `Ensure "${dep}" is upgraded past the ${vuln.id} fix.`,
        location: { kind: 'package', name: meta.name ?? dep },
        references: [vuln.reference],
        owasp: 'LLM03:2025 Supply Chain',
        data: { dependency: dep, advisory: vuln.id },
      });
    }
  }
  return findings;
}

/** Turn a failed published-artifact read into an honest finding (never silent). */
export function analyzeArtifactError(meta: PackageMeta): Finding[] {
  if (meta.requestedVersionMissing) {
    return [
      {
        ruleId: 'MTC-SUP-015',
        title: 'Pinned version is not published in the registry',
        category: 'supply-chain',
        severity: 'medium',
        confidence: 'strong',
        description:
          `The exact version you pinned (${meta.version ?? meta.requestedSpec ?? 'requested'}) is not listed by the ` +
          `registry — it may have been unpublished or yanked, or a hostile registry response may be hiding it to serve ` +
          `a different "latest". The scanner did NOT silently substitute another version: no source was read and no ` +
          `byte pin was recorded for a version that isn't there.`,
        remediation:
          'Confirm the version still exists and is the one you intend to install; if it was yanked, pin a known-good ' +
          'version and re-pin. Treat an unexpectedly-missing pinned version as a supply-chain signal.',
        location: { kind: 'package', name: meta.name },
        owasp: 'LLM03:2025 Supply Chain',
        evidence: `requested ${meta.requestedSpec ?? meta.version ?? ''}`.trim(),
      },
    ];
  }
  const err = meta.artifactError;
  if (!err) return [];
  if (err.kind === 'integrity' || err.kind === 'untrusted-redirect') {
    return [
      {
        ruleId: 'MTC-TOFU-003',
        title: 'Published artifact failed integrity verification',
        category: 'supply-chain',
        severity: 'critical',
        confidence: 'confirmed',
        description:
          `The published artifact for this package could not be verified against the registry's own declared hash ` +
          `(or was served from a host outside the registry's allowlist). Its bytes were NOT trusted, scanned, or ` +
          `pinned. This is exactly the signal a CDN/MITM tamper or a spoofed registry response would produce.\n  • ${err.detail}`,
        remediation:
          'Do not install this package until resolved: re-fetch from a trusted network, confirm the registry ' +
          'metadata, and compare the artifact hash against a known-good source.',
        location: { kind: 'package', name: meta.name },
        owasp: 'LLM03:2025 Supply Chain',
        evidence: err.detail,
      },
    ];
  }
  // Transient/other: not an attack claim, but the scan is NOT verified — say so.
  return [
    {
      ruleId: 'MTC-TOFU-004',
      title: 'Published-source byte check did not run',
      category: 'supply-chain',
      severity: 'info',
      confidence: 'heuristic',
      description:
        `An online scan was requested but the published artifact could not be downloaded, so the implementation ` +
        `source was NOT read and the byte-level integrity pin was NOT recorded. This scan reflects registry ` +
        `metadata only — treat it as incomplete, not as a clean bill of health.\n  • ${err.detail}`,
      remediation: 'Re-run the scan when the registry/network is reachable to complete the source-level analysis.',
      location: { kind: 'package', name: meta.name },
      evidence: err.detail,
    },
  ];
}

export const supplyChainDetector: Detector = {
  id: 'supply-chain',
  stage: 5,
  title: 'Supply-chain & typosquatting',
  run(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const meta = ctx.surface.packageMeta;
    const name = meta?.name ?? (ctx.surface.source.kind === 'package' ? ctx.surface.id : undefined);
    if (name) findings.push(...analyzeTyposquat(name, meta, ctx.config));
    if (meta) {
      findings.push(...analyzeProvenance(meta));
      findings.push(...analyzeDependencies(meta, ctx.config));
      findings.push(...analyzeArtifactError(meta));
    }
    return findings;
  },
};
