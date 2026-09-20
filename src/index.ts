/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * MCP Trust Checker public API.
 *
 * The same engine that powers the CLI is exported here so a marketplace or CI
 * service can embed it directly:
 *
 *   import { scanSurface, surfaceFromManifest } from 'mcptrustchecker';
 *   const surface = surfaceFromManifest(toolsJson, 'my-server');
 *   const report = await scanSurface(surface);
 *   console.log(report.score.grade, report.score.score);
 *
 * Everything in `scanSurface` is deterministic and offline: same methodology
 * version + same surface ⇒ identical score.
 */

export * from './types.js';
export { METHODOLOGY_VERSION, TOOL_VERSION, TOOL_NAME, UNICODE_DATA_VERSION } from './version.js';

// Core engine
export { scanSurface, type ScanOptions } from './engine.js';
export { computeScore } from './scoring/index.js';
export * as scoringModel from './scoring/model.js';

// Config
export { resolveConfig, loadConfigFile, loadIgnoreFile, DEFAULT_CONFIG } from './config.js';
export { evaluatePolicy, type PolicyViolation } from './policy.js';

// Acquisition
export { resolveTargets, type ResolveOptions, type ResolvedTarget } from './acquire/index.js';
export { surfaceFromManifest } from './acquire/manifest.js';
export { surfaceFromPackageDir, readSourceFiles } from './acquire/source.js';
export { acquireStdio, acquireHttp, ALLOWED_COMMANDS, type StdioSpec, type LiveOptions } from './acquire/live.js';
export { parseRepoTarget, surfaceFromGithubRepo, repoLabel, repoHomeUrl, type RepoRef } from './acquire/repo.js';
export { parseClientConfig, isClientConfig, packageFromStdio } from './acquire/clientConfig.js';
export { fetchNpmMeta, fetchPypiMeta } from './acquire/npm.js';

// Registry publishing (opt-in; sends an application, never a verdict)
export {
  buildPublishRequest,
  publishScan,
  publishableTarget,
  publishableTargets,
  publishEndpoint,
  normalizeCategory,
  DEFAULT_PUBLISH_URL,
  PUBLISH_CATEGORIES,
  type PublishTarget,
  type PublishRequest,
  type PublishResponse,
  type PublishResult,
  type PublishOptions,
} from './publish.js';

// Capabilities & flows (useful for custom analysis / UIs)
export { extractCapabilities, extractToolCapability } from './util/capabilities.js';
export { analyzeToxicFlows } from './detectors/toxicFlow.js';

// Integrity / lockfile
export {
  readLockfile,
  writeLockfile,
  pinSurface,
  checkIntegrity,
  emptyLockfile,
  type Lockfile,
  type LockEntry,
} from './lockfile.js';

// Hashing (rug-pull fingerprint)
export { surfaceDigest, canonicalSurface } from './util/hash.js';

// Reporters
export { renderTerminal } from './report/terminal.js';
export { renderJson } from './report/json.js';
export { renderSarif } from './report/sarif.js';
export { renderMarkdown } from './report/markdown.js';
export { renderBadge } from './report/badge.js';

// Detectors (for extension / introspection)
export { DETECTORS } from './detectors/index.js';
