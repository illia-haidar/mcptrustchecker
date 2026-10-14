/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * MCP Trust Checker core type model.
 *
 * Everything in the engine is expressed against a single normalized, transport-
 * agnostic view of a server — the {@link ServerSurface}. Acquisition adapters
 * (stdio / HTTP / static JSON / client config) all produce a `ServerSurface`;
 * every detector consumes one and emits {@link Finding}s; the scorer turns
 * findings into an auditable {@link Score}. Keeping this model small and pure is
 * what makes the whole tool deterministic and offline-capable.
 */

// ---------------------------------------------------------------------------
// Surface model — the normalized security surface of an MCP server
// ---------------------------------------------------------------------------

/** Where a surface was acquired from (drives which detectors have signal). */
export type SurfaceSourceKind =
  | 'stdio' // spawned a local command and spoke MCP over stdio
  | 'http' // connected to a Streamable-HTTP / SSE endpoint
  | 'manifest' // read a pre-generated tools.json (offline)
  | 'client-config' // extracted from a client config (claude_desktop_config.json, etc.)
  | 'package' // resolved package metadata only (no live surface)
  | 'repo'; // read from a repository archive (source, but not a released artifact)

export interface SurfaceSource {
  kind: SurfaceSourceKind;
  /** Human-readable origin: a path, URL, or package spec. */
  origin: string;
}

/** A JSON-Schema-ish object as advertised by a tool's `inputSchema`. */
export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  required?: string[];
  enum?: unknown[];
  description?: string;
  title?: string;
  format?: string;
  [k: string]: unknown;
}

/**
 * Tool behavior hints as advertised by the server.
 *
 * SECURITY NOTE: these are attacker-controllable and MUST NOT be trusted for
 * security decisions. MCP Trust Checker reads them only to flag when they *contradict*
 * a tool's derived capabilities (annotation-vs-behavior mismatch).
 */
export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  [k: string]: unknown;
}

export interface ToolDef {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: JsonSchema;
  outputSchema?: JsonSchema;
  annotations?: ToolAnnotations;
}

export interface PromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface PromptDef {
  name: string;
  title?: string;
  description?: string;
  arguments?: PromptArgument[];
}

export interface ResourceDef {
  uri?: string;
  uriTemplate?: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

export interface TransportInfo {
  kind: 'stdio' | 'http' | 'sse' | 'unknown';
  /** For HTTP/SSE transports. */
  url?: string;
  /** For stdio transports. */
  command?: string;
  args?: string[];
  /**
   * True when the spawned `command`/`args` originate from untrusted metadata
   * without an executable allowlist — the systemic stdio-RCE class.
   */
  userControlledCommand?: boolean;
  /** Execution-hijacking env vars that were stripped before spawning, if any. */
  droppedEnv?: string[];
}

/** Package/provenance metadata, if the target maps to a known package. */
export interface PackageMeta {
  registry?: 'npm' | 'pypi' | 'unknown';
  name?: string;
  version?: string;
  /** Raw install/lifecycle scripts, if known. */
  scripts?: Record<string, string>;
  dependencies?: string[];
  repositoryUrl?: string | null;
  license?: string | null;
  weeklyDownloads?: number | null;
  /** ISO 8601 publish timestamp of the resolved version, if known. */
  publishedAt?: string | null;
  /** Whether the install spec pins an exact version (false = @latest/floating). */
  pinned?: boolean;
  /** The raw version token from the install spec, if any (e.g. "latest", "^1.2.0"). */
  requestedSpec?: string;
  /**
   * True when an EXACT pinned version was requested but the registry does not
   * list it (unpublished, yanked, or hidden by a hostile registry response). The
   * artifact is deliberately left unresolved rather than silently substituting
   * `latest`, and a finding is raised.
   */
  requestedVersionMissing?: boolean;
  /**
   * Publisher identity, decided from facts the publisher cannot forge (build
   * provenance / a vendor-owned scope). Populated only on an `--online` scan
   * that fetched the registry document; left undefined offline.
   */
  publisher?: string | null;
  /** The known vendor this package belongs to, when established; else null. */
  vendor?: string | null;
  /**
   * How verifiable the source of this package is — a client-adoption-risk
   * signal computed from the registry document on an `--online` scan. `unknown`
   * means provenance was not checked (an offline scan); the verification term is
   * NOT applied in that case, and a coverage caveat records the omission.
   */
  verification?: Verification;
  /**
   * PyPI only: the repository the PEP 740 attestation of the scanned file names
   * (PyPI's integrity API, `--online`), whether or not it counted toward
   * `verification`. Absent when the file has none.
   */
  attestedRepositoryUrl?: string;
  /** PyPI only: that repository differs from `repositoryUrl`, so the attestation was not counted (MTC-SUP-016). */
  attestationRepoMismatch?: boolean;
  /** URL of the published artifact (npm dist.tarball / PyPI sdist or wheel). */
  tarballUrl?: string | null;
  /** Registry-declared artifact hash: SRI (`sha512-<b64>`) or `<algo>:<hex>`. */
  tarballIntegrity?: string | null;
  /** SHA-256 (hex) of the verified artifact the scan actually read — the byte-level pin. */
  tarballSha256?: string;
  /**
   * Set when an `--online` artifact read was attempted but did not complete.
   * `integrity`/`untrusted-redirect` are tamper evidence (a detector raises a
   * finding); `network`/`other` mean the byte check simply could not run.
   */
  artifactError?: { kind: 'integrity' | 'untrusted-redirect' | 'network' | 'other'; detail: string };
}

/** The single normalized object every detector operates on. */
export interface ServerSurface {
  /** Stable identity used for lockfile pinning (package spec, url, or path). */
  id: string;
  source: SurfaceSource;
  server: {
    name?: string;
    version?: string;
    title?: string;
    /** Free-text server instructions — a first-class line-jumping surface. */
    instructions?: string;
    protocolVersion?: string;
    capabilities?: Record<string, unknown>;
  };
  tools: ToolDef[];
  prompts: PromptDef[];
  resources: ResourceDef[];
  transport?: TransportInfo;
  packageMeta?: PackageMeta;
  /**
   * Server implementation source, when available (a local package directory or
   * an extracted tarball). Enables implementation-level analysis — reading what
   * the code *does*, not only what the tool metadata *claims*.
   */
  sourceFiles?: SourceFile[];
  /**
   * The package's own layout, when its files were read: root-level metadata
   * (package.json, pyproject.toml, setup.cfg, server.json) for entry points and
   * license, the license files that ship, and the source files that were NOT
   * read because of a size limit. Drives MCP-server reachability (which files
   * the server can actually run) and honest coverage notes.
   */
  packageLayout?: PackageLayout;
  /**
   * Source maps that ship next to a generated source file (`<file>.map`, or the
   * file its `sourceMappingURL` names), read under their own byte budget. Never
   * scanned as code: they only attribute a finding in a bundle to the original
   * file it came from — the server's own code or a bundled dependency.
   */
  sourceMaps?: SourceFile[];
  /**
   * Where {@link tools} came from, when it matters for how far to trust them:
   *   - `live`   — enumerated from a running server (the real runtime surface).
   *   - `manifest`— a declared static tool list (a client-config/manifest).
   *   - `static` — RECONSTRUCTED from the published source by the static tool
   *      extractor (a package scan that never spawned the server). The tool
   *      metadata is inferred, not observed, so the engine caps the confidence of
   *      any tool-derived finding — a statically-inferred tool can never force the
   *      confirmed-critical F-gate; a live scan is what confirms it.
   * Undefined means the tools arrived with the surface as-declared (no inference).
   */
  toolProvenance?: 'live' | 'manifest' | 'static';
  /**
   * For a `static` surface: how each tool was recovered, keyed by tool name —
   * the registration shape, where its annotations came from, a condition it is
   * registered behind, and what its handler visibly does.
   */
  staticTools?: Record<string, StaticToolOrigin>;
  /** Files where static tool recovery hit a reading cap (some tools may be missing). */
  staticToolsTruncated?: string[];
  /**
   * Registrations the static extractor found but whose tool names it cannot read
   * (`for fn in load_tools(): mcp.add_tool(fn)`): the server registers tools
   * this surface does not list. Set with or without any recovered tools.
   */
  staticToolsUnnamed?: { file: string; line: number }[];
}

/** How the static extractor recovered one tool (see {@link ServerSurface.staticTools}). */
export interface StaticToolOrigin {
  file: string;
  line: number;
  /** `direct` — a literal registration; `helper` — through a local wrapper; `loop` — from a table of definitions. */
  via: 'direct' | 'helper' | 'loop' | 'decorator' | 'decorator-helper';
  /** The helper chain, outermost first. */
  helpers?: string[];
  /**
   * Where the tool's annotations came from: its own declaration, the helper's
   * default, both merged, a declaration that exists but cannot be read (then no
   * default is assumed), or none at all.
   */
  hintSource: 'declared' | 'default' | 'merged' | 'unreadable' | 'none';
  /** A condition the registration sits behind (`if (!client.enabled) return`). */
  condition?: { kind: 'if' | 'else' | 'unless'; expr: string; line: number };
  /** Capability evidence read from the handler body (an HTTP write). */
  behavior?: { tag: CapabilityTag; why: string; line: number }[];
  /**
   * URL / host parameters whose destination the handler pins (1.17): every use
   * builds a URL on a fixed host (`f"{BASE}/{uri}"`) or reduces the value to an
   * id first. Such a parameter is not a destination the model chooses.
   */
  pinned?: string[];
}

export interface SourceFile {
  /** Path relative to the package root. */
  path: string;
  content: string;
}

/** A source file the scan did not read, and why. */
export interface SkippedFile {
  path: string;
  bytes: number;
  reason: 'over-per-file-limit' | 'over-total-limit' | 'over-file-count';
}

export interface PackageLayout {
  /** Root-level metadata files by base name: package.json, pyproject.toml, setup.cfg, server.json. */
  files: Record<string, string>;
  /** Root-level license files that ship in the package (LICENSE, LICENCE.md, COPYING…). */
  licenseFiles: string[];
  /** Source files that exist but were not read, with the reason. */
  skipped: SkippedFile[];
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * How sure we are — the "severity ≠ risk" split: a heuristic
 * keyword hit and a decoded hidden-instruction payload can share a severity
 * but must not carry the same weight — and only `confirmed` findings can fire
 * a hard grade gate.
 */
export type Confidence = 'confirmed' | 'strong' | 'heuristic' | 'speculative';

export type Category =
  | 'injection' // prompt-injection / tool-poisoning / line-jumping
  | 'exfiltration' // secrets & data-exfiltration (incl. toxic-flow)
  | 'permissions' // over-broad scope / dangerous capabilities
  | 'supply-chain' // typosquat / install scripts / provenance / known CVEs
  | 'network' // transport & host posture
  | 'hygiene'; // metadata / documentation / minor issues

export interface FindingLocation {
  kind: 'tool' | 'prompt' | 'resource' | 'server' | 'package' | 'transport' | 'flow';
  /** Name of the tool/prompt/resource, when applicable. */
  name?: string;
  /** Field within the object, e.g. `description` or `inputSchema.properties.path.description`. */
  field?: string;
}

export interface Finding {
  /** Stable rule id, e.g. `MTC-UNI-001`. Used for docs, baselines and SARIF. */
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** What was found and why it matters. */
  description: string;
  remediation?: string;
  location?: FindingLocation;
  /** Concrete evidence: a decoded payload, matched snippet, offending name, etc. */
  evidence?: string;
  /** External references (OWASP, CVE, blog posts, spec sections). */
  references?: string[];
  /** OWASP MCP Top 10 / LLM Top 10 mapping id, when available. */
  owasp?: string;
  /** Structured extras for machine consumers. */
  data?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Capabilities & toxic flows
// ---------------------------------------------------------------------------

export type CapabilityTag =
  | 'untrusted-input' // ingests attacker-controllable content (web, issues, email…)
  | 'sensitive-source' // reads private/local data (files, env, secrets, db…)
  | 'external-sink' // can send data out / act externally (http, email, publish…)
  | 'code-exec' // runs shell commands or evaluates code (a severe sink)
  | 'file-write' // writes or deletes files
  /**
   * Spawns a process whose PROGRAM is fixed in the code (`execFile("git", […])`,
   * `execSync("npm --version")`). A real capability, but not arbitrary code
   * execution: it raises the blast radius to `moderate` at most.
   */
  | 'process-spawn'
  /**
   * Changes state it has access to, as the TOOL ITSELF declares it
   * (`readOnlyHint: false` / `destructiveHint: true` without `openWorldHint:
   * true`) — a database row, a document, local memory. Not a file write and not
   * an exfiltration sink: `moderate` at most.
   */
  | 'state-write';

/** Where a capability tag's evidence was found. */
export type CapabilitySource = 'name' | 'description' | 'param' | 'hint' | 'handler';

export interface ToolCapability {
  tool: string;
  tags: CapabilityTag[];
  /** Why each tag was assigned (keyword/schema evidence), for explainability. */
  reasons: Partial<Record<CapabilityTag, string[]>>;
  /**
   * Where each tag's evidence sits: the tool's name, its description prose, a
   * parameter name, a declared hint, or what its handler does. A role that only
   * prose gives cannot complete a single-tool primitive (MTC-FLOW-001).
   */
  sources?: Partial<Record<CapabilityTag, CapabilitySource[]>>;
  /**
   * The behaviour hints the tool declares, as read (explicit booleans only).
   * They can add tags, never remove one.
   */
  hints?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
  /** For a statically recovered tool: where those hints came from. */
  hintSource?: StaticToolOrigin['hintSource'];
}

/** How much a server could do if the model driving it were manipulated. */
export type CapabilityLevel = 'minimal' | 'moderate' | 'high' | 'critical';

export interface CapabilityProfile {
  level: CapabilityLevel;
  /** Human-readable reasons the level was assigned. */
  reasons: string[];
  /** The union of capability tags observed across the server's tools. */
  tags: CapabilityTag[];
  /**
   * What the server does that the level does not price: a tool that only brings
   * outside content in (a prompt-injection entry point) when the model cannot
   * choose where it comes from. Informational — never a finding, never points.
   */
  observations: string[];
}

// ---------------------------------------------------------------------------
// Coverage — how much of the target the scan could actually inspect
// ---------------------------------------------------------------------------

/**
 * The depth of what the scan actually observed. A Trust grade is only ever as
 * meaningful as its coverage: a clean grade from a metadata-only scan (no tools
 * enumerated, no source read) is NOT the same assurance as a clean grade from a
 * live scan that saw the real runtime tools and read the code.
 */
export type CoverageLevel =
  | 'live' // spoke to a running server — the tool surface is real runtime behavior
  | 'source' // read the implementation source (published tarball, local dir, archive)
  | 'manifest' // a static tool list only (tools.json) — no source, not live
  | 'metadata' // registry/provenance metadata only — no tools, no source
  | 'empty'; // nothing scannable was found

/**
 * How verifiable the source of a package is — the third client-adoption-risk
 * input, alongside capability (blast radius) and coverage (inspection depth).
 * Ordered strongest → weakest by what the CLIENT can actually check before
 * adopting the server ("can I trace and read the code that will run?"):
 *   - `vendor` — proven build provenance to a known vendor's repo, or a
 *      vendor-owned npm scope (an authorization fact the registry enforces).
 *   - `source` — the registry publishes a build attestation (Sigstore / SLSA),
 *      cryptographically binding the artifact to the repo + CI that built it.
 *   - `repo`   — no provenance, but the package declares a public repository the
 *      client can open and read. Weaker than provenance (a `repository` field is
 *      self-declared), yet materially better than nothing: the source is
 *      inspectable. This is the current ecosystem norm — most legitimate MCP
 *      packages are here, so it carries only a light discount, not a red flag.
 *   - `none`   — no provenance and no repository: the source cannot even be
 *      located, so the client is adopting an opaque artifact.
 *   - `unknown`— provenance was NOT checked (an offline scan). The verification
 *      term is skipped so offline and online scans stay honest about it.
 */
export type Verification = 'none' | 'repo' | 'source' | 'vendor' | 'unknown';

export interface Coverage {
  level: CoverageLevel;
  /** Which analysis inputs had signal — drives which detectors could contribute. */
  inputs: {
    /** Tool/prompt/resource surface enumerated (injection, capability, toxic-flow). */
    toolSurface: boolean;
    /** Implementation source analyzed (MTC-SRC sinks). */
    implementationSource: boolean;
    /** Package/provenance metadata present (supply-chain). */
    packageMetadata: boolean;
    /** Spoke to a running server (live stdio/HTTP), so the tools are runtime-real. */
    liveTransport: boolean;
  };
  /** Honest notes on what the scan could NOT see; empty when coverage is complete. */
  caveats: string[];
  /** Source files that exist but were not read (size limits), when any. */
  skipped?: SkippedFile[];
  /**
   * Statically recovered tools that are registered only when a condition holds
   * (`if (!client.enabled) return`), grouped by condition. They are part of the
   * server's surface and are analysed; a server started without that
   * configuration exposes only the rest.
   */
  conditionalTools?: { condition: string; kind: 'if' | 'else' | 'unless'; file: string; line: number; tools: string[] }[];
}

export interface ToxicFlow {
  id: string;
  severity: Severity;
  confidence: Confidence;
  /** Tool(s) that supply the untrusted input, if any. */
  untrustedInput: string[];
  /** Tool(s) that read sensitive data, if any. */
  sensitiveSource: string[];
  /** Tool(s) that can exfiltrate / act externally. */
  externalSink: string[];
  /** True when a single tool holds more than one role (self-contained primitive). */
  selfContained: boolean;
  /** The concrete attack chain of tools (e.g. ["fetch_url","read_file","http_request"]). */
  path?: string[];
  /** True when at least one leg of the path is a direct schema wire (higher plausibility). */
  pathWired?: boolean;
  description: string;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

/** A threat-penalty line: points subtracted by one scored finding. */
export interface ThreatVectorItem {
  kind: 'threat';
  ruleId: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  /** Base weight for the severity. */
  rawWeight: number;
  confidenceMult: number;
  /** Diminishing-returns multiplier for the Nth finding of this rule. */
  diminishingFactor: number;
  /** rawWeight × confidenceMult × diminishingFactor, rounded to 2dp. */
  appliedPenalty: number;
}

/** Which client-adoption-risk term a client vector line represents. */
export type ClientTerm = 'capability-exposure' | 'verification-discount' | 'coverage-honesty';

/**
 * A client-adoption-risk line: one of the three subtract-only terms that evolve
 * the threat score into the client score. Itemised so the whole score stays
 * auditable — there is no black box, every point is a line here.
 */
export interface ClientVectorItem {
  kind: 'client';
  term: ClientTerm;
  /** The input level that set this term (e.g. 'high', 'none', 'metadata'). */
  level: string;
  /** Human-readable explanation of what this term reflects. */
  label: string;
  /** Points subtracted from the threat score (>= 0; a discount is never a bonus). */
  appliedPenalty: number;
}

export type ScoreVectorItem = ThreatVectorItem | ClientVectorItem;

export interface Score {
  /**
   * 0–100, higher is safer — the CLIENT-ADOPTION-RISK score: the threat score
   * after the three client terms (capability exposure, verification discount,
   * coverage honesty). Never rises above {@link threatScore}.
   */
  score: number;
  /**
   * The pure threat score (severity × confidence × diminishing, category caps),
   * before any client-adoption-risk term. Preserved for audit so the three
   * itemised terms in {@link vector} are fully reconstructable from it.
   */
  threatScore: number;
  /** Final grade after gates. */
  grade: Grade;
  /** Grade implied by the raw (client) number, before hard gates. */
  band: Grade;
  /** Strictest grade cap forced by a hard gate, if any. */
  gateCap?: Grade;
  /** Points subtracted per category (after per-category caps). */
  categorySubtotals: Record<Category, number>;
  /** Fully itemized, reconstructable penalty vector. */
  vector: ScoreVectorItem[];
  /** Human-readable descriptions of every gate that fired. */
  gatesFired: string[];
  methodologyVersion: string;
}

// ---------------------------------------------------------------------------
// Integrity (rug-pull / TOFU)
// ---------------------------------------------------------------------------

/**
 * `stale-pin` — the entry was pinned under a DIFFERENT methodology version, so
 * its digest was computed from a different canonical projection. Schema drift
 * cannot be evaluated against it, and reporting that as a rug pull would accuse
 * every user of being attacked the first time they upgrade. The byte-level
 * artifact check is projection-independent and still runs.
 */
export type IntegrityStatus = 'first-seen' | 'unchanged' | 'drift' | 'stale-pin';

export interface SurfaceChange {
  kind: 'tool-added' | 'tool-removed' | 'tool-changed' | 'instructions-changed' | 'package-changed';
  name?: string;
  detail: string;
}

export interface IntegrityResult {
  status: IntegrityStatus;
  currentDigest: string;
  previousDigest?: string;
  /** Populated when status is `drift`, or `stale-pin` with a byte-level change. */
  changes?: SurfaceChange[];
  /** The methodology version the pin was made under. Set on `stale-pin`. */
  pinnedMethodologyVersion?: string;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export interface ScanReport {
  tool: {
    name: string;
    version: string;
    methodologyVersion: string;
  };
  target: {
    id: string;
    source: SurfaceSource;
    server?: { name?: string; version?: string };
  };
  /** ISO timestamp. Omitted for reproducible (deterministic) reports. */
  scannedAt?: string;
  findings: Finding[];
  score: Score;
  capabilities: ToolCapability[];
  /** The server's blast-radius rating (independent of the trust grade). */
  capabilityProfile: CapabilityProfile;
  /** How much of the target the scan actually inspected (a grade's depth). */
  coverage: Coverage;
  toxicFlows: ToxicFlow[];
  integrity?: IntegrityResult;
  /** SHA-256 of the canonicalized surface — the rug-pull fingerprint. */
  surfaceDigest: string;
  stats: {
    tools: number;
    prompts: number;
    resources: number;
    findingsBySeverity: Record<Severity, number>;
  };
  /** The scanned surface itself — present only when asked for (`--surface`, `scanSurface(s, { surface: true })`). */
  surface?: ReportSurface;
}

/** A tool as {@link ReportSurface} lists it: the definition as read, and where a recovered tool is registered. */
export interface ReportSurfaceTool extends ToolDef {
  /** For a `static` surface: the file and line of the registration, and its shape (see {@link StaticToolOrigin.via}). */
  origin?: { file: string; line: number; shape: StaticToolOrigin['via'] };
}

/**
 * The surface a report was computed on — after normalization, before analysis
 * — attached on request so a consumer can show the tools the grade is about.
 * Tools are in the canonical order behind `surfaceDigest` (code-unit by name);
 * text is as read with line endings normalized. Bounded: at most 500 tools,
 * prompts and resources, 8,000 characters per description or title, 64 KB of
 * JSON per schema or annotations object; every cut is listed in `truncated`.
 */
export interface ReportSurface {
  /** `live` — a running server's answer; `manifest` — a declared list; `static` — recovered from source. */
  provenance: 'live' | 'manifest' | 'static';
  /** What was cut or left out, and why — including files where static tool recovery hit a cap. */
  truncated: string[];
  server: { name?: string; version?: string; title?: string };
  tools: ReportSurfaceTool[];
  prompts: PromptDef[];
  resources: ResourceDef[];
}

// ---------------------------------------------------------------------------
// Detector contract
// ---------------------------------------------------------------------------

export interface DetectorContext {
  surface: ServerSurface;
  config: ResolvedConfig;
  /** Per-tool capability tags, computed once by the engine and shared. */
  capabilities: ToolCapability[];
  /**
   * Tool names exposed by OTHER servers in the same scan, for cross-server
   * name-collision / shadowing detection. Empty when scanning a single target.
   */
  siblingTools?: { server: string; name: string }[];
}

export interface Detector {
  id: string;
  /** Pipeline stage number (see docs/architecture.md). */
  stage: number;
  title: string;
  run(ctx: DetectorContext): Finding[] | Promise<Finding[]>;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface McpTrustCheckerConfig {
  /** Rule ids to disable entirely. */
  disabledRules?: string[];
  /** Rule ids whose findings are allowed (suppressed) — an explicit waiver list. */
  allowlist?: string[];
  /** Fail CI when the score is below this threshold (0–100). */
  failUnder?: number;
  /** Fail CI when the grade is worse than this (e.g. "B"). */
  minGrade?: Grade;
  /** Path to the integrity lockfile. */
  lockfile?: string;
  /**
   * When true, the toxic-flow graph assumes the client also exposes generic
   * built-in tools (web-fetch as untrusted input, file/network as sinks), which
   * can complete a trifecta on their own.
   */
  includeBuiltins?: boolean;
  /** Additional package names to hard-protect against typosquatting. */
  protectedPackages?: string[];
  /** Zero-width character count above which a string is treated as an encoded payload. */
  invisibleCharThreshold?: number;
  /**
   * Location-scoped waivers (a baseline). Unlike `allowlist` (which silences a
   * whole rule everywhere), each entry silences a specific finding on a specific
   * tool/field — with a justification that stays in the config for audit.
   * Also loadable from a standalone `.mtcignore` JSON file next to the config.
   */
  suppress?: Suppression[];
  /** Organisational policy the scan is gated against (see {@link Policy}). */
  policy?: Policy;
}

/** A single baseline waiver. `rule` is required; the rest narrow the match. */
export interface Suppression {
  rule: string;
  /** Only suppress on this tool/prompt/resource name (location.name). */
  tool?: string;
  /** Only suppress on this field (location.field). */
  field?: string;
  /** Why the waiver is safe — kept for audit, never affects matching. */
  reason?: string;
}

/** Policy-as-code: declarative rules a server must satisfy, gated in CI. */
export interface Policy {
  /** Fail if the Trust grade is worse than this. */
  minGrade?: Grade;
  /** Fail if the Capability blast-radius exceeds this level. */
  maxCapability?: CapabilityLevel;
  /** Fail if any of these rule ids fired. */
  denyRules?: string[];
  /** Fail if the server exposes any of these capability tags. */
  denyCapabilities?: CapabilityTag[];
}

/** Config with all defaults resolved — what detectors actually see. */
export interface ResolvedConfig
  extends Required<
    Omit<
      McpTrustCheckerConfig,
      'minGrade' | 'lockfile' | 'policy'
    >
  > {
  minGrade?: Grade;
  lockfile?: string;
  policy?: Policy;
}
