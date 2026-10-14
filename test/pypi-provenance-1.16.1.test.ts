/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchPypiMeta, RegistryUnavailableError } from '../src/acquire/npm.js';
import { attestedRepoOf, classifyPublisher } from '../src/acquire/publisher.js';
import { analyzeProvenance } from '../src/detectors/supplyChain.js';
import { scanSurface } from '../src/engine.js';
import { RULE_CATALOG } from '../src/data/ruleCatalog.js';
import { loadFixture, makeSurface } from './helpers.js';
import type { PackageMeta } from '../src/types.js';

// PyPI PEP 740 attestations (spec part 2). PyPI's JSON document has no
// provenance field on its files; the attestation lives on the integrity API,
// per file. Until 1.16.1 the engine looked only at the JSON document, so every
// signed PyPI release (staan-mcp 1.0.1, tracehub-mcp 0.12.3, cost-guard-mcp
// 0.3.3, ~2.7k listings on mcprush) read as unsigned.

const STAAN = loadFixture('pypi-staan-mcp-1.0.1.json') as { json: Record<string, any>; provenance: Record<string, any> }; // eslint-disable-line @typescript-eslint/no-explicit-any
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const SDIST = 'staan_mcp-1.0.1.tar.gz';
const WHEEL = 'staan_mcp-1.0.1-py3-none-any.whl';
const INTEGRITY = (file: string) => `https://pypi.org/integrity/staan-mcp/1.0.1/${file}/provenance`;

/** A PyPI JSON document shaped like staan-mcp's, with the repository and files swapped in. */
function pypiDoc(over: { projectUrls?: Record<string, string> | null; files?: 'both' | 'wheel' } = {}): Record<string, any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const doc = clone(STAAN.json);
  if (over.projectUrls !== undefined) doc.info.project_urls = over.projectUrls;
  if (over.files === 'wheel') doc.urls = doc.urls.filter((u: { packagetype: string }) => u.packagetype === 'bdist_wheel');
  return doc;
}

/** A provenance answer whose single bundle names `publisher`. */
function provenanceFor(publisher: Record<string, unknown>): Record<string, any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const p = clone(STAAN.provenance);
  p.attestation_bundles[0].publisher = publisher;
  return p;
}

type Answer = Response | (() => Promise<Response>);
async function withPypi<T>(
  answers: { json?: Answer; integrity?: Answer },
  run: (requested: string[]) => Promise<T>,
): Promise<T> {
  const requested: string[] = [];
  const orig = globalThis.fetch;
  const pick = (a: Answer | undefined) => (typeof a === 'function' ? a() : Promise.resolve((a ?? new Response('', { status: 404 })).clone()));
  globalThis.fetch = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    requested.push(href);
    if (href.startsWith('https://pypi.org/pypi/')) return pick(answers.json);
    // Unset ⇒ PyPI's real "this file has no attestation" answer.
    if (href.startsWith('https://pypi.org/integrity/')) return pick(answers.integrity);
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;
  try {
    return await run(requested);
  } finally {
    globalThis.fetch = orig;
  }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

async function scanMeta(meta: PackageMeta) {
  return scanSurface(makeSurface({ id: meta.name, source: { kind: 'package', origin: meta.name ?? 'p' }, server: { name: meta.name }, packageMeta: meta }));
}

test('staan-mcp 1.0.1: real JSON + integrity 200 ⇒ source, E_ver 0, no "no provenance" wording', async () => {
  const meta = await withPypi({ json: json(STAAN.json), integrity: json(STAAN.provenance) }, async (requested) => {
    const m = await fetchPypiMeta('staan-mcp', '1.0.1');
    // The sdist is the artifact the scan reads, so ITS attestation is the one asked for.
    assert.deepEqual(requested.filter((u) => u.includes('/integrity/')), [INTEGRITY(SDIST)]);
    return m;
  });
  assert.equal(meta.verification, 'source');
  assert.equal(meta.repositoryUrl, 'https://github.com/MarcinWolnyEU/Staan-MCP');
  assert.equal(meta.attestedRepositoryUrl, 'https://github.com/MarcinWolnyEU/Staan-MCP');
  assert.equal(meta.attestationRepoMismatch, undefined);
  assert.equal(meta.publisher, 'marcinwolnyeu');

  const report = await scanMeta(meta);
  const ver = report.score.vector.find((v) => v.kind === 'client' && v.term === 'verification-discount');
  assert.ok(ver && ver.kind === 'client', 'the verification term is applied');
  assert.equal(ver.level, 'source');
  assert.equal(ver!.appliedPenalty, 0);
  assert.doesNotMatch(JSON.stringify(report), /no provenance/i);
  assert.ok(!report.findings.some((f) => f.ruleId === 'MTC-SUP-016'));
});

test('integrity 404 ⇒ as before: repo with a declared repository, none without one', async () => {
  const withRepo = await withPypi({ json: json(STAAN.json), integrity: json({ message: 'No provenance available' }, 404) }, () =>
    fetchPypiMeta('staan-mcp', '1.0.1'),
  );
  assert.equal(withRepo.verification, 'repo');
  assert.equal(withRepo.attestedRepositoryUrl, undefined);

  const bare = await withPypi({ json: json(pypiDoc({ projectUrls: null })) }, () => fetchPypiMeta('staan-mcp', '1.0.1'));
  assert.equal(bare.repositoryUrl, null);
  assert.equal(bare.verification, 'none');
  // The 404 case still raises the (info) no-repository note.
  assert.ok(analyzeProvenance(bare).some((f) => f.ruleId === 'MTC-SUP-011'));
});

const retryable = (status: number | null) => (err: unknown) =>
  err instanceof RegistryUnavailableError &&
  err.retryable &&
  err.registryStatus === status &&
  err.status === 503 &&
  err.url === INTEGRITY(SDIST);

test('integrity 503 / 429 / network error / malformed 200 ⇒ retryable RegistryUnavailableError, never repo or unknown', async () => {
  for (const [answer, status] of [
    [new Response('busy', { status: 503 }), 503],
    [new Response('slow down', { status: 429 }), 429],
    [async () => { throw new TypeError('fetch failed'); }, null],
    [json({ version: 1 }), 200],
    [new Response('<html>', { status: 200 }), 200],
  ] as Array<[Answer, number | null]>) {
    await withPypi({ json: json(STAAN.json), integrity: answer }, async () => {
      await assert.rejects(fetchPypiMeta('staan-mcp', '1.0.1'), retryable(status));
    });
  }
  // A refusal other than "not found" is not a verdict either — just not retryable.
  await withPypi({ json: json(STAAN.json), integrity: new Response('', { status: 403 }) }, async () => {
    await assert.rejects(fetchPypiMeta('staan-mcp', '1.0.1'), (err: unknown) => err instanceof RegistryUnavailableError && !err.retryable && err.registryStatus === 403);
  });
});

test('integrity that never answers times out as a retryable error', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const orig = globalThis.fetch;
  let integrityAsked: () => void = () => {};
  const asked = new Promise<void>((resolve) => { integrityAsked = resolve; });
  globalThis.fetch = (async (input: URL | string, init?: RequestInit) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    if (href.startsWith('https://pypi.org/pypi/')) return json(STAAN.json);
    integrityAsked();
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    });
  }) as unknown as typeof fetch;
  try {
    const p = fetchPypiMeta('staan-mcp', '1.0.1');
    await asked;
    t.mock.timers.tick(8000);
    await assert.rejects(p, (err: unknown) => retryable(null)(err) && /no answer within 8000 ms/.test((err as Error).message));
  } finally {
    globalThis.fetch = orig;
  }
});

test('attestation from github.com/evil/other vs project_urls github.com/a/b ⇒ not counted + MTC-SUP-016 (info)', async () => {
  const doc = pypiDoc({ projectUrls: { Source: 'https://github.com/a/b' } });
  const prov = provenanceFor({ kind: 'GitHub', repository: 'evil/other', workflow: 'release.yml', environment: 'pypi' });
  const meta = await withPypi({ json: json(doc), integrity: json(prov) }, () => fetchPypiMeta('staan-mcp', '1.0.1'));
  assert.equal(meta.verification, 'repo', 'the attestation is not counted');
  assert.equal(meta.attestedRepositoryUrl, 'https://github.com/evil/other');
  assert.equal(meta.attestationRepoMismatch, true);

  const f = analyzeProvenance(meta).find((x) => x.ruleId === 'MTC-SUP-016');
  assert.ok(f, 'the mismatch is recorded');
  assert.equal(f!.severity, 'info');
  assert.match(f!.description, /github\.com\/evil\/other/);
  assert.match(f!.description, /github\.com\/a\/b/);
  assert.equal(RULE_CATALOG.find((r) => r.id === 'MTC-SUP-016')?.severity, 'info');

  // Info never lowers the threat score: the same package without the mismatch scores the same.
  const report = await scanMeta(meta);
  assert.ok(report.findings.some((x) => x.ruleId === 'MTC-SUP-016'));
  const plain = await scanMeta({ ...meta, attestationRepoMismatch: undefined, attestedRepositoryUrl: undefined });
  assert.equal(report.score.threatScore, plain.score.threatScore);
  assert.equal(report.score.score, plain.score.score);
});

test('repository comparison ignores case: MarcinWolnyEU/Staan-MCP matches marcinwolnyeu/staan-mcp', () => {
  const doc = pypiDoc({ projectUrls: { Source: 'https://github.com/marcinwolnyeu/staan-mcp' } });
  const id = classifyPublisher('pypi', 'staan-mcp', doc, 'https://github.com/marcinwolnyeu/staan-mcp', '1.0.1', STAAN.provenance);
  assert.equal(id.verification, 'source');
  assert.equal(id.attestationMismatch, false);
  assert.equal(id.declaredRepo, 'https://github.com/marcinwolnyeu/staan-mcp', 'the declared URL is kept');
});

test('a declared view of the repository (monorepo path, .git, www.) is the same repository', () => {
  for (const declared of [
    'https://github.com/MarcinWolnyEU/Staan-MCP/tree/main/packages/server',
    'https://www.github.com/MarcinWolnyEU/Staan-MCP',
    'https://github.com/MarcinWolnyEU/Staan-MCP.git',
  ]) {
    const id = classifyPublisher('pypi', 'staan-mcp', STAAN.json, declared, '1.0.1', STAAN.provenance);
    assert.equal(id.verification, 'source', declared);
  }
  // A different repository of the same owner is a different repository.
  const other = classifyPublisher('pypi', 'staan-mcp', STAAN.json, 'https://github.com/MarcinWolnyEU/Staan-MCP-fork', '1.0.1', STAAN.provenance);
  assert.equal(other.verification, 'repo');
  assert.equal(other.attestationMismatch, true);
});

test('Staan fixture end to end: integrity 200, publisher matches project_urls ⇒ source', () => {
  const id = classifyPublisher('pypi', 'staan-mcp', STAAN.json, 'https://github.com/MarcinWolnyEU/Staan-MCP', '1.0.1', STAAN.provenance);
  assert.equal(id.verification, 'source');
  assert.equal(id.declaredRepo, 'https://github.com/MarcinWolnyEU/Staan-MCP');
  assert.equal(id.vendor, null, 'an attestation earns source, never a vendor badge');
});

test('the package names no repository ⇒ the attested one is used, and the no-repository note is not raised', async () => {
  const meta = await withPypi({ json: json(pypiDoc({ projectUrls: null })), integrity: json(STAAN.provenance) }, () =>
    fetchPypiMeta('staan-mcp', '1.0.1'),
  );
  assert.equal(meta.repositoryUrl, null);
  assert.equal(meta.verification, 'source');
  assert.equal(meta.attestedRepositoryUrl, 'https://github.com/MarcinWolnyEU/Staan-MCP');
  assert.ok(!analyzeProvenance({ ...meta }).some((f) => f.ruleId === 'MTC-SUP-011' || f.ruleId === 'MTC-SUP-016'));
});

test('wheel-only release: the integrity URL names the wheel, the file the scan reads', async () => {
  await withPypi({ json: json(pypiDoc({ files: 'wheel' })), integrity: json(STAAN.provenance) }, async (requested) => {
    const meta = await fetchPypiMeta('staan-mcp', '1.0.1');
    assert.match(meta.tarballUrl ?? '', /\.whl$/);
    assert.deepEqual(requested.filter((u) => u.includes('/integrity/')), [INTEGRITY(WHEEL)]);
    assert.equal(meta.verification, 'source');
  });
});

test('no published file ⇒ no integrity request and no attestation', async () => {
  const doc = clone(STAAN.json);
  doc.urls = [];
  await withPypi({ json: json(doc), integrity: json(STAAN.provenance) }, async (requested) => {
    const meta = await fetchPypiMeta('staan-mcp', '1.0.1');
    assert.ok(!requested.some((u) => u.includes('/integrity/')));
    assert.equal(meta.verification, 'repo');
  });
});

test('unpinned scan asks for the version the JSON document resolved', async () => {
  await withPypi({ json: json(STAAN.json), integrity: json(STAAN.provenance) }, async (requested) => {
    const meta = await fetchPypiMeta('staan-mcp');
    assert.equal(meta.version, '1.0.1');
    assert.deepEqual(requested.filter((u) => u.includes('/integrity/')), [INTEGRITY(SDIST)]);
  });
});

test('publisher kinds: GitHub and GitLab map to their forge, CircleCI by vcs_origin, Google is not counted', () => {
  assert.equal(attestedRepoOf({ kind: 'GitHub', repository: 'mcpsmiths/tracehub-mcp', workflow: 'release.yml' }), 'https://github.com/mcpsmiths/tracehub-mcp');
  assert.equal(attestedRepoOf({ kind: 'GitLab', repository: 'group/sub/project', workflow_filepath: '.gitlab-ci.yml' }), 'https://gitlab.com/group/sub/project');
  assert.equal(attestedRepoOf({ kind: 'CircleCI', project_id: 'x', pipeline_definition_id: 'y', vcs_origin: 'github.com/o/r' }), 'https://github.com/o/r');
  assert.equal(attestedRepoOf({ kind: 'CircleCI', project_id: 'x', pipeline_definition_id: 'y' }), null);
  assert.equal(attestedRepoOf({ kind: 'Google', email: 'svc@project.iam.gserviceaccount.com' }), null);
  assert.equal(attestedRepoOf({ kind: 'GitHub', repository: 'not a slug' }), null);
  assert.equal(attestedRepoOf({ kind: 'GitHub', repository: 'a/b/../../c' }), null);
  assert.equal(attestedRepoOf(null), null);

  // GitLab: matched by its own URL, including an old-style /tree view below the project.
  const gitlab = provenanceFor({ kind: 'GitLab', repository: 'Group/Sub/Project', workflow_filepath: '.gitlab-ci.yml' });
  for (const declared of ['https://gitlab.com/group/sub/project', 'https://gitlab.com/group/sub/project/-/tree/main', 'https://gitlab.com/group/sub/project/tree/main']) {
    assert.equal(classifyPublisher('pypi', 'p', {}, declared, '1.0.0', gitlab).verification, 'source', declared);
  }
  // Same slug on a different forge is a different repository.
  assert.equal(classifyPublisher('pypi', 'p', {}, 'https://github.com/group/sub', '1.0.0', gitlab).attestationMismatch, true);

  // An unmappable publisher is not counted — and is no mismatch either.
  const google = classifyPublisher('pypi', 'p', {}, 'https://github.com/a/b', '1.0.0', provenanceFor({ kind: 'Google', email: 's@x.iam.gserviceaccount.com' }));
  assert.equal(google.verification, 'repo');
  assert.equal(google.attestationMismatch, false);
  assert.equal(google.attestedRepo, null);
  const googleBare = classifyPublisher('pypi', 'p', {}, null, '1.0.0', provenanceFor({ kind: 'Google', email: 's@x.iam.gserviceaccount.com' }));
  assert.equal(googleBare.verification, 'none');
});

test('empty bundles, bundles without attestations, and an omitted lookup are not attestations', () => {
  const repo = 'https://github.com/MarcinWolnyEU/Staan-MCP';
  assert.equal(classifyPublisher('pypi', 'p', STAAN.json, repo, '1.0.1', { attestation_bundles: [], version: 1 }).verification, 'repo');
  const hollow = clone(STAAN.provenance);
  hollow.attestation_bundles[0].attestations = [];
  assert.equal(classifyPublisher('pypi', 'p', STAAN.json, repo, '1.0.1', hollow).verification, 'repo');
  assert.equal(classifyPublisher('pypi', 'p', STAAN.json, repo, '1.0.1', null).verification, 'repo');
  assert.equal(classifyPublisher('pypi', 'p', STAAN.json, repo).verification, 'repo');
});

test('several bundles: the one matching the declared repository counts', () => {
  const prov = clone(STAAN.provenance);
  prov.attestation_bundles = [
    { ...prov.attestation_bundles[0], publisher: { kind: 'GitHub', repository: 'someone/else', workflow: 'r.yml' } },
    prov.attestation_bundles[0],
  ];
  const id = classifyPublisher('pypi', 'p', STAAN.json, 'https://github.com/MarcinWolnyEU/Staan-MCP', '1.0.1', prov);
  assert.equal(id.verification, 'source');
  assert.equal(id.attestedRepo, 'https://github.com/MarcinWolnyEU/Staan-MCP');
});

test('npm is unchanged: provenance is still accepted without a subject check', () => {
  const doc = { 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { dist: { attestations: { provenance: {} } } } } };
  const id = classifyPublisher('npm', 'x', doc, 'https://github.com/a/b', '1.0.0', STAAN.provenance);
  assert.equal(id.verification, 'source');
  assert.equal(id.attestedRepo, null);
  assert.equal(id.attestationMismatch, false);
});

// A package whose project_urls name only a website or an owner's page names no
// repository the attestation could contradict: a website takes the attested
// repository; an owner's page must agree with the attested owner.
test('a website or an owner page in project_urls is not a named repository', () => {
  const prov = provenanceFor({ kind: 'GitHub', repository: 'MarcinWolnyEU/Staan-MCP', workflow: 'release.yml', environment: 'pypi' });
  const site = classifyPublisher('pypi', 'staan-mcp', pypiDoc(), 'https://staan.example.com', '1.0.1', prov);
  assert.equal(site.verification, 'source');
  assert.equal(site.attestationMismatch, false);
  assert.equal(site.declaredRepo, 'https://github.com/MarcinWolnyEU/Staan-MCP');

  const owner = classifyPublisher('pypi', 'staan-mcp', pypiDoc(), 'https://github.com/marcinwolnyeu', '1.0.1', prov);
  assert.equal(owner.verification, 'source');
  assert.equal(owner.attestationMismatch, false);

  const otherOwner = classifyPublisher('pypi', 'staan-mcp', pypiDoc(), 'https://github.com/someone-else', '1.0.1', prov);
  assert.notEqual(otherOwner.verification, 'source');
  assert.equal(otherOwner.attestationMismatch, true);

  const otherRepo = classifyPublisher('pypi', 'staan-mcp', pypiDoc(), 'https://github.com/MarcinWolnyEU/other', '1.0.1', prov);
  assert.notEqual(otherRepo.verification, 'source');
  assert.equal(otherRepo.attestationMismatch, true);
});
