/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolveTargets } from '../src/acquire/index.js';
import { RegistryUnavailableError } from '../src/acquire/npm.js';
import { downloadCapped, fetchPackageSource, PackageSourceError } from '../src/acquire/packageSource.js';
import { RegistryUnavailableError as ExportedRegistryUnavailableError } from '../src/index.js';
import { scanSurface } from '../src/engine.js';

// A read failure is not a property of the package. Before 1.16.1 a 503, a
// timeout or a dropped connection on the artifact download became
// `artifactError: network`: the scan fell back to metadata coverage plus an info
// MTC-TOFU-004, and a passing outage was recorded as a grade (nodemw-mcp read
// C 75 on a hiccup, A 96 once the artifact was readable). Now the transient kinds
// throw a retryable RegistryUnavailableError, and only what the artifact itself
// is — gone, tampered, redirected off the registry, over the size cap — is
// recorded. Every registry answer below is a stub; nothing touches the network.

const TARBALL = 'https://registry.npmjs.org/p/-/p-1.0.0.tgz';

function tarEntry(name: string, content: string): Buffer {
  const data = Buffer.from(content, 'utf8');
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write('0', 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([h, padded]);
}

const TGZ = gzipSync(Buffer.concat([tarEntry('package/index.js', 'export const a = 1;\n'), Buffer.alloc(1024)]));
const sri = (buf: Buffer | string) => `sha512-${createHash('sha512').update(buf).digest('base64')}`;

function packument(integrity: string | null = sri(TGZ)): Response {
  return new Response(
    JSON.stringify({
      name: 'p',
      'dist-tags': { latest: '1.0.0' },
      versions: { '1.0.0': { name: 'p', version: '1.0.0', dist: { tarball: TARBALL, ...(integrity ? { integrity } : {}) } } },
    }),
    { status: 200 },
  );
}

type Answer = (url: string, init?: RequestInit) => Response | Promise<Response>;

/** Serve the packument from the registry and `tarball` for the artifact. */
async function withRegistry<T>(tarball: Answer, run: () => Promise<T>, meta: Answer = () => packument()): Promise<T> {
  const orig = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string, init?: RequestInit) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    if (href.includes('/-/')) return tarball(href, init);
    if (href.startsWith('https://registry.npmjs.org/')) return meta(href, init);
    return new Response('', { status: 404 }); // weekly downloads: optional
  }) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = orig;
  }
}

const retryable = (status: number | null, message?: RegExp) => (err: unknown) => {
  assert.ok(err instanceof RegistryUnavailableError, `expected RegistryUnavailableError, got ${String(err)}`);
  assert.equal(err.code, 'MTC_REGISTRY_UNAVAILABLE');
  assert.equal(err.retryable, true);
  assert.equal(err.registryStatus, status);
  assert.equal(err.status, 503);
  assert.equal(err.url, TARBALL);
  if (message) assert.match(err.message, message);
  // The words a scan queue reads as the artifact's own ceiling never appear.
  assert.doesNotMatch(err.message, /timed out|aborted|terminated/i);
  return true;
};

// ── transient: thrown, retryable ─────────────────────────────────────────────

test('artifact 503 throws a retryable error worded "artifact download failed: HTTP 503 … retry shortly"', async () => {
  await withRegistry(
    () => new Response('busy', { status: 503 }),
    () =>
      assert.rejects(
        resolveTargets('p@1.0.0', { online: true }),
        retryable(503, /^artifact download failed: HTTP 503 for https:\/\/registry\.npmjs\.org\/p\/-\/p-1\.0\.0\.tgz — .*retry shortly$/),
      ),
  );
});

test('artifact 408 / 425 / 429 / 502 are retryable too', async () => {
  for (const status of [408, 425, 429, 502]) {
    await withRegistry(
      () => new Response('', { status }),
      () => assert.rejects(resolveTargets('p@1.0.0', { online: true }), retryable(status)),
    );
  }
});

test('a network error on the artifact is retryable and says "could not be reached"', async () => {
  await withRegistry(
    () => {
      throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
    },
    () =>
      assert.rejects(
        resolveTargets('p@1.0.0', { online: true }),
        retryable(null, /^artifact download failed: the registry could not be reached \(fetch failed \(ECONNRESET\)\)/),
      ),
  );
  // undici's own codes can carry the words a queue reads as a ceiling.
  await withRegistry(
    () => {
      throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'UND_ERR_ABORTED' } });
    },
    () =>
      assert.rejects(resolveTargets('p@1.0.0', { online: true }), retryable(null, /could not be reached \(the connection closed early\)/)),
  );
});

test('a PyPI wheel / sdist download hiccup is retryable the same way', async () => {
  const sdist = 'https://files.pythonhosted.org/packages/aa/bb/heropen-2.0.5.tar.gz';
  const orig = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string) => {
    const href = typeof input === 'string' ? input : (input as URL).href;
    if (href === 'https://pypi.org/pypi/heropen/2.0.5/json') {
      return new Response(
        JSON.stringify({
          info: { name: 'heropen', version: '2.0.5', license: 'MIT' },
          urls: [{ packagetype: 'sdist', url: sdist, digests: { sha256: createHash('sha256').update(TGZ).digest('hex') } }],
        }),
        { status: 200 },
      );
    }
    if (href === sdist) return new Response('', { status: 502 });
    return new Response('', { status: 404 });
  }) as typeof fetch;
  try {
    await assert.rejects(
      resolveTargets('heropen@2.0.5', { online: true, registry: 'pypi' }),
      (err: unknown) =>
        err instanceof RegistryUnavailableError && err.retryable && err.registryStatus === 502 && err.url === sdist && /artifact download failed: HTTP 502/.test(err.message),
    );
  } finally {
    globalThis.fetch = orig;
  }
});

test('the download timer firing is retryable, and is never called "timed out"', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let asked!: () => void;
  const tarballAsked = new Promise<void>((resolve) => (asked = resolve));
  await withRegistry(
    (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('This operation was aborted', 'AbortError')));
        asked();
      }),
    async () => {
      const p = resolveTargets('p@1.0.0', { online: true });
      await tarballAsked;
      t.mock.timers.tick(30_000);
      await assert.rejects(p, retryable(null, /could not be reached \(no complete answer within 30000 ms\)/));
    },
  );
});

test('a body cut short of its Content-Length, or a connection that drops mid-body, is retryable', async () => {
  await withRegistry(
    () => new Response(new Uint8Array(TGZ.subarray(0, 10)), { status: 200, headers: { 'content-length': String(TGZ.length) } }),
    () =>
      assert.rejects(
        resolveTargets('p@1.0.0', { online: true }),
        retryable(200, new RegExp(`could not be reached to finish the body \\(10 of ${TGZ.length} bytes arrived\\)`)),
      ),
  );
  const dropping = () =>
    new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(new Uint8Array(TGZ.subarray(0, 10)));
        },
        pull(c) {
          c.error(new TypeError('terminated'));
        },
      }),
      { status: 200 },
    );
  await withRegistry(dropping, () =>
    assert.rejects(resolveTargets('p@1.0.0', { online: true }), retryable(null, /could not be reached \(the connection closed early\)/)),
  );
});

test('a client config entry whose artifact or metadata hiccups fails the config, retryably', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mtc-cfg-1161-'));
  try {
    const cfg = join(dir, 'claude_desktop_config.json');
    writeFileSync(cfg, JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'p@1.0.0'] } } }));
    await withRegistry(
      () => new Response('', { status: 503 }),
      () => assert.rejects(resolveTargets(cfg, { online: true }), retryable(503)),
    );
    await withRegistry(
      () => new Response(new Uint8Array(TGZ), { status: 200 }),
      () =>
        assert.rejects(
          resolveTargets(cfg, { online: true }),
          (err: unknown) => err instanceof RegistryUnavailableError && err.retryable && err.registryStatus === 502,
        ),
      () => new Response('', { status: 502 }),
    );
    // Offline, the same config never asks the registry.
    const [s] = await resolveTargets(cfg, {});
    assert.equal(s!.surface.packageMeta?.name, 'p');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── a refusal that is not transient: thrown, NOT retryable ────────────────────

test('artifact 403 throws, but is not retryable', async () => {
  await withRegistry(
    () => new Response('no', { status: 403 }),
    () =>
      assert.rejects(resolveTargets('p@1.0.0', { online: true }), (err: unknown) => {
        assert.ok(err instanceof RegistryUnavailableError);
        assert.equal(err.retryable, false);
        assert.equal(err.registryStatus, 403);
        assert.equal(err.status, 502);
        // The "artifact download failed: HTTP N" prefix a scan queue classifies by is kept.
        assert.match(err.message, /^artifact download failed: HTTP 403 — the registry refused the artifact download for .* — not a finding about the package$/);
        return true;
      }),
  );
});

// ── what the artifact IS: recorded on the surface, never thrown ──────────────

test('artifact 404 / 410 is recorded (MTC-TOFU-004, metadata coverage), not thrown', async () => {
  for (const status of [404, 410]) {
    const [t] = await withRegistry(
      () => new Response('', { status }),
      () => resolveTargets('p@1.0.0', { online: true }),
    );
    assert.deepEqual(t!.surface.packageMeta?.artifactError, { kind: 'network', detail: `artifact download failed: HTTP ${status}` });
    const r = await scanSurface(t!.surface);
    assert.ok(r.findings.some((f) => f.ruleId === 'MTC-TOFU-004'), `HTTP ${status}`);
    assert.equal(r.coverage.level, 'metadata');
  }
});

test('an integrity mismatch is recorded as tamper evidence (MTC-TOFU-003), not thrown', async () => {
  const [t] = await withRegistry(
    () => new Response(new Uint8Array(TGZ), { status: 200 }),
    () => resolveTargets('p@1.0.0', { online: true }),
    () => packument(sri('DIFFERENT BYTES')),
  );
  assert.equal(t!.surface.packageMeta?.artifactError?.kind, 'integrity');
  const r = await scanSurface(t!.surface);
  assert.equal(r.findings.find((f) => f.ruleId === 'MTC-TOFU-003')?.severity, 'critical');
});

test('a redirect off the registry host is recorded as tamper evidence, not thrown', async () => {
  const [t] = await withRegistry(
    () => new Response(null, { status: 302, headers: { location: 'https://evil.example/p.tgz' } }),
    () => resolveTargets('p@1.0.0', { online: true }),
  );
  assert.equal(t!.surface.packageMeta?.artifactError?.kind, 'untrusted-redirect');
  assert.ok((await scanSurface(t!.surface)).findings.some((f) => f.ruleId === 'MTC-TOFU-003'));
});

test('an artifact over the size cap is recorded ("over the 50 MB safety cap"), not thrown', async () => {
  const [t] = await withRegistry(
    () => new Response(new Uint8Array(1), { status: 200, headers: { 'content-length': String(60 * 1024 * 1024) } }),
    () => resolveTargets('p@1.0.0', { online: true }),
  );
  assert.equal(t!.surface.packageMeta?.artifactError?.kind, 'network');
  assert.match(t!.surface.packageMeta?.artifactError?.detail ?? '', /over the 50 MB safety cap/);
});

test('a readable artifact is read as before (control)', async () => {
  const [t] = await withRegistry(
    () => new Response(new Uint8Array(TGZ), { status: 200, headers: { 'content-length': String(TGZ.length) } }),
    () => resolveTargets('p@1.0.0', { online: true }),
  );
  assert.equal(t!.surface.packageMeta?.artifactError, undefined);
  assert.deepEqual(t!.surface.sourceFiles?.map((f) => f.path), ['index.js']);
  assert.equal(t!.surface.packageMeta?.tarballSha256, createHash('sha256').update(TGZ).digest('hex'));
});

// ── the lower layers keep their contracts ────────────────────────────────────

test('downloadCapped keeps its message (GitHub path) and marks the status transient', async () => {
  for (const [status, transient] of [[503, true], [429, true], [403, false], [404, false]] as const) {
    await assert.rejects(
      downloadCapped(new URL('https://api.github.com/repos/o/r/tarball'), 'github', (async () => new Response('', { status })) as unknown as typeof fetch),
      (err: unknown) =>
        err instanceof PackageSourceError &&
        err.kind === 'network' &&
        err.message === `artifact download failed: HTTP ${status}` &&
        err.registryStatus === status &&
        err.transient === transient,
    );
  }
});

test('fetchPackageSource turns a raw network failure into a transient PackageSourceError', async () => {
  const meta = { registry: 'npm' as const, name: 'p', version: '1.0.0', tarballUrl: TARBALL };
  await assert.rejects(
    fetchPackageSource(meta, (async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch),
    (err: unknown) => err instanceof PackageSourceError && err.transient && err.registryStatus === null && /could not be reached \(fetch failed\)/.test(err.message),
  );
});

test('RegistryUnavailableError is part of the public API', () => {
  assert.equal(ExportedRegistryUnavailableError, RegistryUnavailableError);
});

// ── the CLI: exit 3 for a hiccup, without calling it a bug ───────────────────

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'src', 'cli', 'index.ts');
const TSX = import.meta.resolve('tsx');
const WORK = mkdtempSync(join(tmpdir(), 'mtc-cli-1161-'));
after(() => rmSync(WORK, { recursive: true, force: true }));

// Preloaded into the CLI process: replaces fetch with a stub that answers the
// registry from MTC_TEST_FETCH_PLAN, so the real entry point runs offline.
const STUB = join(WORK, 'stub-fetch.mjs');
writeFileSync(
  STUB,
  `const plan = JSON.parse(process.env.MTC_TEST_FETCH_PLAN || '{}');
globalThis.fetch = async (input) => {
  const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const answer = href.includes('/-/') ? plan.tarball : href.startsWith('https://registry.npmjs.org/') ? plan.packument : href.startsWith('https://api.github.com/') ? plan.github : 404;
  if (answer === 'reset') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
  if (answer !== 200) return new Response('', { status: answer ?? 404 });
  return new Response(JSON.stringify({ name: 'p', 'dist-tags': { latest: '1.0.0' },
    versions: { '1.0.0': { name: 'p', version: '1.0.0', dist: { tarball: ${JSON.stringify(TARBALL)} } } } }), { status: 200 });
};
`,
);

function cli(args: string[], plan: { packument?: number | 'reset'; tarball?: number | 'reset'; github?: number | 'reset' }, opts: { cwd?: string; home?: string } = {}) {
  const res = spawnSync(process.execPath, ['--import', TSX, '--import', pathToFileURL(STUB).href, CLI, ...args, '--no-lock', '--no-pager'], {
    cwd: opts.cwd ?? WORK,
    encoding: 'utf8',
    timeout: 60_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      MTC_TEST_FETCH_PLAN: JSON.stringify(plan),
      ...(opts.home ? { HOME: opts.home, USERPROFILE: opts.home } : {}),
    },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

const notABug = (stderr: string) => {
  assert.doesNotMatch(stderr, /internal error/);
  assert.doesNotMatch(stderr, /This is a bug/);
  assert.doesNotMatch(stderr, /timed out/);
};

test('CLI: a registry 503 on an explicit target exits 3 with the error’s own wording', () => {
  const r = cli(['scan', 'p@1.0.0', '--online', '--json'], { packument: 503 });
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /mcptrustchecker: temporary failure the registry answered HTTP 503 for https:\/\/registry\.npmjs\.org\/p — .*retry shortly/);
  notABug(r.stderr);
  assert.equal(r.stdout, '');
});

test('CLI: an artifact 503 / dropped connection exits 3 ("artifact download failed: HTTP 503", "could not be reached")', () => {
  const r = cli(['scan', 'p@1.0.0', '--online', '--json'], { packument: 200, tarball: 503 });
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /artifact download failed: HTTP 503 for https:\/\/registry\.npmjs\.org\/p\/-\/p-1\.0\.0\.tgz/);
  notABug(r.stderr);
  const reset = cli(['scan', 'p@1.0.0', '--online', '--json'], { packument: 200, tarball: 'reset' });
  assert.equal(reset.status, 3, reset.stderr);
  assert.match(reset.stderr, /artifact download failed: the registry could not be reached/);
  notABug(reset.stderr);
});

test('CLI: a non-retryable registry refusal keeps exit 2 (fix the caller), still not "a bug"', () => {
  const r = cli(['scan', 'p@1.0.0', '--online', '--json'], { packument: 403 });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /mcptrustchecker: error the registry refused the request \(HTTP 403\)/);
  notABug(r.stderr);
});

test('CLI: an artifact 404 is recorded, the scan completes (exit 0) and reports MTC-TOFU-004', () => {
  const r = cli(['scan', 'p@1.0.0', '--online', '--json'], { packument: 200, tarball: 404 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.ok(report.findings.some((f: { ruleId: string }) => f.ruleId === 'MTC-TOFU-004'));
  assert.equal(report.coverage.level, 'metadata');
});

test('CLI --auto-discover: every config failing on a hiccup exits 3; one that resolves keeps the scan going', () => {
  const home = join(WORK, 'home');
  mkdirSync(join(home, '.cursor'), { recursive: true });
  writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'p@1.0.0'] } } }));
  const cwd = join(WORK, 'empty');
  mkdirSync(cwd, { recursive: true });

  const failed = cli(['--online', '--json'], { packument: 503 }, { cwd, home });
  assert.equal(failed.status, 3, failed.stderr);
  assert.match(failed.stderr, /skipped .*mcp\.json: the registry answered HTTP 503/);
  assert.match(failed.stderr, /temporary failure no discovered config could be scanned — the registry answered HTTP 503/);
  notABug(failed.stderr);

  // A second config that needs no registry still resolves: it is scanned and
  // printed, but the run exits 3 — no gate is judged on a partial set.
  mkdirSync(join(home, '.codeium', 'windsurf'), { recursive: true });
  writeFileSync(join(home, '.codeium', 'windsurf', 'mcp_config.json'), JSON.stringify({ mcpServers: { remote: { url: 'https://example.com/mcp' } } }));
  const partial = cli(['--online', '--json'], { packument: 503 }, { cwd, home });
  assert.equal(partial.status, 3, partial.stderr);
  assert.match(partial.stderr, /skipped .*\.cursor[\\/]mcp\.json: the registry answered HTTP 503/);
  assert.match(partial.stderr, /temporary failure some discovered configs could not be scanned, so no gate was evaluated/);
  assert.ok(JSON.parse(partial.stdout), 'the configs that resolved are still reported');
  notABug(partial.stderr);
});

// ── Review of 1.16.1: contracts a scan queue and a hosted API read ────────────────

test('R3-5: the registry\u2019s code is registryStatus; status is what a service built on this should answer', async () => {
  for (const [answer, retryable, status] of [[503, true, 503], [429, true, 503], [403, false, 502], [401, false, 502]] as const) {
    await withRegistry(
      () => new Response(new Uint8Array(TGZ), { status: 200 }),
      () =>
        assert.rejects(resolveTargets('p@1.0.0', { online: true }), (err: unknown) => {
          assert.ok(err instanceof RegistryUnavailableError);
          assert.equal(err.retryable, retryable);
          assert.equal(err.registryStatus, answer);
          assert.equal(err.status, status, 'never the upstream code: a registry 429 is not the service\u2019s own 429');
          return true;
        }),
      () => new Response('', { status: answer }),
    );
  }
});

test('R3-6: a JSON body cut mid-stream is a hiccup, not a ceiling ("terminated" is reworded)', async () => {
  await withRegistry(
    () => new Response(new Uint8Array(TGZ), { status: 200 }),
    () =>
      assert.rejects(resolveTargets('p@1.0.0', { online: true }), (err: unknown) => {
        assert.ok(err instanceof RegistryUnavailableError && err.retryable);
        assert.match(err.message, /unreadable body \(the connection closed early\)/);
        assert.doesNotMatch(err.message, /timed out|aborted|terminated/i);
        return true;
      }),
    () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(new TextEncoder().encode('{"name":"p","versions":{'));
            c.error(new TypeError('terminated'));
          },
        }),
        { status: 200 },
      ),
  );
});

test('R3-9: PyPI answering 200 with no `info` is a malformed answer, not a missing version', async () => {
  const orig = globalThis.fetch;
  for (const body of ['{}', 'null', '{"info":null}']) {
    globalThis.fetch = (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
    try {
      await assert.rejects(resolveTargets('q@1.0.0', { online: true, registry: 'pypi' }), (err: unknown) => {
        assert.ok(err instanceof RegistryUnavailableError && err.retryable, body);
        assert.match(err.message, /unexpected document/);
        return true;
      });
    } finally {
      globalThis.fetch = orig;
    }
  }
  // A real 404 is still a missing version (heropen).
  globalThis.fetch = (async () => new Response('{"message":"Not Found"}', { status: 404 })) as unknown as typeof fetch;
  try {
    const [t] = await resolveTargets('q@9.9.9', { online: true, registry: 'pypi' });
    assert.equal(t!.surface.packageMeta?.requestedVersionMissing, true);
  } finally {
    globalThis.fetch = orig;
  }
});

test('R3-10: a refused artifact keeps the "artifact download failed: HTTP N" prefix a queue classifies by', async () => {
  for (const code of [422, 403]) {
    await withRegistry(
      () => new Response('', { status: code }),
      () =>
        assert.rejects(resolveTargets('p@1.0.0', { online: true }), (err: unknown) => {
          assert.ok(err instanceof RegistryUnavailableError && !err.retryable);
          assert.match(err.message, new RegExp(`^artifact download failed: HTTP ${code} — `));
          return true;
        }),
    );
  }
});

test('R3-8: a GitHub tarball 503 or a dropped connection exits 3, not 2', () => {
  for (const github of [503, 'reset'] as const) {
    const r = cli(['scan', 'o/r', '--json'], { github });
    assert.equal(r.status, 3, r.stderr);
    assert.match(r.stderr, /mcptrustchecker: temporary failure artifact download failed: (?:HTTP 503|the registry could not be reached)/);
    notABug(r.stderr);
  }
  // A missing repository is a verdict: exit 2.
  const gone = cli(['scan', 'o/r', '--json'], { github: 404 });
  assert.equal(gone.status, 2, gone.stderr);
});

test('R3-4: auto-discover with a gate and one config skipped on a hiccup exits 3 — the gate is not judged on a partial set', () => {
  const home = join(WORK, 'home-gate');
  mkdirSync(join(home, '.cursor'), { recursive: true });
  writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { evil: { command: 'npx', args: ['-y', 'p@1.0.0'] } } }));
  mkdirSync(join(home, '.codeium', 'windsurf'), { recursive: true });
  writeFileSync(join(home, '.codeium', 'windsurf', 'mcp_config.json'), JSON.stringify({ mcpServers: { remote: { url: 'https://example.com/mcp' } } }));
  const cwd = join(WORK, 'empty-gate');
  mkdirSync(cwd, { recursive: true });
  const r = cli(['--online', '--min-grade', 'B', '--json'], { packument: 503 }, { cwd, home });
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /no gate was evaluated/);
  assert.ok(JSON.parse(r.stdout));
  notABug(r.stderr);
});
