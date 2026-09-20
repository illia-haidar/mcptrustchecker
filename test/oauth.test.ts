import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCallback, CliOAuthProvider, startCallbackServer } from '../src/acquire/oauth.js';

test('parseCallback: extracts the authorization code and state', () => {
  assert.deepEqual(parseCallback('/callback?code=abc123&state=x'), { code: 'abc123', state: 'x' });
});

test('parseCallback: surfaces an OAuth error with description', () => {
  const { code, error } = parseCallback('/callback?error=access_denied&error_description=user%20said%20no');
  assert.equal(code, undefined);
  assert.match(error!.message, /access_denied/);
  assert.match(error!.message, /user said no/);
});

test('parseCallback: no code and no error → descriptive error', () => {
  const { error } = parseCallback('/callback');
  assert.match(error!.message, /no authorization code/i);
});

test('CliOAuthProvider: clientMetadata carries loopback redirect + PKCE-friendly grants', () => {
  const p = new CliOAuthProvider('http://127.0.0.1:9999/callback', 'mcp:tools', () => {}, 's');
  const m = p.clientMetadata;
  assert.deepEqual(m.redirect_uris, ['http://127.0.0.1:9999/callback']);
  assert.ok(m.grant_types?.includes('authorization_code'));
  assert.ok(m.grant_types?.includes('refresh_token'));
  assert.deepEqual(m.response_types, ['code']);
  assert.equal(m.scope, 'mcp:tools');
  assert.equal(p.redirectUrl, 'http://127.0.0.1:9999/callback');
});

test('CliOAuthProvider: scope omitted when not requested', () => {
  const p = new CliOAuthProvider('http://127.0.0.1:9999/callback', undefined, () => {}, 's');
  assert.equal(p.clientMetadata.scope, undefined);
});

test('CliOAuthProvider: state() returns the CSRF nonce (or undefined)', () => {
  assert.equal(new CliOAuthProvider('http://127.0.0.1:9999/callback', undefined, () => {}, 'nonce123').state(), 'nonce123');
});

test('CliOAuthProvider: stores/returns tokens, client info, verifier; redirect invokes callback', () => {
  let opened: URL | undefined;
  const p = new CliOAuthProvider('http://127.0.0.1:9999/callback', undefined, (u) => (opened = u), 's');

  assert.equal(p.tokens(), undefined);
  p.saveTokens({ access_token: 't', token_type: 'Bearer' });
  assert.equal(p.tokens()?.access_token, 't');

  assert.equal(p.clientInformation(), undefined);
  p.saveClientInformation({ client_id: 'cid', redirect_uris: ['http://127.0.0.1:9999/callback'] } as never);
  assert.equal(p.clientInformation()?.client_id, 'cid');

  assert.throws(() => p.codeVerifier(), /No PKCE code verifier/);
  p.saveCodeVerifier('verif');
  assert.equal(p.codeVerifier(), 'verif');

  p.redirectToAuthorization(new URL('https://auth.example/authorize?x=1'));
  assert.equal(opened?.href, 'https://auth.example/authorize?x=1');
});

test('startCallbackServer: serves a free loopback port and resolves the code on a state-matched redirect', async () => {
  const cb = await startCallbackServer();
  try {
    assert.match(cb.redirectUrl, /^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    assert.ok(cb.state.length > 0);
    const codeP = cb.waitForCode();
    // A forged request with the WRONG state must NOT settle the flow (400, ignored).
    const bad = await fetch(`${cb.redirectUrl}?code=EVIL&state=wrong`);
    assert.equal(bad.status, 400);
    // A request to another path is ignored too (404).
    const other = await fetch(`${cb.redirectUrl.replace('/callback', '/other')}?code=X&state=${cb.state}`);
    assert.equal(other.status, 404);
    // The genuine, state-matched redirect resolves with the real code.
    const res = await fetch(`${cb.redirectUrl}?code=THECODE&state=${cb.state}`);
    assert.equal(res.status, 200);
    assert.equal(await codeP, 'THECODE');
  } finally {
    cb.close();
  }
});
