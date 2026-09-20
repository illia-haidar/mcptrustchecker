/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Interactive OAuth 2.0 login for scanning protected remote MCP servers.
 *
 * Modern remote MCP servers gate their `/mcp` endpoint behind OAuth (the MCP
 * authorization spec: discovery → dynamic client registration → authorization-
 * code + PKCE). A static header can't authenticate there. This implements the
 * client half of that flow for the CLI: a loopback callback server catches the
 * redirect, the browser is opened for the user's sign-in, and the SDK exchanges
 * the code for an access token — which it then attaches to the MCP handshake.
 *
 * Tokens are held in memory for the duration of one scan only — nothing is
 * written to disk, consistent with the tool's local-first, no-account stance.
 */
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientMetadata,
  OAuthTokens,
  OAuthClientInformationFull,
} from '@modelcontextprotocol/sdk/shared/auth.js';

const CLIENT_NAME = 'MCP Trust Checker';
/** How long to wait for the user to finish signing in in their browser. */
export const OAUTH_CALLBACK_TIMEOUT_MS = 180_000;

/** Open a URL in the user's default browser (best-effort, cross-platform). */
export function openBrowser(url: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '', url]]
        : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {
      /* the URL is also printed, so the user can open it manually */
    });
    child.unref();
  } catch {
    /* ignore — non-fatal, the URL is printed for manual use */
  }
}

/** Parse an OAuth redirect request URL into a code (+ state), or a descriptive error. */
export function parseCallback(reqUrl: string | undefined): { code?: string; state?: string; error?: Error } {
  const parsed = new URL(reqUrl || '', 'http://127.0.0.1');
  const code = parsed.searchParams.get('code');
  const state = parsed.searchParams.get('state') || undefined;
  if (code) return { code, state };
  const error = parsed.searchParams.get('error');
  if (error) {
    const desc = parsed.searchParams.get('error_description');
    return { error: new Error(`OAuth authorization failed: ${error}${desc ? ` — ${desc}` : ''}`) };
  }
  return { error: new Error('OAuth callback carried no authorization code.') };
}

export interface CallbackServer {
  /** The loopback redirect URI to register and redirect back to. */
  redirectUrl: string;
  /** The CSRF `state` value the authorization request must echo back. */
  state: string;
  /** Resolves with the authorization code once the browser redirects back. */
  waitForCode(): Promise<string>;
  /** Shut the loopback server down. */
  close(): void;
}

const OK_PAGE =
  '<!doctype html><meta charset="utf-8"><title>Authorized</title>' +
  '<body style="font-family:system-ui,sans-serif;background:#07080b;color:#eef1f6;text-align:center;padding:64px 24px">' +
  '<h1 style="color:#c4f542">✓ Authorized</h1>' +
  '<p>You can close this tab and return to the terminal.</p>' +
  '<script>setTimeout(function(){window.close()},1500)</script></body>';

/** Start a loopback HTTP server on a free port to receive the OAuth redirect. */
export async function startCallbackServer(): Promise<CallbackServer> {
  let resolveCode!: (code: string) => void;
  let rejectCode!: (err: Error) => void;
  const codePromise = new Promise<string>((res, rej) => {
    resolveCode = res;
    rejectCode = rej;
  });

  const expectedState = randomUUID();
  const server = createServer((req, res) => {
    const parsed = new URL(req.url || '', 'http://127.0.0.1');
    if (parsed.pathname !== '/callback') {
      res.writeHead(404);
      res.end();
      return;
    }
    const { code, state, error } = parseCallback(req.url);
    // Require the CSRF state to match before settling — a stray/forged local
    // request (or a page spraying the ephemeral port) can neither complete NOR
    // abort the sign-in.
    if (state !== expectedState) {
      res.writeHead(400, { 'content-type': 'text/html' });
      res.end('<!doctype html><meta charset="utf-8"><body>Invalid OAuth state.</body>');
      return;
    }
    if (code) {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(OK_PAGE);
      resolveCode(code);
    } else {
      res.writeHead(400, { 'content-type': 'text/html' });
      res.end(`<!doctype html><meta charset="utf-8"><body>${error!.message}</body>`);
      rejectCode(error!);
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const redirectUrl = `http://127.0.0.1:${port}/callback`;

  // Race the callback against a timeout, but ALWAYS clear the timer once the
  // code arrives — a lingering setTimeout would keep the event loop (and the
  // whole CLI, after the scan finishes) alive until it fires.
  const waitForCode = (): Promise<string> =>
    new Promise<string>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('Timed out waiting for the browser sign-in (3 min). Re-run to try again.')),
        OAUTH_CALLBACK_TIMEOUT_MS,
      );
      timer.unref?.();
      codePromise.then(
        (code) => {
          clearTimeout(timer);
          resolve(code);
        },
        (err) => {
          clearTimeout(timer);
          reject(err);
        },
      );
    });

  return {
    redirectUrl,
    state: expectedState,
    waitForCode,
    close: () => {
      try {
        server.close();
      } catch {
        /* already closed */
      }
    },
  };
}

/**
 * In-memory `OAuthClientProvider`. Holds the dynamically-registered client,
 * tokens and PKCE verifier for a single scan; opens the browser on redirect.
 */
export class CliOAuthProvider implements OAuthClientProvider {
  private _clientInformation?: OAuthClientInformationFull;
  private _tokens?: OAuthTokens;
  private _codeVerifier?: string;

  constructor(
    private readonly _redirectUrl: string,
    private readonly _scope: string | undefined,
    private readonly _onAuthorize: (url: URL) => void,
    private readonly _state: string,
  ) {}

  get redirectUrl(): string {
    return this._redirectUrl;
  }

  /** CSRF nonce echoed through the authorization request (OAuth 2.1 hardening). */
  state(): string {
    return this._state;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: CLIENT_NAME,
      redirect_uris: [this._redirectUrl],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
      ...(this._scope ? { scope: this._scope } : {}),
    };
  }

  clientInformation(): OAuthClientInformationFull | undefined {
    return this._clientInformation;
  }

  saveClientInformation(info: OAuthClientInformationFull): void {
    this._clientInformation = info;
  }

  tokens(): OAuthTokens | undefined {
    return this._tokens;
  }

  saveTokens(tokens: OAuthTokens): void {
    this._tokens = tokens;
  }

  redirectToAuthorization(authorizationUrl: URL): void {
    this._onAuthorize(authorizationUrl);
  }

  saveCodeVerifier(codeVerifier: string): void {
    this._codeVerifier = codeVerifier;
  }

  codeVerifier(): string {
    if (!this._codeVerifier) throw new Error('No PKCE code verifier saved.');
    return this._codeVerifier;
  }
}
