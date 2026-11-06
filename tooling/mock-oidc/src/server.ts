/**
 * Minimal OIDC provider for LOCAL DEVELOPMENT AND TESTS ONLY. Never deploy.
 * Implements discovery, JWKS, authorization code + PKCE (S256 only), RS256 ID tokens.
 * Any subject can log in (the "users" are synthetic seed identities).
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

export interface MockClient {
  id: string;
  secret: string;
  redirectUris: string[];
}

export interface MockOidcOptions {
  port?: number;
  host?: string;
  clients: MockClient[];
  /** Value of the amr claim; default ['pwd', 'mfa']; null omits the claim. */
  amr?: string[] | null;
}

export interface MockOidc {
  issuer: string;
  close(): Promise<void>;
}

interface CodeRecord {
  clientId: string;
  redirectUri: string;
  sub: string;
  nonce?: string;
  challenge: string;
  expires: number;
}

const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

async function body(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

export async function startMockOidc(opts: MockOidcOptions): Promise<MockOidc> {
  const host = opts.host ?? '127.0.0.1';
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'mock-1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, CodeRecord>();
  let issuer = '';

  const server: Server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', issuer || `http://${host}`);
      const json = (status: number, data: unknown): void => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(data));
      };

      if (url.pathname === '/.well-known/openid-configuration') {
        return json(200, {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          scopes_supported: ['openid', 'email', 'profile'],
        });
      }
      if (url.pathname === '/jwks') return json(200, { keys: [jwk] });

      const issueCode = (p: URLSearchParams, sub: string): void => {
        const client = opts.clients.find((c) => c.id === p.get('client_id'));
        const redirectUri = p.get('redirect_uri') ?? '';
        if (!client || !client.redirectUris.includes(redirectUri)) return json(400, { error: 'invalid_client_or_redirect' });
        if (p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256' || !p.get('code_challenge')) {
          return json(400, { error: 'invalid_request' });
        }
        const code = randomBytes(24).toString('base64url');
        codes.set(code, {
          clientId: client.id,
          redirectUri,
          sub,
          nonce: p.get('nonce') ?? undefined,
          challenge: p.get('code_challenge')!,
          expires: Date.now() + 60_000,
        });
        const target = new URL(redirectUri);
        target.searchParams.set('code', code);
        if (p.get('state')) target.searchParams.set('state', p.get('state')!);
        target.searchParams.set('iss', issuer);
        res.writeHead(302, { location: target.toString() });
        res.end();
      };

      if (url.pathname === '/authorize' && req.method === 'GET') {
        const hint = url.searchParams.get('login_hint');
        if (hint) return issueCode(url.searchParams, hint);
        const hidden = [...url.searchParams].map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join('');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(`<!doctype html><title>Mock IdP</title><h1>Mock IdP (synthetic users only)</h1>
          <form method="post" action="/authorize">${hidden}
          <label>Subject <input name="login" autofocus></label> <button type="submit">Sign in</button></form>`);
      }
      if (url.pathname === '/authorize' && req.method === 'POST') {
        const p = await body(req);
        return issueCode(p, p.get('login') ?? '');
      }

      if (url.pathname === '/token' && req.method === 'POST') {
        const p = await body(req);
        let clientId = p.get('client_id');
        let secret = p.get('client_secret');
        const basic = req.headers.authorization;
        if (basic?.startsWith('Basic ')) {
          const [id, s] = Buffer.from(basic.slice(6), 'base64').toString('utf8').split(':');
          clientId = decodeURIComponent(id ?? '');
          secret = decodeURIComponent(s ?? '');
        }
        const client = opts.clients.find((c) => c.id === clientId && c.secret === secret);
        if (!client) return json(401, { error: 'invalid_client' });
        const code = p.get('code') ?? '';
        const rec = codes.get(code);
        codes.delete(code); // single use
        if (!rec || rec.expires < Date.now() || rec.clientId !== client.id || rec.redirectUri !== p.get('redirect_uri')) {
          return json(400, { error: 'invalid_grant' });
        }
        const verifier = p.get('code_verifier') ?? '';
        if (createHash('sha256').update(verifier).digest('base64url') !== rec.challenge) return json(400, { error: 'invalid_grant' });
        const now = Math.floor(Date.now() / 1000);
        const idToken = await new SignJWT({ nonce: rec.nonce, auth_time: now, ...(opts.amr === null ? {} : { amr: opts.amr ?? ['pwd', 'mfa'] }) })
          .setProtectedHeader({ alg: 'RS256', kid: 'mock-1' })
          .setIssuer(issuer)
          .setSubject(rec.sub)
          .setAudience(client.id)
          .setIssuedAt(now)
          .setExpirationTime(now + 300)
          .sign(privateKey);
        return json(200, { access_token: randomBytes(24).toString('base64url'), token_type: 'Bearer', expires_in: 300, id_token: idToken });
      }
      json(404, { error: 'not_found' });
    } catch (err) {
      res.writeHead(500);
      res.end(String(err));
    }
  });

  await new Promise<void>((resolve) => server.listen(opts.port ?? 0, host, resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : opts.port;
  issuer = `http://${host}:${port}`;
  return {
    issuer,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
