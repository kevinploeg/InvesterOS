import * as client from 'openid-client';
import { AuthenticationError } from '../errors';
import type { AuthConfig } from './config';
import { openState, sealState } from './state';

const cache = new Map<string, Promise<client.Configuration>>();

/** OIDC discovery (cached). Plain http is only allowed for loopback issuers (local mock IdP). */
export function oidcConfiguration(cfg: AuthConfig): Promise<client.Configuration> {
  const key = `${cfg.issuer}|${cfg.clientId}`;
  let c = cache.get(key);
  if (!c) {
    const url = new URL(cfg.issuer);
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !loopback) throw new Error('OIDC issuer must use https');
    c = client.discovery(url, cfg.clientId, cfg.clientSecret, undefined, url.protocol === 'http:' ? { execute: [client.allowInsecureRequests] } : undefined);
    c.catch(() => cache.delete(key));
    cache.set(key, c);
  }
  return c;
}

/** Step 1: Authorization Code + PKCE (S256) + state + nonce. Returns the IdP URL and the sealed state cookie value. */
export async function beginLogin(cfg: AuthConfig): Promise<{ url: string; stateCookie: string }> {
  const config = await oidcConfiguration(cfg);
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: cfg.redirectUri,
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  });
  return { url: url.toString(), stateCookie: sealState(cfg.stateSecret, { verifier, state, nonce, iat: Date.now() }) };
}

export interface VerifiedIdentity {
  issuer: string;
  subject: string;
  amr: readonly string[];
}

/** Step 2: validates state, exchanges the code (PKCE), validates the ID token (iss, aud, exp, nonce, signature). */
export async function completeLogin(cfg: AuthConfig, callbackUrl: URL, stateCookie: string | undefined): Promise<VerifiedIdentity> {
  const s = openState(cfg.stateSecret, stateCookie);
  if (!s) throw new AuthenticationError('Login state missing or expired');
  const config = await oidcConfiguration(cfg);
  let tokens;
  try {
    tokens = await client.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: s.verifier,
      expectedState: s.state,
      expectedNonce: s.nonce,
      idTokenExpected: true,
    });
  } catch (err) {
    throw new AuthenticationError(`OIDC callback rejected: ${(err as Error).message}`);
  }
  // idTokenExpected: openid-client has already validated presence, signature, iss, aud, exp and nonce.
  const claims = tokens.claims()!;
  return { issuer: claims.iss, subject: claims.sub, amr: Array.isArray(claims.amr) ? (claims.amr as string[]) : [] };
}
