import { createHmac, timingSafeEqual } from 'node:crypto';

/** Short-lived, HMAC-signed login state (PKCE verifier, state, nonce). Not encrypted: contains no secrets
 *  usable without the authorization code, and lives in an httpOnly cookie for at most 10 minutes. */
export interface LoginState {
  verifier: string;
  state: string;
  nonce: string;
  iat: number;
}

const MAX_AGE_MS = 10 * 60_000;

const mac = (secret: string, data: string): string => createHmac('sha256', secret).update(data).digest('base64url');

export function sealState(secret: string, s: LoginState): string {
  const body = Buffer.from(JSON.stringify(s)).toString('base64url');
  return `${body}.${mac(secret, body)}`;
}

export function openState(secret: string, sealed: string | undefined, now = Date.now()): LoginState | null {
  if (!sealed) return null;
  const [body, sig] = sealed.split('.');
  if (!body || !sig) return null;
  const expected = Buffer.from(mac(secret, body));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  try {
    const s = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as LoginState;
    if (typeof s.iat !== 'number' || now - s.iat > MAX_AGE_MS || now < s.iat - 60_000) return null;
    if (typeof s.verifier !== 'string' || typeof s.state !== 'string' || typeof s.nonce !== 'string') return null;
    return s;
  } catch {
    return null;
  }
}
