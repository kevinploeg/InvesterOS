/** M0-AC8..11, AC15: OIDC login (against the mock IdP), identity binding, sessions, tenant resolution. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startMockOidc, type MockOidc } from '@investoros/mock-oidc';
import {
  beginLogin, completeLogin, createSession, getSession, hashToken, listMemberships, loadAuthConfig, oidcConfiguration,
  openState, resolveIdentity, resolveTenantContext, revokeSession, sealState, sessionCookieName, stateCookieName, type AuthConfig,
} from '../src/auth';
import { AuthenticationError } from '../src/errors';
import * as fx from '../src/fixtures';
import { harness, type Harness } from './helpers';

const BASE = 'http://127.0.0.1:3999';
let h: Harness;
let idp: MockOidc;
let otherIdp: MockOidc;
let cfg: AuthConfig;
let A: fx.TenantFixture;
let B: fx.TenantFixture;
let aliceId: string;
let aliceA: string;

const envFor = (issuer: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({
  OIDC_ISSUER: issuer,
  OIDC_CLIENT_ID: 'investoros-web',
  OIDC_CLIENT_SECRET: 'test-secret',
  APP_BASE_URL: BASE,
  AUTH_STATE_SECRET: 'x'.repeat(48),
  SESSION_IDLE_MINUTES: '30',
  ...extra,
});

/** Simulates the browser: follow the IdP authorize URL (login_hint auto-login) to the callback URL. */
async function idpRoundTrip(c: AuthConfig, subject: string): Promise<{ callback: URL; stateCookie: string }> {
  const { url, stateCookie } = await beginLogin(c);
  const authz = new URL(url);
  authz.searchParams.set('login_hint', subject);
  const res = await fetch(authz, { redirect: 'manual' });
  expect(res.status).toBe(302);
  return { callback: new URL(res.headers.get('location')!), stateCookie };
}

beforeAll(async () => {
  h = await harness();
  const clients = [{ id: 'investoros-web', secret: 'test-secret', redirectUris: [`${BASE}/auth/callback`] }];
  idp = await startMockOidc({ clients });
  otherIdp = await startMockOidc({ clients, amr: null });
  cfg = loadAuthConfig(envFor(idp.issuer));
  A = await fx.createTenant(h.admin, 'alpha-capital');
  B = await fx.createTenant(h.admin, 'beta-partners');
  aliceId = await fx.createUser(h.admin, { email: 'alice@synthetic.test', displayName: 'Alice', issuer: idp.issuer, subject: 'alice' });
  aliceA = await fx.addMembership(h.admin, A.id, aliceId);
  await fx.addMembership(h.admin, B.id, aliceId);
  await fx.createUser(h.admin, { email: 'disabled@synthetic.test', displayName: 'Dis', issuer: idp.issuer, subject: 'disabled', status: 'disabled' });
});
afterAll(async () => {
  await idp?.close();
  await otherIdp?.close();
  await h?.close();
});

describe('config', () => {
  it('derives redirect URI, TTLs and cookie names; secure cookies over https', () => {
    expect(cfg.redirectUri).toBe(`${BASE}/auth/callback`);
    expect(cfg.idleSeconds).toBe(1800);
    expect(cfg.absoluteTtlMs).toBe(12 * 3_600_000);
    expect(cfg.secureCookies).toBe(false);
    expect(sessionCookieName(cfg)).toBe('ios_session');
    const secure = loadAuthConfig(envFor('https://idp.example', { APP_BASE_URL: 'https://app.example' }));
    expect(secure.secureCookies).toBe(true);
    expect(sessionCookieName(secure)).toBe('__Host-ios_session');
    expect(stateCookieName(secure)).toBe('__Host-ios_oidc');
    expect(stateCookieName(cfg)).toBe('ios_oidc');
  });
  it('rejects incomplete configuration', () => {
    expect(() => loadAuthConfig({ OIDC_ISSUER: 'not a url' })).toThrow();
  });
  it('refuses a non-https issuer that is not loopback', async () => {
    expect(() => oidcConfiguration(loadAuthConfig(envFor('http://idp.example.com')))).toThrow(/https/);
  });
  it('a failed discovery is not cached', async () => {
    const c = loadAuthConfig(envFor('https://127.0.0.1:1'));
    const first = oidcConfiguration(c);
    await expect(first).rejects.toThrow();
    expect(oidcConfiguration(c)).not.toBe(first);
    await oidcConfiguration(c).catch(() => undefined);
  });
});

describe('login state cookie', () => {
  const secret = 'y'.repeat(40);
  const s = { verifier: 'v', state: 's', nonce: 'n', iat: Date.now() };
  it('round-trips and rejects tampering, expiry, future iat and garbage', () => {
    const sealed = sealState(secret, s);
    expect(openState(secret, sealed)).toEqual(s);
    expect(openState('z'.repeat(40), sealed)).toBeNull();
    expect(openState(secret, sealed.replace(/^./, 'A'))).toBeNull();
    expect(openState(secret, `${sealed}x`)).toBeNull();
    expect(openState(secret, undefined)).toBeNull();
    expect(openState(secret, 'nodot')).toBeNull();
    expect(openState(secret, sealed, s.iat + 11 * 60_000)).toBeNull();
    expect(openState(secret, sealed, s.iat - 5 * 60_000)).toBeNull();
    const bad = sealState(secret, { ...s, verifier: 1 as unknown as string });
    expect(openState(secret, bad)).toBeNull();
    const notJson = Buffer.from('{oops').toString('base64url');
    const { createHmac } = require('node:crypto') as typeof import('node:crypto');
    expect(openState(secret, `${notJson}.${createHmac('sha256', secret).update(notJson).digest('base64url')}`)).toBeNull();
  });
});

describe('OIDC authorization code + PKCE (M0-AC8)', () => {
  it('logs in a known identity and binds it by (issuer, subject)', async () => {
    const { callback, stateCookie } = await idpRoundTrip(cfg, 'alice');
    const id = await completeLogin(cfg, callback, stateCookie);
    expect(id).toEqual({ issuer: idp.issuer, subject: 'alice', amr: ['pwd', 'mfa'] });
    expect(await resolveIdentity(h.app, id.issuer, id.subject)).toBe(aliceId);
  });

  it('rejects a callback without, or with a mismatching, state cookie', async () => {
    const { callback } = await idpRoundTrip(cfg, 'alice');
    await expect(completeLogin(cfg, callback, undefined)).rejects.toBeInstanceOf(AuthenticationError);
    const other = await beginLogin(cfg);
    await expect(completeLogin(cfg, callback, other.stateCookie)).rejects.toThrow(/OIDC callback rejected/);
  });

  it('rejects a replayed authorization code', async () => {
    const { callback, stateCookie } = await idpRoundTrip(cfg, 'alice');
    await completeLogin(cfg, callback, stateCookie);
    await expect(completeLogin(cfg, callback, stateCookie)).rejects.toThrow(AuthenticationError);
  });

  it('M0-AC9: same subject at a different issuer does NOT map to the user (no e-mail matching)', async () => {
    const c2 = loadAuthConfig(envFor(otherIdp.issuer));
    const { callback, stateCookie } = await idpRoundTrip(c2, 'alice');
    const id = await completeLogin(c2, callback, stateCookie);
    expect(id.amr).toEqual([]); // amr claim absent
    expect(await resolveIdentity(h.app, id.issuer, id.subject)).toBeNull();
  });

  it('disabled users and unknown subjects resolve to nobody', async () => {
    expect(await resolveIdentity(h.app, idp.issuer, 'disabled')).toBeNull();
    expect(await resolveIdentity(h.app, idp.issuer, 'mallory')).toBeNull();
  });
});

describe('sessions (M0-AC10)', () => {
  it('create → get → revoke; token stored only as a hash', async () => {
    const { token, session } = await createSession(h.app, cfg, aliceId);
    expect(session.activeTenantId).toBe(A.id); // first by slug
    const stored = await h.admin.query('SELECT token_hash FROM sessions WHERE id = $1', [session.sessionId]);
    expect(Buffer.compare(stored.rows[0].token_hash, hashToken(token))).toBe(0);
    expect(JSON.stringify(stored.rows)).not.toContain(token);
    const got = await getSession(h.app, cfg, token);
    expect(got).toMatchObject({ sessionId: session.sessionId, userId: aliceId, activeMembershipId: aliceA });
    await revokeSession(h.app, got!);
    expect(await getSession(h.app, cfg, token)).toBeNull();
  });

  it('rotation: a new login revokes the previous session token', async () => {
    const first = await createSession(h.app, cfg, aliceId);
    const second = await createSession(h.app, cfg, aliceId, first.token);
    expect(await getSession(h.app, cfg, first.token)).toBeNull();
    expect(await getSession(h.app, cfg, second.token)).not.toBeNull();
  });

  it('idle timeout and absolute expiry', async () => {
    const idle = await createSession(h.app, cfg, aliceId);
    await h.admin.query(`UPDATE sessions SET last_seen_at = now() - interval '31 minutes' WHERE id = $1`, [idle.session.sessionId]);
    expect(await getSession(h.app, cfg, idle.token)).toBeNull();
    const old = await createSession(h.app, cfg, aliceId);
    await h.admin.query(`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = $1`, [old.session.sessionId]);
    expect(await getSession(h.app, cfg, old.token)).toBeNull();
  });

  it('a disabled user loses all sessions immediately', async () => {
    const s = await createSession(h.app, cfg, aliceId);
    await h.admin.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [aliceId]);
    try {
      expect(await getSession(h.app, cfg, s.token)).toBeNull();
    } finally {
      await h.admin.query(`UPDATE users SET status = 'active' WHERE id = $1`, [aliceId]);
    }
  });

  it('garbage tokens are rejected without a lookup', async () => {
    expect(await getSession(h.app, cfg, undefined)).toBeNull();
    expect(await getSession(h.app, cfg, 'short')).toBeNull();
    expect(await getSession(h.app, cfg, 'x'.repeat(200))).toBeNull();
    expect(await getSession(h.app, cfg, 'x'.repeat(43))).toBeNull();
  });

  it('a user without memberships gets a session without an active tenant', async () => {
    const lonely = await fx.createUser(h.admin, { email: 'lonely@synthetic.test', displayName: 'L', issuer: idp.issuer, subject: 'lonely' });
    const { session } = await createSession(h.app, cfg, lonely);
    expect(session.activeTenantId).toBeNull();
    expect(await listMemberships(h.app, lonely)).toEqual([]);
  });
});

describe('tenant resolution (M0-AC15, M1 groundwork for multi-membership)', () => {
  it('lists active memberships across tenants', async () => {
    const ms = await listMemberships(h.app, aliceId);
    expect(ms.map((m) => m.tenantSlug)).toEqual(['alpha-capital', 'beta-partners']);
  });

  it('resolves a member slug, switches the active tenant, and returns null for anything else', async () => {
    const { token } = await createSession(h.app, cfg, aliceId);
    const s = (await getSession(h.app, cfg, token))!;
    const ctxA = await resolveTenantContext(h.app, s, 'alpha-capital', 'req-1');
    expect(ctxA).toMatchObject({ tenantId: A.id, membershipId: aliceA, userId: aliceId, principalType: 'staff', requestId: 'req-1' });
    const ctxB = await resolveTenantContext(h.app, s, 'beta-partners', 'req-2');
    expect(ctxB?.tenantId).toBe(B.id);
    expect((await getSession(h.app, cfg, token))?.activeTenantId).toBe(B.id);
    expect(await resolveTenantContext(h.app, s, 'gamma-ventures', 'req-3')).toBeNull();
    expect(await resolveTenantContext(h.app, s, '../etc', 'req-4')).toBeNull();
  });

  it('a suspended membership or suspended tenant no longer resolves', async () => {
    const { token } = await createSession(h.app, cfg, aliceId);
    const s = (await getSession(h.app, cfg, token))!;
    await h.admin.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [B.id]);
    expect(await resolveTenantContext(h.app, s, 'beta-partners', 'r')).toBeNull();
    await h.admin.query(`UPDATE tenants SET status = 'active' WHERE id = $1`, [B.id]);
    await h.admin.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [aliceA]);
    expect(await resolveTenantContext(h.app, s, 'alpha-capital', 'r')).toBeNull();
    await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [aliceA]);
  });
});
