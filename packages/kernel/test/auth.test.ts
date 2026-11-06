/** M0-AC8..11, AC15: OIDC login (against the mock IdP), identity binding, sessions, tenant resolution. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startMockOidc, type MockOidc } from '@investoros/mock-oidc';
import {
  beginLogin, completeLogin, createSession, getSessionView, loadAuthConfig, oidcConfiguration,
  openState, revokeSession, sealState, sessionCookieName, stateCookieName, type AuthConfig,
} from '../src/auth';
import { SessionCredential, withTenantTx } from '../src/db';
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
    expect((await createSession(h.auth, id.issuer, id.subject))?.userId).toBe(aliceId);
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
    expect(await createSession(h.auth, id.issuer, id.subject)).toBeNull();
  });

  it('disabled users and unknown subjects get no session', async () => {
    expect(await createSession(h.auth, idp.issuer, 'disabled')).toBeNull();
    expect(await createSession(h.auth, idp.issuer, 'mallory')).toBeNull();
  });
});

const view = (c: SessionCredential | undefined) => getSessionView(h.app, c);

describe('sessions (M0-AC10, enforced in the database since M1-WP1)', () => {
  it('create → view → revoke; token stored only as a hash', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    expect(s.activeTenantSlug).toBe('alpha-capital'); // first by slug
    const stored = await h.admin.query('SELECT token_hash FROM sessions WHERE id = $1', [s.sessionId]);
    expect(stored.rows[0].token_hash).toHaveLength(32);
    expect(JSON.stringify(stored.rows)).not.toContain(s.credential.reveal());
    const v = await view(s.credential);
    expect(v).toMatchObject({ sessionId: s.sessionId, userId: aliceId, activeTenantSlug: 'alpha-capital' });
    await revokeSession(h.app, s.credential);
    expect(await view(s.credential)).toBeNull();
    await expect(revokeSession(h.app, s.credential)).rejects.toThrow(/No valid session/);
  });

  it('rotation: a new login revokes the previous session token', async () => {
    const first = (await createSession(h.auth, idp.issuer, 'alice'))!;
    const second = (await createSession(h.auth, idp.issuer, 'alice', first.credential))!;
    expect(await view(first.credential)).toBeNull();
    expect(await view(second.credential)).not.toBeNull();
  });

  it('idle timeout and absolute expiry are database policy', async () => {
    const idle = (await createSession(h.auth, idp.issuer, 'alice'))!;
    await h.admin.query(`UPDATE sessions SET last_seen_at = now() - interval '31 minutes' WHERE id = $1`, [idle.sessionId]);
    expect(await view(idle.credential)).toBeNull();
    const old = (await createSession(h.auth, idp.issuer, 'alice'))!;
    await h.admin.query(`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = $1`, [old.sessionId]);
    expect(await view(old.credential)).toBeNull();
  });

  it('idle tracking writes last_seen_at at most once per 60 s', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    await h.admin.query(`UPDATE sessions SET last_seen_at = now() - interval '30 seconds' WHERE id = $1`, [s.sessionId]);
    const before = (await h.admin.query('SELECT last_seen_at FROM sessions WHERE id = $1', [s.sessionId])).rows[0].last_seen_at;
    await view(s.credential);
    expect((await h.admin.query('SELECT last_seen_at FROM sessions WHERE id = $1', [s.sessionId])).rows[0].last_seen_at).toEqual(before);
    await h.admin.query(`UPDATE sessions SET last_seen_at = now() - interval '5 minutes' WHERE id = $1`, [s.sessionId]);
    await view(s.credential);
    const after = (await h.admin.query('SELECT last_seen_at > now() - interval \'5 seconds\' AS fresh FROM sessions WHERE id = $1', [s.sessionId])).rows[0];
    expect(after.fresh).toBe(true);
  });

  it('a disabled user loses all sessions immediately', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    await h.admin.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [aliceId]);
    try {
      expect(await view(s.credential)).toBeNull();
    } finally {
      await h.admin.query(`UPDATE users SET status = 'active' WHERE id = $1`, [aliceId]);
    }
  });

  it('garbage tokens are rejected', async () => {
    expect(await view(undefined)).toBeNull();
    expect(await view(new SessionCredential('short'))).toBeNull();
    expect(await view(new SessionCredential('x'.repeat(200)))).toBeNull();
    expect(await view(new SessionCredential('x'.repeat(43)))).toBeNull();
  });

  it('only the ios_auth login can create sessions', async () => {
    const r = await h.app.query(`SELECT * FROM auth.create_session($1, 'alice', $2, NULL)`, [idp.issuer, 'y'.repeat(43)]).catch((e) => e);
    expect(r.code).toBe('42501');
    const w = await h.worker.query(`SELECT * FROM auth.create_session($1, 'alice', $2, NULL)`, [idp.issuer, 'y'.repeat(43)]).catch((e) => e);
    expect(w.code).toBe('42501');
    const bad = await h.auth.query(`SELECT * FROM auth.create_session($1, 'alice', 'short', NULL)`, [idp.issuer]).catch((e) => e);
    expect(bad.code).toBe('22023');
  });

  it('a user without memberships gets a session without an active tenant', async () => {
    await fx.createUser(h.admin, { email: 'lonely@synthetic.test', displayName: 'L', issuer: idp.issuer, subject: 'lonely' });
    const s = (await createSession(h.auth, idp.issuer, 'lonely'))!;
    expect(s.activeTenantSlug).toBeNull();
    expect((await view(s.credential))?.memberships).toEqual([]);
  });
});

describe('tenant resolution (M0-AC15) — now decided by auth.begin in the database', () => {
  it('lists active memberships across tenants', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    expect((await view(s.credential))?.memberships.map((m) => m.tenantSlug)).toEqual(['alpha-capital', 'beta-partners']);
  });

  it('a member slug yields a DB-established context; anything else is NotFound', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    const ctxA = await withTenantTx(h.app, s.credential, 'alpha-capital', 'read', async (_tx, ctx) => ctx, 'req-1');
    expect(ctxA).toMatchObject({ tenantId: A.id, membershipId: aliceA, userId: aliceId, principalType: 'staff', requestId: 'req-1', sessionId: s.sessionId });
    expect((await withTenantTx(h.app, s.credential, 'beta-partners', 'read', async (_tx, ctx) => ctx)).tenantId).toBe(B.id);
    await expect(withTenantTx(h.app, s.credential, 'gamma-ventures', 'read', async () => 1)).rejects.toThrow(/Not found/);
    await expect(withTenantTx(h.app, s.credential, '../etc', 'read', async () => 1)).rejects.toThrow(/Not found/);
  });

  it('a suspended membership or suspended tenant no longer resolves', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    await h.admin.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [B.id]);
    await expect(withTenantTx(h.app, s.credential, 'beta-partners', 'read', async () => 1)).rejects.toThrow(/Not found/);
    await h.admin.query(`UPDATE tenants SET status = 'active' WHERE id = $1`, [B.id]);
    await h.admin.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [aliceA]);
    await expect(withTenantTx(h.app, s.credential, 'alpha-capital', 'read', async () => 1)).rejects.toThrow(/Not found/);
    await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [aliceA]);
  });

  it('a revoked session yields AuthenticationError, not NotFound', async () => {
    const s = (await createSession(h.auth, idp.issuer, 'alice'))!;
    await revokeSession(h.app, s.credential);
    await expect(withTenantTx(h.app, s.credential, 'alpha-capital', 'read', async () => 1)).rejects.toThrow(/No valid session/);
  });

  it('getSessionView propagates unexpected errors', async () => {
    const broken = { connect: async () => { throw new Error('db down'); } } as unknown as import('pg').Pool;
    await expect(getSessionView(broken, new SessionCredential('z'.repeat(43)))).rejects.toThrow('db down');
  });
});
