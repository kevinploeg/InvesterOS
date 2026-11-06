import { createHash, randomBytes } from 'node:crypto';
import type pg from 'pg';
import { withAnonymousTx, withUserTx } from '../db';
import type { RequestContext } from '../context';
import { newId, isUuid } from '../ids';
import type { AuthConfig } from './config';

export interface Session {
  sessionId: string;
  userId: string;
  activeTenantId: string | null;
  activeMembershipId: string | null;
  expiresAt: Date;
}

export const hashToken = (token: string): Buffer => createHash('sha256').update(token, 'utf8').digest();

/** Maps a verified IdP identity to a user. Bound to (issuer, subject); e-mail is never used. */
export async function resolveIdentity(pool: pg.Pool, issuer: string, subject: string): Promise<string | null> {
  return withAnonymousTx(pool, async (tx) => {
    const r = await tx.query<{ id: string | null }>('SELECT auth.resolve_identity($1, $2) AS id', [issuer, subject]);
    return r.rows[0]?.id ?? null;
  });
}

/**
 * Creates a fresh session (new random token => rotation on every login). The previous session,
 * if its token is passed, is revoked. Default active tenant: the user's first active membership.
 */
export async function createSession(
  pool: pg.Pool,
  cfg: Pick<AuthConfig, 'absoluteTtlMs'>,
  userId: string,
  previousToken?: string,
): Promise<{ token: string; session: Session }> {
  const token = randomBytes(32).toString('base64url');
  return withUserTx(pool, userId, async (tx) => {
    if (previousToken) {
      await tx.query('UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL', [hashToken(previousToken)]);
    }
    const m = await tx.query<{ tenant_id: string; id: string }>(
      `SELECT m.tenant_id, m.id FROM tenant_memberships m JOIN tenants t ON t.id = m.tenant_id
       WHERE m.user_id = $1 AND m.status = 'active' AND t.status = 'active' ORDER BY t.slug LIMIT 1`,
      [userId],
    );
    const id = newId();
    const expiresAt = new Date(Date.now() + cfg.absoluteTtlMs);
    const tenantId = m.rows[0]?.tenant_id ?? null;
    const membershipId = m.rows[0]?.id ?? null;
    await tx.query(
      `INSERT INTO sessions (id, token_hash, user_id, active_tenant_id, active_membership_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, hashToken(token), userId, tenantId, membershipId, expiresAt],
    );
    return { token, session: { sessionId: id, userId, activeTenantId: tenantId, activeMembershipId: membershipId, expiresAt } };
  });
}

/** Resolves a session cookie. Returns null if unknown, revoked, expired, idle too long, or the user is disabled. */
export async function getSession(pool: pg.Pool, cfg: Pick<AuthConfig, 'idleSeconds'>, token: string | undefined): Promise<Session | null> {
  if (!token || token.length < 32 || token.length > 128) return null;
  return withAnonymousTx(pool, async (tx) => {
    const r = await tx.query<{ session_id: string; user_id: string; active_tenant_id: string | null; active_membership_id: string | null; expires_at: Date }>(
      'SELECT * FROM auth.lookup_session($1, $2)',
      [hashToken(token), cfg.idleSeconds],
    );
    const row = r.rows[0];
    if (!row) return null;
    return {
      sessionId: row.session_id,
      userId: row.user_id,
      activeTenantId: row.active_tenant_id,
      activeMembershipId: row.active_membership_id,
      expiresAt: row.expires_at,
    };
  });
}

export async function revokeSession(pool: pg.Pool, session: Session): Promise<void> {
  await withUserTx(pool, session.userId, (tx) => tx.query('UPDATE sessions SET revoked_at = now() WHERE id = $1', [session.sessionId]));
}

export interface MembershipSummary {
  tenantId: string;
  tenantSlug: string;
  tenantName: string;
  membershipId: string;
  locale: string;
}

/** The user's active memberships in active tenants (tenant switcher). */
export async function listMemberships(pool: pg.Pool, userId: string): Promise<MembershipSummary[]> {
  return withUserTx(pool, userId, async (tx) => {
    const r = await tx.query<{ tenant_id: string; slug: string; name: string; id: string; default_locale: string }>(
      `SELECT m.tenant_id, t.slug, t.name, m.id, t.default_locale
       FROM tenant_memberships m JOIN tenants t ON t.id = m.tenant_id
       WHERE m.user_id = $1 AND m.status = 'active' AND t.status = 'active' ORDER BY t.slug`,
      [userId],
    );
    return r.rows.map((x) => ({ tenantId: x.tenant_id, tenantSlug: x.slug, tenantName: x.name, membershipId: x.id, locale: x.default_locale }));
  });
}

/**
 * Turns (session, tenant slug from the URL) into a RequestContext. The slug is only a selector:
 * it must match an ACTIVE membership of the session's user, otherwise null (callers respond 404,
 * never 403, so tenant existence is not disclosed). Selecting a tenant records it as active.
 */
export async function resolveTenantContext(pool: pg.Pool, session: Session, slug: string, requestId: string): Promise<RequestContext | null> {
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(slug)) return null;
  const m = (await listMemberships(pool, session.userId)).find((x) => x.tenantSlug === slug);
  if (!m || !isUuid(m.membershipId)) return null;
  if (session.activeMembershipId !== m.membershipId) {
    await withUserTx(pool, session.userId, (tx) =>
      tx.query('UPDATE sessions SET active_tenant_id = $1, active_membership_id = $2 WHERE id = $3', [m.tenantId, m.membershipId, session.sessionId]),
    );
  }
  return { tenantId: m.tenantId, tenantSlug: m.tenantSlug, userId: session.userId, membershipId: m.membershipId, principalType: 'staff', requestId };
}
