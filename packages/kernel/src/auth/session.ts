import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { SessionCredential, withAuthTx, withUserTx } from '../db';

export interface NewSession {
  credential: SessionCredential;
  sessionId: string;
  userId: string;
  activeTenantSlug: string | null;
  expiresAt: Date;
}

/**
 * Creates a session for a VALIDATED OIDC identity, via the ios_auth pool (ios_app cannot mint sessions).
 * A new random token on every login = rotation; the previous session (if presented) is revoked.
 * Returns null when (issuer, subject) is not linked to an active user. E-mail is never used.
 */
export async function createSession(authPool: pg.Pool, issuer: string, subject: string, previous?: SessionCredential): Promise<NewSession | null> {
  const token = randomBytes(32).toString('base64url');
  const row = await withAuthTx(authPool, async (tx) => {
    const r = await tx.query<{ session_id: string; user_id: string; active_tenant_slug: string | null; expires_at: Date }>(
      'SELECT * FROM auth.create_session($1, $2, $3, $4)',
      [issuer, subject, token, previous?.reveal() ?? null],
    );
    return r.rows[0];
  });
  if (!row) return null;
  return {
    credential: new SessionCredential(token),
    sessionId: row.session_id,
    userId: row.user_id,
    activeTenantSlug: row.active_tenant_slug,
    expiresAt: row.expires_at,
  };
}

export interface MembershipSummary {
  tenantId: string;
  tenantSlug: string;
  tenantName: string;
  membershipId: string;
  locale: string;
}

export interface SessionView {
  userId: string;
  sessionId: string;
  activeTenantSlug: string | null;
  memberships: MembershipSummary[];
}

/** Validates the session in the database and lists the user's active memberships. Null = no valid session. */
export async function getSessionView(appPool: pg.Pool, credential: SessionCredential | undefined): Promise<SessionView | null> {
  if (!credential) return null;
  try {
    return await withUserTx(appPool, credential, async (tx, user) => {
      const r = await tx.query<{ tenant_id: string; slug: string; name: string; id: string; default_locale: string }>(
        `SELECT m.tenant_id, t.slug, t.name, m.id, t.default_locale
         FROM tenant_memberships m JOIN tenants t ON t.id = m.tenant_id
         WHERE m.user_id = app.current_user_id() AND m.status = 'active' AND t.status = 'active' ORDER BY t.slug`,
      );
      return {
        ...user,
        memberships: r.rows.map((x) => ({ tenantId: x.tenant_id, tenantSlug: x.slug, tenantName: x.name, membershipId: x.id, locale: x.default_locale })),
      };
    });
  } catch (err) {
    if ((err as Error).name === 'AuthenticationError') return null;
    throw err;
  }
}

/** Logout: the database revokes the session that the credential itself establishes. */
export async function revokeSession(appPool: pg.Pool, credential: SessionCredential): Promise<void> {
  await withUserTx(appPool, credential, (tx) => tx.query('SELECT auth.revoke_current_session()'));
}
