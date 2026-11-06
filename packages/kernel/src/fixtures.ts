/**
 * Synthetic fixture builders for tests and the dev seed. They use an ADMIN connection
 * (bypasses RLS) and must never be imported by application code (enforced by dependency-cruiser).
 */
import { createHash, randomBytes } from 'node:crypto';
import type pg from 'pg';
import { SessionCredential } from './db';
import { newId } from './ids';
import { SYSTEM_ROLE_KEYS, SYSTEM_ROLES, type SystemRoleKey } from './authz/roles';

export type Admin = pg.ClientBase;

export interface TenantFixture {
  id: string;
  slug: string;
  roles: Record<SystemRoleKey, string>;
}

export async function createTenant(admin: Admin, slug: string, name = slug, locale = 'en'): Promise<TenantFixture> {
  const id = newId();
  await admin.query('INSERT INTO tenants (id, slug, name, default_locale) VALUES ($1, $2, $3, $4)', [id, slug, name, locale]);
  const roles = {} as Record<SystemRoleKey, string>;
  for (const key of SYSTEM_ROLE_KEYS) {
    const roleId = newId();
    roles[key] = roleId;
    await admin.query('INSERT INTO roles (tenant_id, id, key, name, is_system) VALUES ($1, $2, $3, $4, true)', [id, roleId, key, SYSTEM_ROLES[key].name]);
    const perms = [...SYSTEM_ROLES[key].permissions];
    if (perms.length) {
      await admin.query(
        'INSERT INTO role_permissions (tenant_id, role_id, permission) SELECT $1, $2, unnest($3::text[])',
        [id, roleId, perms],
      );
    }
  }
  return { id, slug, roles };
}

export async function createUser(admin: Admin, o: { email: string; displayName: string; issuer: string; subject: string; status?: string }): Promise<string> {
  const id = newId();
  await admin.query('INSERT INTO users (id, email, display_name, status) VALUES ($1, $2, $3, $4)', [id, o.email.toLowerCase(), o.displayName, o.status ?? 'active']);
  await admin.query('INSERT INTO user_identities (id, user_id, issuer, subject) VALUES ($1, $2, $3, $4)', [newId(), id, o.issuer, o.subject]);
  return id;
}

export async function addMembership(admin: Admin, tenantId: string, userId: string, status = 'active'): Promise<string> {
  const id = newId();
  await admin.query('INSERT INTO tenant_memberships (tenant_id, id, user_id, status) VALUES ($1, $2, $3, $4)', [tenantId, id, userId, status]);
  return id;
}

export async function createTeam(admin: Admin, tenantId: string, name: string): Promise<string> {
  const id = newId();
  await admin.query('INSERT INTO teams (tenant_id, id, name) VALUES ($1, $2, $3)', [tenantId, id, name]);
  return id;
}

export async function addTeamMember(admin: Admin, tenantId: string, teamId: string, membershipId: string): Promise<void> {
  await admin.query('INSERT INTO team_members (tenant_id, team_id, membership_id) VALUES ($1, $2, $3)', [tenantId, teamId, membershipId]);
}

export async function assignRole(
  admin: Admin,
  tenantId: string,
  roleId: string,
  to: { membershipId?: string; teamId?: string; scopeId?: string },
): Promise<string> {
  const id = newId();
  await admin.query(
    `INSERT INTO role_assignments (tenant_id, id, role_id, membership_id, team_id, scope_type, scope_id) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [tenantId, id, roleId, to.membershipId ?? null, to.teamId ?? null, to.scopeId ? 'securable' : 'tenant', to.scopeId ?? null],
  );
  return id;
}

export async function createSecurable(admin: Admin, tenantId: string, classification: 'standard' | 'restricted', kind = 'project'): Promise<string> {
  const id = newId();
  await admin.query('INSERT INTO securables (tenant_id, id, kind, classification) VALUES ($1, $2, $3, $4)', [tenantId, id, kind, classification]);
  return id;
}

export async function grantSecurable(
  admin: Admin,
  tenantId: string,
  securableId: string,
  to: { membershipId?: string; teamId?: string; access: 'read' | 'write'; grantedBy: string; expiresAt?: Date },
): Promise<string> {
  const id = newId();
  await admin.query(
    `INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, team_id, access, expires_at, granted_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [tenantId, id, securableId, to.membershipId ?? null, to.teamId ?? null, to.access, to.expiresAt ?? null, to.grantedBy],
  );
  return id;
}

/**
 * Creates a live session for a user directly in the database (fixture shortcut for the OIDC login)
 * and returns its credential. Everything after this goes through auth.begin like a real request.
 */
export async function login(admin: Admin, userId: string, o: { expiresInSeconds?: number } = {}): Promise<SessionCredential> {
  const token = randomBytes(32).toString('base64url');
  await admin.query(
    `INSERT INTO sessions (id, token_hash, user_id, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
    [newId(), createHash('sha256').update(token).digest(), userId, o.expiresInSeconds ?? 3600],
  );
  return new SessionCredential(token);
}
