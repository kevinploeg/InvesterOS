/** M0-AC12..14: permission registry, authorization matrix, DB parity. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  assertAllowed, authorize, renderRoleMatrix, isPermission, loadPrincipalAccess, PERMISSION_KEYS, PERMISSIONS, permissionDef,
  SYSTEM_ROLE_KEYS, SYSTEM_ROLES, type Permission, type PrincipalAccess,
} from '../src/authz';
import { withTenantTx, type SessionCredential } from '../src/db';
import { AuthorizationError } from '../src/errors';
import * as fx from '../src/fixtures';
import { asApp, harness, ISSUER, type As, type Harness } from './helpers';

const access = (perms: Iterable<Permission>, extra: Partial<PrincipalAccess> = {}): PrincipalAccess => ({
  membershipActive: true,
  tenantPermissions: new Set(perms),
  scopedPermissions: [],
  restrictedGrants: new Map(),
  ...extra,
});
const X = '00000000-0000-7000-8000-000000000001';
const Y = '00000000-0000-7000-8000-000000000002';

describe('permission registry', () => {
  it('keys are unique and well-formed', () => {
    expect(new Set(PERMISSION_KEYS).size).toBe(PERMISSION_KEYS.length);
    for (const k of PERMISSION_KEYS) expect(k).toMatch(/^[a-z]+(\.[a-z_]+)+$/);
  });
  it('lookups', () => {
    expect(isPermission('projects.read')).toBe(true);
    expect(isPermission('projects.delete_everything')).toBe(false);
    expect(() => permissionDef('nope' as Permission)).toThrow(/Unknown permission/);
  });
  it('no system role holds a permission outside the registry; only compliance has oversight', () => {
    for (const key of SYSTEM_ROLE_KEYS) {
      for (const p of SYSTEM_ROLES[key].permissions) expect(isPermission(p)).toBe(true);
      expect(SYSTEM_ROLES[key].permissions.has('restricted.oversight')).toBe(key === 'compliance');
    }
  });
  it('the reviewed role matrix document is up to date (docs/security/role-matrix.md)', async () => {
    const doc = await readFile(join(__dirname, '..', '..', '..', 'docs', 'security', 'role-matrix.md'), 'utf8');
    expect(doc).toContain(renderRoleMatrix());
  });
});

describe('authorization matrix: every system role × every permission', () => {
  for (const role of SYSTEM_ROLE_KEYS) {
    for (const perm of PERMISSION_KEYS) {
      const held = SYSTEM_ROLES[role].permissions.has(perm);
      it(`${role} ${held ? 'may' : 'may not'} ${perm} (tenant scope, standard resource)`, () => {
        const a = access(SYSTEM_ROLES[role].permissions);
        expect(authorize(a, perm).allowed).toBe(held);
        expect(authorize(a, perm, { securableId: X, classification: 'standard' }).allowed).toBe(held);
      });
    }
  }
});

describe('authorization rules', () => {
  it('inactive membership is always denied', () => {
    expect(authorize(access(PERMISSION_KEYS, { membershipActive: false }), 'projects.read')).toEqual({ allowed: false, reason: 'inactive-membership' });
  });

  it('scoped roles apply only to their securable, and only for scopable permissions', () => {
    const a = access([], { scopedPermissions: [{ securableId: X, permission: 'projects.write' }, { securableId: X, permission: 'ledger.post' }] });
    expect(authorize(a, 'projects.write', { securableId: X, classification: 'standard' })).toMatchObject({ allowed: true, via: 'scoped-role' });
    expect(authorize(a, 'projects.write', { securableId: Y, classification: 'standard' }).allowed).toBe(false);
    expect(authorize(a, 'projects.write').allowed).toBe(false);
    expect(authorize(a, 'ledger.post', { securableId: X, classification: 'standard' }).allowed).toBe(false); // not scopable
  });

  it('restricted: tenant-wide role is not enough without a grant', () => {
    const a = access(SYSTEM_ROLES.owner.permissions);
    expect(authorize(a, 'projects.read', { securableId: X, classification: 'restricted' })).toEqual({ allowed: false, reason: 'restricted-no-grant' });
    expect(authorize(a, 'projects.write', { securableId: X, classification: 'restricted' })).toEqual({ allowed: false, reason: 'restricted-no-grant' });
  });

  it('restricted: read grant allows reads only; write grant allows both', () => {
    const r = access(['projects.read', 'projects.write'], { restrictedGrants: new Map([[X, 'read']]) });
    expect(authorize(r, 'projects.read', { securableId: X, classification: 'restricted' })).toMatchObject({ allowed: true, oversight: false });
    expect(authorize(r, 'projects.write', { securableId: X, classification: 'restricted' })).toEqual({ allowed: false, reason: 'restricted-read-only' });
    const w = access(['projects.read', 'projects.write'], { restrictedGrants: new Map([[X, 'write']]) });
    expect(authorize(w, 'projects.write', { securableId: X, classification: 'restricted' }).allowed).toBe(true);
    expect(authorize(w, 'projects.write', { securableId: Y, classification: 'restricted' }).allowed).toBe(false);
  });

  it('restricted: a grant never substitutes for the permission itself', () => {
    const a = access([], { restrictedGrants: new Map([[X, 'write']]) });
    expect(authorize(a, 'projects.read', { securableId: X, classification: 'restricted' })).toEqual({ allowed: false, reason: 'missing-permission' });
  });

  it('restricted: oversight satisfies reads (flagged), never writes', () => {
    const a = access(SYSTEM_ROLES.compliance.permissions);
    expect(authorize(a, 'projects.read', { securableId: X, classification: 'restricted' })).toEqual({ allowed: true, via: 'tenant-role', oversight: true });
    expect(authorize(a, 'subscriptions.approve', { securableId: X, classification: 'restricted' }).allowed).toBe(false);
  });

  it('assertAllowed throws AuthorizationError with the reason', () => {
    expect(() => assertAllowed(access([]), 'audit.read')).toThrow(AuthorizationError);
    expect(assertAllowed(access(['audit.read']), 'audit.read').allowed).toBe(true);
    try { assertAllowed(access([]), 'audit.read'); } catch (e) {
      expect((e as AuthorizationError).status).toBe(403);
      expect((e as AuthorizationError).reason).toBe('missing-permission');
    }
  });
});

describe('database parity', () => {
  let h: Harness;
  let T: fx.TenantFixture;
  const members: Record<string, { userId: string; membershipId: string; cred: SessionCredential }> = {};
  const as = (m: { cred: SessionCredential }): As => ({ cred: m.cred, slug: 'parity' });
  const access = (m: { cred: SessionCredential }) => withTenantTx(h.app, m.cred, 'parity', 'read', (tx) => loadPrincipalAccess(tx));

  beforeAll(async () => {
    h = await harness();
    T = await fx.createTenant(h.admin, 'parity');
    for (const role of SYSTEM_ROLE_KEYS) {
      const userId = await fx.createUser(h.admin, { email: `${role}@synthetic.test`, displayName: role, issuer: ISSUER, subject: role });
      const membershipId = await fx.addMembership(h.admin, T.id, userId);
      await fx.assignRole(h.admin, T.id, T.roles[role], { membershipId });
      members[role] = { userId, membershipId, cred: await fx.login(h.admin, userId) };
    }
    // team-inherited role
    const userId = await fx.createUser(h.admin, { email: 'teamie@synthetic.test', displayName: 'teamie', issuer: ISSUER, subject: 'teamie' });
    const membershipId = await fx.addMembership(h.admin, T.id, userId);
    const team = await fx.createTeam(h.admin, T.id, 'Compliance desk');
    await fx.addTeamMember(h.admin, T.id, team, membershipId);
    await fx.assignRole(h.admin, T.id, T.roles.compliance, { teamId: team });
    members.teamie = { userId, membershipId, cred: await fx.login(h.admin, userId) };
  });
  afterAll(async () => h?.close());

  it('the DB permission catalog equals the code registry', async () => {
    const r = await h.admin.query<{ key: string; scopable: boolean }>('SELECT key, scopable FROM meta.permissions ORDER BY key');
    expect(r.rows).toEqual(PERMISSIONS.map((p) => ({ key: p.key, scopable: p.scopable })).sort((a, b) => a.key.localeCompare(b.key)));
  });

  it('app.has_permission() equals the TS registry for every role × permission', async () => {
    for (const role of SYSTEM_ROLE_KEYS) {
      const m = members[role]!;
      const r = await asApp(h.app, as(m),
        `SELECT p.key, app.has_permission(p.key) AS ok FROM meta.permissions p ORDER BY p.key`);
      for (const row of r.rows) {
        expect(row.ok, `${role} ${row.key}`).toBe(SYSTEM_ROLES[role].permissions.has(row.key as Permission));
      }
    }
  });

  it('loadPrincipalAccess() returns exactly the role permissions, including team-inherited roles', async () => {
    for (const [name, role] of [...SYSTEM_ROLE_KEYS.map((r) => [r, r] as const), ['teamie', 'compliance'] as const]) {
      const m = members[name]!;
      const a = await access(m);
      expect([...a.tenantPermissions].sort(), name).toEqual([...SYSTEM_ROLES[role].permissions].sort());
      expect(a.membershipActive).toBe(true);
    }
  });

  it('loadPrincipalAccess() reports scoped roles and keeps the strongest grant', async () => {
    const m = members.read_only!;
    const sec = await fx.createSecurable(h.admin, T.id, 'restricted');
    await fx.assignRole(h.admin, T.id, T.roles.investment_professional, { membershipId: m.membershipId, scopeId: sec });
    await fx.grantSecurable(h.admin, T.id, sec, { membershipId: m.membershipId, access: 'write', grantedBy: m.membershipId });
    await fx.grantSecurable(h.admin, T.id, sec, { membershipId: m.membershipId, access: 'read', grantedBy: m.membershipId });
    await h.admin.query(`INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'projects.write')`, [T.id, T.roles.read_only]).catch(() => undefined);
    const a = await access(m);
    expect(a.scopedPermissions).toContainEqual({ securableId: sec, permission: 'projects.write' });
    expect(a.restrictedGrants.get(sec)).toBe('write');
    expect(authorize(a, 'projects.write', { securableId: sec, classification: 'restricted' }).allowed).toBe(true);
  });

  it('loadPrincipalAccess() ignores unknown permissions and reports suspended memberships as inactive', async () => {
    await h.admin.query(`INSERT INTO meta.permissions (key, description) VALUES ('legacy.unknown', 'not in registry')`);
    await h.admin.query(`INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'legacy.unknown')`, [T.id, T.roles.read_only]);
    const m = members.read_only!;
    const a = await access(m);
    expect([...a.tenantPermissions]).not.toContain('legacy.unknown');
    await h.admin.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [m.membershipId]);
    // Since M1-WP1 a suspended member cannot even establish a context (the DB refuses auth.begin).
    await expect(access(m)).rejects.toThrow(/Not found/);
  });

  it('system roles cannot be edited through the app role, even by an owner', async () => {
    const m = members.owner!;
    const r = await asApp(h.app, as(m),
      `INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'restricted.oversight')`, [T.id, T.roles.owner]);
    expect(r.code).toBe('42501');
    const u = await asApp(h.app, as(m), `UPDATE roles SET name = 'x' WHERE id = $1`, [T.roles.owner]);
    expect(u.rowCount).toBe(0);
  });

  it('a read-only member cannot assign roles to themselves', async () => {
    const m = members.read_only!;
    await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [m.membershipId]);
    const r = await asApp(h.app, as(m),
      `INSERT INTO role_assignments (tenant_id, id, role_id, membership_id) VALUES ($1, gen_random_uuid(), $2, $3)`, [T.id, T.roles.owner, m.membershipId]);
    expect(r.code).toBe('42501');
  });
});
