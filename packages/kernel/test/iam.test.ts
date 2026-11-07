/**
 * M1-WP3: IAM invariants enforced by the database (AC4 / D5). Everything runs as raw SQL under ios_app with a
 * DB-established context: these are the guarantees that hold even if application code is bypassed.
 */
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type SessionCredential } from '../src/db';
import { PERMISSION_KEYS } from '../src/authz';
import * as fx from '../src/fixtures';
import { asApp, harness, ISSUER, type Harness } from './helpers';

let h: Harness;
let T: fx.TenantFixture;
const u: Record<string, { userId: string; membershipId: string; cred: SessionCredential }> = {};
const SLUG = 'iam-co';

async function member(name: string, role?: keyof fx.TenantFixture['roles']) {
  const userId = await fx.createUser(h.admin, { email: `${name}@synthetic.test`, displayName: name, issuer: ISSUER, subject: name });
  const membershipId = await fx.addMembership(h.admin, T.id, userId);
  if (role) await fx.assignRole(h.admin, T.id, T.roles[role], { membershipId });
  u[name] = { userId, membershipId, cred: await fx.login(h.admin, userId) };
}
const iam = (name: string, sql: string, params: unknown[] = [], mode: 'iam' | 'write' = 'iam') =>
  asApp(h.app, { cred: u[name]!.cred, slug: SLUG, mode }, sql, params);
const assign = (actor: string, role: string, target: { membershipId?: string; teamId?: string; scopeId?: string }, mode: 'iam' | 'write' = 'iam') =>
  iam(actor, `INSERT INTO role_assignments (tenant_id, id, role_id, membership_id, team_id, scope_type, scope_id) VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, $6)`,
    [T.id, role, target.membershipId ?? null, target.teamId ?? null, target.scopeId ? 'securable' : 'tenant', target.scopeId ?? null], mode);
async function customRole(key: string, perms: string[]): Promise<string> {
  const id = crypto.randomUUID();
  await h.admin.query(`INSERT INTO roles (tenant_id, id, key, name) VALUES ($1, $2, $3, $3)`, [T.id, id, key]);
  if (perms.length) await h.admin.query(`INSERT INTO role_permissions (tenant_id, role_id, permission) SELECT $1, $2, unnest($3::text[])`, [T.id, id, perms]);
  return id;
}
const owners = async () => Number((await h.admin.query(`
  SELECT count(DISTINCT m.id)::int AS n FROM tenant_memberships m JOIN role_assignments ra ON ra.tenant_id = m.tenant_id AND ra.membership_id = m.id
  WHERE m.tenant_id = $1 AND m.status = 'active' AND ra.role_id = $2`, [T.id, T.roles.owner])).rows[0].n);

beforeAll(async () => {
  h = await harness();
  T = await fx.createTenant(h.admin, SLUG);
  await member('owner1', 'owner');
  await member('owner2', 'owner');
  await member('admin', 'admin');
  await member('ro', 'read_only');
  await member('target');
  await member('target2');
});
afterAll(async () => h?.close());

describe('(a) IAM changes require iam mode; system jobs cannot change IAM', () => {
  it('write mode is refused for IAM mutations', async () => {
    const r = await assign('admin', T.roles.read_only, { membershipId: u.target!.membershipId }, 'write');
    expect(r.code).toBe('IOS03');
  });
  it('iam mode is accepted', async () => {
    expect((await assign('admin', T.roles.read_only, { membershipId: u.target!.membershipId })).code).toBeUndefined();
  });
  it('a system principal cannot change IAM', async () => {
    const c = await h.worker.connect();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin_system($1, $2)', [T.id, 'job.iam']);
      await h.admin.query(`CREATE POLICY team_members_sys_probe ON team_members FOR INSERT TO ios_worker WITH CHECK (true)`);
      await h.admin.query(`GRANT INSERT ON team_members TO ios_worker`);
      const team = await fx.createTeam(h.admin, T.id, 'sys-probe');
      const r = await c.query(`INSERT INTO team_members (tenant_id, team_id, membership_id) VALUES ($1, $2, $3)`, [T.id, team, u.target!.membershipId]).catch((e) => e.code);
      expect(r).toBe('IOS03');
    } finally {
      await c.query('ROLLBACK');
      c.release();
      await h.admin.query(`REVOKE INSERT ON team_members FROM ios_worker`);
      await h.admin.query(`DROP POLICY team_members_sys_probe ON team_members`);
    }
  });
});

describe('(b) no self-mutation', () => {
  it('cannot assign a role to yourself', async () => {
    expect((await assign('admin', T.roles.read_only, { membershipId: u.admin!.membershipId })).code).toBe('IOS03');
  });
  it('cannot add yourself to a team, nor assign roles to a team you are in', async () => {
    const team = await fx.createTeam(h.admin, T.id, 'admins-own-team');
    expect((await iam('admin', `INSERT INTO team_members (tenant_id, team_id, membership_id) VALUES ($1, $2, $3)`, [T.id, team, u.admin!.membershipId])).code).toBe('IOS03');
    await fx.addTeamMember(h.admin, T.id, team, u.admin!.membershipId);
    expect((await assign('admin', T.roles.read_only, { teamId: team })).code).toBe('IOS03');
  });
  it('cannot change the permissions of a role you hold (directly or via a team)', async () => {
    const r = await customRole('held_role', ['crm.read']);
    await fx.assignRole(h.admin, T.id, r, { membershipId: u.admin!.membershipId });
    expect((await iam('admin', `INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'crm.write')`, [T.id, r])).code).toBe('IOS03');
  });
  it('cannot grant yourself access to a restricted securable (closes the M0 self-grant gap)', async () => {
    const sec = await fx.createSecurable(h.admin, T.id, 'restricted');
    const r = await iam('admin', `INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, access, granted_by) VALUES ($1, gen_random_uuid(), $2, $3, 'read', $3)`,
      [T.id, sec, u.admin!.membershipId]);
    expect(r.code).toBe('IOS03');
    const other = await iam('admin', `INSERT INTO securable_grants (tenant_id, id, securable_id, membership_id, access, granted_by) VALUES ($1, gen_random_uuid(), $2, $3, 'read', $4)`,
      [T.id, sec, u.target!.membershipId, u.admin!.membershipId]);
    expect(other.code).toBeUndefined();
  });
  it('cannot suspend yourself', async () => {
    expect((await iam('owner1', `UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [u.owner1!.membershipId])).code).toBe('IOS03');
  });
});

describe('(c) subset rule: you cannot hand out or take away what you do not hold', () => {
  it('admin cannot make someone owner; owner can', async () => {
    const r = await assign('admin', T.roles.owner, { membershipId: u.target!.membershipId });
    expect(r.code).toBe('IOS03');
    expect((await assign('owner1', T.roles.compliance, { membershipId: u.target2!.membershipId })).code).toBe('IOS03'); // oversight not held by owner
    expect((await assign('owner1', T.roles.admin, { membershipId: u.target2!.membershipId })).code).toBeUndefined();
  });
  it('indirect via team: adding someone to a team that carries a stronger role is refused', async () => {
    const team = await fx.createTeam(h.admin, T.id, 'owners-team');
    await fx.assignRole(h.admin, T.id, T.roles.owner, { teamId: team });
    expect((await iam('admin', `INSERT INTO team_members (tenant_id, team_id, membership_id) VALUES ($1, $2, $3)`, [T.id, team, u.target!.membershipId])).code).toBe('IOS03');
    expect((await iam('owner1', `INSERT INTO team_members (tenant_id, team_id, membership_id) VALUES ($1, $2, $3)`, [T.id, team, u.target!.membershipId])).code).toBeUndefined();
  });
  it('custom roles: cannot add a permission you lack', async () => {
    const r = await customRole('custom_free', []);
    expect((await iam('admin', `INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'restricted.oversight')`, [T.id, r])).code).toBe('IOS03');
    expect((await iam('admin', `INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'audit.read')`, [T.id, r])).code).toBeUndefined();
  });
  it('cannot demote or suspend a stronger member', async () => {
    const ownerAssignment = (await h.admin.query(`SELECT id FROM role_assignments WHERE membership_id = $1 AND role_id = $2`, [u.owner2!.membershipId, T.roles.owner])).rows[0].id;
    expect((await iam('admin', `DELETE FROM role_assignments WHERE id = $1`, [ownerAssignment])).code).toBe('IOS03');
    expect((await iam('admin', `UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [u.owner2!.membershipId])).code).toBe('IOS03');
    expect((await iam('owner1', `UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [u.ro!.membershipId])).code).toBeUndefined();
  });
  it('scoped permissions: a scoped holder can delegate only on that securable, never tenant-wide', async () => {
    const x = await fx.createSecurable(h.admin, T.id, 'standard');
    const y = await fx.createSecurable(h.admin, T.id, 'standard');
    const writer = await customRole('proj_writer', ['projects.write']);
    const manager = await customRole('role_manager', ['iam.roles.manage']);
    await member('scoped');
    await fx.assignRole(h.admin, T.id, manager, { membershipId: u.scoped!.membershipId });
    await fx.assignRole(h.admin, T.id, writer, { membershipId: u.scoped!.membershipId, scopeId: x });
    expect((await assign('scoped', writer, { membershipId: u.target!.membershipId, scopeId: x })).code).toBeUndefined();
    expect((await assign('scoped', writer, { membershipId: u.target!.membershipId, scopeId: y })).code).toBe('IOS03');
    expect((await assign('scoped', writer, { membershipId: u.target!.membershipId })).code).toBe('IOS03');
  });
  it('RLS still applies first: a read-only member cannot touch IAM at all', async () => {
    expect((await assign('ro', T.roles.read_only, { membershipId: u.target!.membershipId })).code).toBe('42501');
  });
});

describe('(d) last owner', () => {
  it('a member holding every owner permission (but not the owner role) cannot remove the last owner', async () => {
    const T2 = await fx.createTenant(h.admin, 'last-owner-co');
    const mk = async (n: string) => {
      const id = await fx.createUser(h.admin, { email: `${n}@synthetic.test`, displayName: n, issuer: ISSUER, subject: n });
      return { userId: id, membershipId: await fx.addMembership(h.admin, T2.id, id), cred: await fx.login(h.admin, id) };
    };
    const solo = await mk('solo-owner');
    const sup = await mk('super-custom');
    const ownerRa = await fx.assignRole(h.admin, T2.id, T2.roles.owner, { membershipId: solo.membershipId });
    const all = crypto.randomUUID();
    await h.admin.query(`INSERT INTO roles (tenant_id, id, key, name) VALUES ($1, $2, 'everything', 'Everything')`, [T2.id, all]);
    await h.admin.query(`INSERT INTO role_permissions (tenant_id, role_id, permission) SELECT $1, $2, unnest($3::text[])`, [T2.id, all, PERMISSION_KEYS]);
    await fx.assignRole(h.admin, T2.id, all, { membershipId: sup.membershipId });
    const as = { cred: sup.cred, slug: 'last-owner-co', mode: 'iam' as const };
    const del = await asApp(h.app, as, `DELETE FROM role_assignments WHERE id = $1`, [ownerRa]);
    expect(del.code).toBe('IOS03');
    const susp = await asApp(h.app, as, `UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [solo.membershipId]);
    expect(susp.code).toBe('IOS03');
  });

  it('two owners demoting each other concurrently: at least one owner remains (serialised by the IAM lock)', async () => {
    const a = new pg.Client({ connectionString: h.db.appUrl });
    const b = new pg.Client({ connectionString: h.db.appUrl });
    await a.connect();
    await b.connect();
    const ra = async (mid: string) => (await h.admin.query(`SELECT id FROM role_assignments WHERE membership_id = $1 AND role_id = $2`, [mid, T.roles.owner])).rows[0]?.id;
    try {
      const raOf1 = await ra(u.owner1!.membershipId);
      const raOf2 = await ra(u.owner2!.membershipId);
      await a.query('BEGIN');
      await b.query('BEGIN');
      await a.query('SELECT auth.begin($1, $2, $3)', [u.owner1!.cred.reveal(), SLUG, 'iam']);
      const bBegin = b.query('SELECT auth.begin($1, $2, $3)', [u.owner2!.cred.reveal(), SLUG, 'iam']); // waits for a
      await a.query('DELETE FROM role_assignments WHERE id = $1', [raOf2]);
      await a.query('COMMIT');
      await bBegin;
      const bResult = await b.query('DELETE FROM role_assignments WHERE id = $1', [raOf1]).then((r) => r.rowCount, (e) => e.code);
      await b.query('ROLLBACK').catch(() => undefined);
      expect(['42501', 'IOS03', 0]).toContain(bResult);
      expect(await owners()).toBeGreaterThanOrEqual(1);
    } finally {
      await a.end();
      await b.end();
    }
  });
});
