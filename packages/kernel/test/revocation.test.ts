/**
 * M1-WP2: immediate revocation and race-free permission changes (C3 / D6 / D7 / R1–R5).
 * Uses real concurrent connections. Revocations are issued with an admin connection here because the
 * IAM write paths for ios_app are added (and tested) in WP3; the locking behaviour is identical.
 */
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getSessionView, switchTenant } from '../src/auth';
import { type SessionCredential, withTenantTx } from '../src/db';
import { enqueueJob, runJob } from '../src/jobs';
import * as fx from '../src/fixtures';
import { asApp, harness, ISSUER, type Harness } from './helpers';

let h: Harness;
let T: fx.TenantFixture;
let U2: fx.TenantFixture;
const u: Record<string, { userId: string; membershipId: string; cred: SessionCredential; assignment: string }> = {};

async function member(name: string, role: keyof fx.TenantFixture['roles'], tenant = T) {
  const userId = await fx.createUser(h.admin, { email: `${name}@synthetic.test`, displayName: name, issuer: ISSUER, subject: name });
  const membershipId = await fx.addMembership(h.admin, tenant.id, userId);
  const assignment = await fx.assignRole(h.admin, tenant.id, tenant.roles[role], { membershipId });
  u[name] = { userId, membershipId, cred: await fx.login(h.admin, userId), assignment };
}
const epoch = async (mid: string) => Number((await h.admin.query('SELECT authz_epoch FROM tenant_memberships WHERE id = $1', [mid])).rows[0].authz_epoch);
const settled = async (p: Promise<unknown>, ms = 300) => Promise.race([p.then(() => true, () => true), new Promise((r) => setTimeout(() => r(false), ms))]);
async function openWrite(name: string, mode: 'write' | 'iam' | 'read' = 'write'): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: h.db.appUrl });
  await c.connect();
  await c.query('BEGIN');
  await c.query('SELECT auth.begin($1, $2, $3)', [u[name]!.cred.reveal(), 'rev', mode]);
  return c;
}
async function adminConn(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: h.db.adminUrl });
  await c.connect();
  return c;
}
const createTeam = (name: string) => asApp(h.app, { cred: u[name]!.cred, slug: 'rev' }, `INSERT INTO teams (tenant_id, id, name) VALUES ($1, gen_random_uuid(), $2)`, [T.id, `t-${Math.random()}`]);

beforeAll(async () => {
  h = await harness();
  T = await fx.createTenant(h.admin, 'rev');
  U2 = await fx.createTenant(h.admin, 'rev-two');
  await member('owner', 'owner');
  await member('admin', 'admin');
  await member('admin2', 'admin');
  await member('ro', 'read_only');
  await fx.addMembership(h.admin, U2.id, u.admin!.userId);
});
afterAll(async () => h?.close());

describe('D6a: a revocation waits for in-flight writes; later writes see it (no TOCTOU window)', () => {
  it('role revocation during a write transaction', async () => {
    expect((await createTeam('admin')).code).toBeUndefined();
    const w = await openWrite('admin');
    const a = await adminConn();
    try {
      const revoke = a.query('DELETE FROM role_assignments WHERE id = $1', [u.admin!.assignment]);
      expect(await settled(revoke)).toBe(false); // blocked by the writer's FOR SHARE
      await w.query(`INSERT INTO teams (tenant_id, id, name) VALUES ($1, gen_random_uuid(), 'in-flight')`, [T.id]);
      await w.query('COMMIT');
      await revoke;
      expect((await createTeam('admin')).code).toBe('42501'); // next write: rights are gone
    } finally {
      await w.end();
      await a.end();
    }
  });

  it('membership suspension during a write transaction', async () => {
    const w = await openWrite('admin2');
    const a = await adminConn();
    try {
      const suspend = a.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [u.admin2!.membershipId]);
      expect(await settled(suspend)).toBe(false);
      await w.query('COMMIT');
      await suspend;
      expect((await createTeam('admin2')).code).toBe('IOS04');
      expect((await asApp(h.app, { cred: u.admin2!.cred, slug: 'rev', mode: 'read' }, 'SELECT 1')).code).toBe('IOS04');
    } finally {
      await w.end();
      await a.end();
      await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [u.admin2!.membershipId]);
    }
  });

  it('tenant suspension during a write transaction', async () => {
    const w = await openWrite('owner');
    const a = await adminConn();
    try {
      const suspend = a.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [T.id]);
      expect(await settled(suspend)).toBe(false);
      await w.query('COMMIT');
      await suspend;
      expect((await createTeam('owner')).code).toBe('IOS04');
    } finally {
      await w.end();
      await a.end();
      await h.admin.query(`UPDATE tenants SET status = 'active' WHERE id = $1`, [T.id]);
    }
  });

  it('a writer that starts after the revocation committed is refused at auth.begin', async () => {
    const a = await adminConn();
    try {
      await a.query('BEGIN');
      await a.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [u.ro!.membershipId]);
      const c = new pg.Client({ connectionString: h.db.appUrl });
      await c.connect();
      const begin = c.query('SELECT auth.begin($1, $2, $3)', [u.ro!.cred.reveal(), 'rev', 'write']).then(() => 'ok', (e) => e.code);
      await a.query('COMMIT');
      expect(await begin).toBe('IOS04');
      await c.end();
    } finally {
      await a.end();
      await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [u.ro!.membershipId]);
    }
  });

  it('read transactions take no locks (revocation proceeds immediately)', async () => {
    const r = await openWrite('ro', 'read');
    try {
      await h.admin.query('UPDATE tenant_memberships SET authz_epoch = authz_epoch + 1 WHERE id = $1', [u.ro!.membershipId]);
    } finally {
      await r.query('ROLLBACK');
      await r.end();
    }
  });

  it('iam mode serialises IAM transactions within a tenant (advisory lock)', async () => {
    const first = await openWrite('owner', 'iam');
    const second = new pg.Client({ connectionString: h.db.appUrl });
    await second.connect();
    try {
      await second.query('BEGIN');
      const p = second.query('SELECT auth.begin($1, $2, $3)', [u.ro!.cred.reveal(), 'rev', 'iam']);
      expect(await settled(p)).toBe(false);
      await first.query('COMMIT');
      await p;
      await second.query('ROLLBACK');
    } finally {
      await first.end();
      await second.end();
    }
  });

  it('user-level contexts are read-only', async () => {
    expect((await asApp(h.app, { cred: u.ro!.cred, slug: null, mode: 'write' }, 'SELECT 1')).code).toBe('22023');
  });
});

describe('D7: epoch bumps reach every affected membership', () => {
  it('team role assignment, team membership, role permissions, grants and user disable', async () => {
    const team = await fx.createTeam(h.admin, T.id, 'Epoch team');
    await fx.addTeamMember(h.admin, T.id, team, u.ro!.membershipId);
    const before = await epoch(u.ro!.membershipId);
    const ra = await fx.assignRole(h.admin, T.id, T.roles.compliance, { teamId: team });
    expect(await epoch(u.ro!.membershipId)).toBe(before + 1);
    await h.admin.query(`INSERT INTO roles (tenant_id, id, key, name) VALUES ($1, gen_random_uuid(), 'custom_x', 'X') RETURNING id`, [T.id]);
    const custom = (await h.admin.query(`SELECT id FROM roles WHERE tenant_id = $1 AND key = 'custom_x'`, [T.id])).rows[0].id;
    await fx.assignRole(h.admin, T.id, custom, { teamId: team });
    const b2 = await epoch(u.ro!.membershipId);
    await h.admin.query(`INSERT INTO role_permissions (tenant_id, role_id, permission) VALUES ($1, $2, 'crm.read')`, [T.id, custom]);
    expect(await epoch(u.ro!.membershipId)).toBe(b2 + 1);
    const sec = await fx.createSecurable(h.admin, T.id, 'restricted');
    const b3 = await epoch(u.ro!.membershipId);
    await fx.grantSecurable(h.admin, T.id, sec, { teamId: team, access: 'read', grantedBy: u.owner!.membershipId });
    expect(await epoch(u.ro!.membershipId)).toBe(b3 + 1);
    const b4 = await epoch(u.ro!.membershipId);
    await h.admin.query('DELETE FROM role_assignments WHERE id = $1', [ra]);
    await h.admin.query('DELETE FROM team_members WHERE team_id = $1 AND membership_id = $2', [team, u.ro!.membershipId]);
    expect(await epoch(u.ro!.membershipId)).toBe(b4 + 2);
    const multi = await epoch(u.admin!.membershipId);
    await h.admin.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [u.admin!.userId]);
    await h.admin.query(`UPDATE users SET status = 'active' WHERE id = $1`, [u.admin!.userId]);
    expect(await epoch(u.admin!.membershipId)).toBe(multi + 2);
    const other = (await h.admin.query('SELECT authz_epoch FROM tenant_memberships WHERE tenant_id = $1 AND user_id = $2', [U2.id, u.admin!.userId])).rows[0];
    expect(Number(other.authz_epoch)).toBeGreaterThanOrEqual(2); // all tenants of the user
  });
});

describe('R4: background actions re-validate the enqueuer at execution time', () => {
  const enqueue = (name: string, permission: 'audit.read' | 'iam.teams.manage' = 'audit.read') =>
    withTenantTx(h.app, u[name]!.cred, 'rev', 'write', (tx, ctx) => enqueueJob(tx, ctx, 'test.echo', permission, { n: 1 }));

  it('runs as the enqueuer (DB-established), then completes', async () => {
    const id = await enqueue('owner');
    let seen: Record<string, unknown> = {};
    const outcome = await runJob(h.worker, id, async (tx, job) => {
      const r = await tx.query(`SELECT app.current_membership() AS m, app.principal_type() AS p, app.has_permission('audit.read') AS ok`);
      seen = { ...r.rows[0], payload: job.payload };
    });
    expect(outcome).toBe('done');
    expect(seen).toEqual({ m: u.owner!.membershipId, p: 'staff', ok: true, payload: { n: 1 } });
    expect(await runJob(h.worker, id, async () => undefined)).toBe('unavailable'); // no double execution
  });

  it('a handler error marks the job failed; its writes are rolled back', async () => {
    const id = await enqueue('owner');
    expect(await runJob(h.worker, id, async (tx) => {
      await tx.query(`INSERT INTO teams (tenant_id, id, name) VALUES ($1, gen_random_uuid(), 'job-team-should-vanish')`, [T.id]);
      throw new Error('boom');
    })).toBe('failed');
    expect((await h.admin.query(`SELECT count(*)::int AS n FROM teams WHERE name = 'job-team-should-vanish'`)).rows[0].n).toBe(0);
  });

  it('enqueuer suspended before execution → refused and recorded; handler never runs', async () => {
    const id = await enqueue('admin2');
    await h.admin.query(`UPDATE tenant_memberships SET status = 'suspended' WHERE id = $1`, [u.admin2!.membershipId]);
    let ran = false;
    try {
      expect(await runJob(h.worker, id, async () => { ran = true; })).toBe('refused:enqueuer_inactive');
    } finally {
      await h.admin.query(`UPDATE tenant_memberships SET status = 'active' WHERE id = $1`, [u.admin2!.membershipId]);
    }
    expect(ran).toBe(false);
    expect((await h.admin.query('SELECT status, refusal FROM jobs WHERE id = $1', [id])).rows[0]).toEqual({ status: 'refused', refusal: 'enqueuer_inactive' });
  });

  it('permission withdrawn before execution → refused', async () => {
    const id = await enqueue('admin2', 'iam.teams.manage');
    const ra = (await h.admin.query(`SELECT id FROM role_assignments WHERE membership_id = $1`, [u.admin2!.membershipId])).rows[0].id;
    await h.admin.query('DELETE FROM role_assignments WHERE id = $1', [ra]);
    expect(await runJob(h.worker, id, async () => undefined)).toBe('refused:permission_revoked');
  });

  it('users cannot enqueue on behalf of someone else, and cannot execute jobs', async () => {
    const forged = await asApp(h.app, { cred: u.ro!.cred, slug: 'rev' },
      `INSERT INTO jobs (tenant_id, id, kind, permission, enqueued_by) VALUES ($1, gen_random_uuid(), 'x.y', 'audit.read', $2)`, [T.id, u.owner!.membershipId]);
    expect(forged.code).toBe('42501');
    expect((await asApp(h.app, null, `SELECT * FROM auth.begin_job(gen_random_uuid())`)).code).toBe('42501');
    expect((await asApp(h.app, null, `SELECT auth.complete_job(gen_random_uuid(), true)`)).code).toBe('42501');
    const w = await h.worker.query(`SELECT auth.complete_job(gen_random_uuid(), true)`).catch((e) => e.code);
    expect(w).toBe('55000');
  });

  it('runJob maps database errors', async () => {
    await expect(runJob(h.app, crypto.randomUUID(), async () => undefined)).rejects.toMatchObject({ code: '42501' });
  });
});

describe('R5: tenant switch rotates the session token', () => {
  it('old token dies, new token works for the target tenant, absolute expiry is not extended', async () => {
    const before = (await h.admin.query(`SELECT expires_at FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, [u.admin!.userId])).rows[0].expires_at;
    const next = await switchTenant(h.app, u.admin!.cred, 'rev-two');
    expect(await getSessionView(h.app, u.admin!.cred)).toBeNull();
    const v = await getSessionView(h.app, next.credential);
    expect(v?.activeTenantSlug).toBe('rev-two');
    expect(next.expiresAt).toEqual(before);
    u.admin!.cred = next.credential;
  });

  it('switching to a tenant without membership is refused and keeps the old session', async () => {
    await expect(switchTenant(h.app, u.ro!.cred, 'rev-two')).rejects.toThrow(/Not found/);
    expect(await getSessionView(h.app, u.ro!.cred)).not.toBeNull();
  });

  it('switch requires a user-level context and a well-formed token (direct SQL)', async () => {
    expect((await asApp(h.app, { cred: u.ro!.cred, slug: 'rev' }, `SELECT * FROM auth.switch_tenant($1, 'rev')`, ['n'.repeat(43)])).code).toBe('IOS01');
    expect((await asApp(h.app, { cred: u.ro!.cred, slug: null }, `SELECT * FROM auth.switch_tenant('short', 'rev')`)).code).toBe('22023');
    expect((await asApp(h.app, null, `SELECT * FROM auth.switch_tenant($1, 'rev')`, ['n'.repeat(43)])).code).toBe('IOS01');
  });
});

describe('bounded lock holding', () => {
  it('request roles have statement, idle-in-transaction and lock timeouts', async () => {
    const r = await h.app.query(`SELECT current_setting('statement_timeout') AS s, current_setting('idle_in_transaction_session_timeout') AS i, current_setting('lock_timeout') AS l`);
    expect(r.rows[0]).toEqual({ s: '15s', i: '30s', l: '10s' });
  });
});
