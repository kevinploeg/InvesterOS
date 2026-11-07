/**
 * M0-AC6: generated cross-tenant isolation suite. Tables are enumerated from pg_catalog, so a new
 * tenant table is covered automatically (and schema-lint forces it to carry the policy shape).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPool, withTenantTx, type SessionCredential } from '../src/db';
import { writeAudit } from '../src/audit';
import * as fx from '../src/fixtures';
import { asApp, harness, ISSUER, type As, type Harness } from './helpers';

interface Side { tenant: fx.TenantFixture; userId: string; membershipId: string; teamId: string; securableId: string; cred: SessionCredential }

let h: Harness;
let A: Side;
let B: Side;
let tenantTables: string[] = [];
const insertable = new Map<string, string[]>();

async function makeSide(slug: string): Promise<Side> {
  const tenant = await fx.createTenant(h.admin, slug);
  const userId = await fx.createUser(h.admin, { email: `${slug}@synthetic.test`, displayName: slug, issuer: ISSUER, subject: `${slug}-sub` });
  const membershipId = await fx.addMembership(h.admin, tenant.id, userId);
  await fx.assignRole(h.admin, tenant.id, tenant.roles.owner, { membershipId });
  const teamId = await fx.createTeam(h.admin, tenant.id, `${slug}-team`);
  await fx.addTeamMember(h.admin, tenant.id, teamId, membershipId);
  const securableId = await fx.createSecurable(h.admin, tenant.id, 'standard');
  await fx.assignRole(h.admin, tenant.id, tenant.roles.investment_professional, { teamId, scopeId: securableId });
  await fx.grantSecurable(h.admin, tenant.id, securableId, { membershipId, access: 'write', grantedBy: membershipId });
  await h.admin.query('INSERT INTO probe_notes (tenant_id, id, securable_id, body) VALUES ($1, gen_random_uuid(), $2, $3)', [tenant.id, securableId, `note ${slug}`]);
  const cred = await fx.login(h.admin, userId);
  await withTenantTx(h.app, cred, slug, 'write', async (tx, ctx) => {
    await writeAudit(tx, ctx, { action: 'test.created', securableId });
    await tx.query(`INSERT INTO jobs (tenant_id, id, kind, permission, enqueued_by) VALUES ($1, gen_random_uuid(), 'test.job', 'audit.read', $2)`,
      [ctx.tenantId, ctx.membershipId]);
  });
  return { tenant, userId, membershipId, teamId, securableId, cred };
}

beforeAll(async () => {
  h = await harness({ probe: true });
  A = await makeSide('tenant-a');
  B = await makeSide('tenant-b');
  const t = await h.admin.query<{ relname: string }>(`
    SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
    WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1`);
  tenantTables = t.rows.map((r) => r.relname);
  for (const table of tenantTables) {
    const cols = await h.admin.query<{ attname: string }>(`
      SELECT attname FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped
        AND attidentity = '' AND attgenerated = '' ORDER BY attnum`, [table]);
    insertable.set(table, cols.rows.map((r) => r.attname));
  }
});
afterAll(async () => h?.close());

const asB = (): As => ({ cred: B.cred, slug: 'tenant-b' });

describe('cross-tenant isolation (generated per tenant table)', () => {
  it('covers every tenant table, each seeded with rows for both tenants', async () => {
    expect(tenantTables).toEqual(expect.arrayContaining([
      'audit_events', 'jobs', 'probe_notes', 'role_assignments', 'role_permissions', 'roles', 'securable_grants',
      'securables', 'team_members', 'teams', 'tenant_memberships',
    ]));
    for (const t of tenantTables) {
      const r = await h.admin.query(`SELECT count(DISTINCT tenant_id)::int AS n FROM ${t} WHERE tenant_id IN ($1, $2)`, [A.tenant.id, B.tenant.id]);
      expect(r.rows[0].n, t).toBe(2);
    }
  });

  it('SELECT: tenant B sees zero rows of tenant A, but does see its own', async () => {
    for (const t of tenantTables) {
      const other = await asApp(h.app, asB(), `SELECT count(*)::int AS n FROM ${t} WHERE tenant_id = $1`, [A.tenant.id]);
      expect(other.code, t).toBeUndefined();
      expect(other.rows[0]?.n, `${t}: A rows visible to B`).toBe(0);
      const own = await asApp(h.app, asB(), `SELECT count(*)::int AS n FROM ${t} WHERE tenant_id = $1`, [B.tenant.id]);
      expect(Number(own.rows[0]?.n), `${t}: own rows`).toBeGreaterThan(0);
    }
  });

  it('UPDATE: tenant B cannot modify tenant A rows', async () => {
    for (const t of tenantTables) {
      const r = await asApp(h.app, asB(), `UPDATE ${t} SET tenant_id = tenant_id WHERE tenant_id = $1`, [A.tenant.id]);
      if (r.code) expect(r.code, t).toBe('42501');
      else expect(r.rowCount, t).toBe(0);
    }
  });

  it('UPDATE: tenant B cannot move its own rows into tenant A', async () => {
    for (const t of tenantTables) {
      const r = await asApp(h.app, asB(), `UPDATE ${t} SET tenant_id = $1 WHERE tenant_id = $2`, [A.tenant.id, B.tenant.id]);
      // RLS WITH CHECK (42501), composite FK (23503), or no row qualifies for the write policy (0 rows).
      if (r.code) expect(['42501', '23503'], t).toContain(r.code);
      else expect(r.rowCount, t).toBe(0);
    }
  });

  it('DELETE: tenant B cannot delete tenant A rows', async () => {
    for (const t of tenantTables) {
      const r = await asApp(h.app, asB(), `DELETE FROM ${t} WHERE tenant_id = $1`, [A.tenant.id]);
      if (r.code) expect(r.code, t).toBe('42501');
      else expect(r.rowCount, t).toBe(0);
    }
  });

  it('INSERT: tenant B cannot insert rows carrying tenant A id (RLS WITH CHECK)', async () => {
    for (const t of tenantTables) {
      const cols = insertable.get(t)!;
      const src = await h.admin.query(`SELECT row_to_json(x) AS j FROM ${t} x WHERE tenant_id = $1 LIMIT 1`, [A.tenant.id]);
      const j = src.rows[0].j as Record<string, unknown>;
      if ('id' in j) j.id = crypto.randomUUID();
      const list = cols.join(', ');
      const r = await asApp(h.app, asB(), `INSERT INTO ${t} (${list}) SELECT ${list} FROM json_populate_record(null::${t}, $1)`, [JSON.stringify(j)]);
      expect(r.code, `${t}: insert into other tenant`).toBe('42501');
    }
  });

  it('no context: zero rows from every tenant table and every global table', async () => {
    for (const t of [...tenantTables, 'tenants', 'users', 'user_identities', 'sessions']) {
      const r = await asApp(h.app, null, `SELECT count(*)::int AS n FROM ${t}`);
      if (t === 'sessions') { expect(r.code).toBe('42501'); continue; } // no privilege at all since M1-WP1
      expect(r.code, t).toBeUndefined();
      expect(r.rows[0]?.n, t).toBe(0);
    }
  });

  it('tenant B cannot establish a context in tenant A (no membership) — same error as a non-existent tenant', async () => {
    const r = await asApp(h.app, { cred: B.cred, slug: 'tenant-a' }, 'SELECT 1');
    const none = await asApp(h.app, { cred: B.cred, slug: 'no-such-tenant' }, 'SELECT 1');
    expect(r.code).toBe('IOS04');
    expect(none.code).toBe(r.code);
  });

  it('composite FKs: a tenant-B row can never reference a tenant-A parent (even bypassing RLS)', async () => {
    const fks = await h.admin.query<{ src: string; dst: string; src_cols: string[]; dst_cols: string[] }>(`
      SELECT cs.relname AS src, cd.relname AS dst,
        ARRAY(SELECT a.attname FROM unnest(con.conkey) k JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k)::text[] AS src_cols,
        ARRAY(SELECT a.attname FROM unnest(con.confkey) k JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k)::text[] AS dst_cols
      FROM pg_constraint con JOIN pg_class cs ON cs.oid = con.conrelid JOIN pg_class cd ON cd.oid = con.confrelid
      JOIN pg_namespace n ON n.oid = cs.relnamespace
      WHERE con.contype = 'f' AND n.nspname = 'public' AND 'tenant_id' = ANY (ARRAY(SELECT a.attname FROM unnest(con.conkey) k JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k))`);
    expect(fks.rowCount).toBeGreaterThan(10);
    let tested = 0;
    for (const fk of fks.rows) {
      const fkCols = fk.src_cols.filter((c) => c !== 'tenant_id');
      if (fkCols.length === 0) continue; // FK to the tenants registry itself
      const srcRow = await h.admin.query(`SELECT row_to_json(x) AS j FROM ${fk.src} x WHERE tenant_id = $1 AND ${fkCols.map((c) => `${c} IS NOT NULL`).join(' AND ')} LIMIT 1`, [B.tenant.id]);
      const parent = await h.admin.query(`SELECT row_to_json(x) AS j FROM ${fk.dst} x WHERE tenant_id = $1 LIMIT 1`, [A.tenant.id]);
      if (!srcRow.rowCount || !parent.rowCount) continue;
      const j = srcRow.rows[0].j as Record<string, unknown>;
      const p = parent.rows[0].j as Record<string, unknown>;
      fk.src_cols.forEach((c, i) => { if (c !== 'tenant_id') j[c] = p[fk.dst_cols[i]!]; });
      if ('id' in j) j.id = crypto.randomUUID();
      const cols = insertable.get(fk.src)!.join(', ');
      const err = await h.admin
        .query(`INSERT INTO ${fk.src} (${cols}) SELECT ${cols} FROM json_populate_record(null::${fk.src}, $1)`, [JSON.stringify(j)])
        .then(() => null, (e: { code: string }) => e.code);
      expect(err, `${fk.src} -> ${fk.dst}`).toBe('23503');
      tested++;
    }
    expect(tested).toBeGreaterThan(10);
  });
});

describe('global tables', () => {
  it('tenants: a user sees only tenants they are an active member of', async () => {
    const r = await asApp(h.app, { cred: B.cred, slug: null }, 'SELECT slug FROM tenants ORDER BY slug');
    expect(r.rows.map((x) => x.slug)).toEqual(['tenant-b']);
  });

  it('users / identities / sessions: no cross-user leakage', async () => {
    const users = await asApp(h.app, asB(), 'SELECT id FROM users');
    expect(users.rows.map((x) => x.id)).toEqual([B.userId]);
    const ids = await asApp(h.app, asB(), 'SELECT user_id FROM user_identities');
    expect(ids.rows.map((x) => x.user_id)).toEqual([B.userId]);
    expect((await asApp(h.app, asB(), 'SELECT user_id FROM sessions')).code).toBe('42501');
    expect((await asApp(h.app, asB(), 'UPDATE sessions SET revoked_at = now() WHERE user_id = $1', [A.userId])).code).toBe('42501');
    const upd2 = await asApp(h.app, asB(), 'UPDATE users SET display_name = $2 WHERE id = $1', [A.userId, 'x']);
    expect(upd2.rowCount).toBe(0);
  });

  it('the app role cannot write tenants, identities, or its own e-mail', async () => {
    expect((await asApp(h.app, asB(), `UPDATE tenants SET name = 'x'`)).code).toBe('42501');
    expect((await asApp(h.app, asB(), `INSERT INTO user_identities (id, user_id, issuer, subject) VALUES (gen_random_uuid(), $1, 'https://evil.test', 'x')`, [B.userId])).code).toBe('42501');
    expect((await asApp(h.app, asB(), `UPDATE users SET email = 'x@y.z' WHERE id = $1`, [B.userId])).code).toBe('42501');
  });

  it('the app role cannot read or modify sessions directly (only through auth.* functions)', async () => {
    const r = await asApp(h.app, { cred: B.cred, slug: null }, 'UPDATE sessions SET active_tenant_id = $1, active_membership_id = $2 WHERE user_id = $3', [A.tenant.id, A.membershipId, B.userId]);
    expect(r.code).toBe('42501');
  });
});

describe('connection pool hygiene (M0-AC6)', () => {
  it('context never survives COMMIT or ROLLBACK on a reused connection', async () => {
    const pool = createPool(h.db.appUrl, 1);
    try {
      await withTenantTx(pool, B.cred, 'tenant-b', 'read', async (tx) => {
        expect((await tx.query(`SELECT app.current_tenant() AS t`)).rows[0].t).toBe(B.tenant.id);
      });
      const after = await pool.query(`SELECT app.current_tenant() AS t, app.current_membership() AS m, (SELECT count(*)::int FROM teams) AS n`);
      expect(after.rows[0]).toEqual({ t: null, m: null, n: 0 });
      await expect(withTenantTx(pool, B.cred, 'tenant-b', 'write', async () => { throw new Error('boom'); })).rejects.toThrow('boom');
      const after2 = await pool.query(`SELECT app.current_tenant() AS t`);
      expect(after2.rows[0].t).toBeNull();
    } finally {
      await pool.end();
    }
  });
});
