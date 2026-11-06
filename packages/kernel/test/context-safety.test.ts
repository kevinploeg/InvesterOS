/**
 * M1-WP1: the request context is established and held by the DATABASE.
 * Every test here runs raw SQL as ios_app (an attacker who can execute arbitrary SQL with the app's
 * credentials) and proves it cannot assume another identity or keep a stale one.
 */
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPool, type SessionCredential } from '../src/db';
import * as fx from '../src/fixtures';
import { harness, ISSUER, type Harness } from './helpers';

let h: Harness;
let T: fx.TenantFixture;
let O: fx.TenantFixture;
const u: Record<string, { userId: string; membershipId: string; cred: SessionCredential }> = {};

async function member(name: string, tenant: fx.TenantFixture, role: keyof fx.TenantFixture['roles']) {
  const userId = await fx.createUser(h.admin, { email: `${name}@synthetic.test`, displayName: name, issuer: ISSUER, subject: name });
  const membershipId = await fx.addMembership(h.admin, tenant.id, userId);
  await fx.assignRole(h.admin, tenant.id, tenant.roles[role], { membershipId });
  u[name] = { userId, membershipId, cred: await fx.login(h.admin, userId) };
}

/** One dedicated connection, like a pooled backend serving successive requests. */
async function conn(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: h.db.appUrl });
  await c.connect();
  return c;
}
const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: { code?: string }) => e.code ?? 'error');
const who = async (c: pg.ClientBase) =>
  (await c.query(`SELECT app.current_tenant() AS t, app.current_user_id() AS u, app.current_membership() AS m, app.principal_type() AS p`)).rows[0];

beforeAll(async () => {
  h = await harness();
  T = await fx.createTenant(h.admin, 'ctx-tenant');
  O = await fx.createTenant(h.admin, 'other-tenant');
  await member('alice', T, 'read_only');
  await member('olga', T, 'owner');
  await member('oscar', O, 'owner');
});
afterAll(async () => h?.close());

describe('identity cannot be asserted through GUCs (the M0 gap)', () => {
  it('set_config without auth.begin yields no context and no rows', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query(`SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true),
                     set_config('app.membership_id', $3, true), set_config('app.principal_type', 'staff', true)`,
        [T.id, u.olga!.userId, u.olga!.membershipId]);
      expect(await who(c)).toEqual({ t: null, u: null, m: null, p: null });
      expect((await c.query('SELECT count(*)::int AS n FROM teams')).rows[0].n).toBe(0);
      expect((await c.query('SELECT count(*)::int AS n FROM roles')).rows[0].n).toBe(0);
      await c.query('ROLLBACK');
    } finally {
      await c.end();
    }
  });

  it('set_config AFTER auth.begin does not change the established identity', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.alice!.cred.reveal(), 'ctx-tenant', 'write']);
      await c.query(`SELECT set_config('app.membership_id', $1, true), set_config('app.user_id', $2, true), set_config('app.tenant_id', $3, true)`,
        [u.olga!.membershipId, u.olga!.userId, O.id]);
      expect(await who(c)).toEqual({ t: T.id, u: u.alice!.userId, m: u.alice!.membershipId, p: 'staff' });
      // alice is read_only: owner-only writes stay refused despite the spoof attempt
      expect(await code(c.query(`INSERT INTO teams (tenant_id, id, name) VALUES ($1, gen_random_uuid(), 'x')`, [T.id]))).toBe('42501');
      await c.query('ROLLBACK');
    } finally {
      await c.end();
    }
  });
});

describe('the context store cannot be touched by request roles', () => {
  it('ios_app cannot create temp objects (no TEMPORARY), so it cannot pre-create or shadow the store', async () => {
    const c = await conn();
    try {
      expect(await code(c.query('CREATE TEMP TABLE ios_tx_context (singleton boolean)'))).toBe('42501');
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.alice!.cred.reveal(), 'ctx-tenant', 'read']);
      expect(await code(c.query(`CREATE FUNCTION pg_temp.f() RETURNS int LANGUAGE sql AS 'SELECT 1'`))).toBe('42501');
      await c.query('ROLLBACK');
    } finally {
      await c.end();
    }
  });

  it.each([
    ['SELECT', `SELECT * FROM pg_temp.ios_tx_context`],
    ['INSERT', `INSERT INTO pg_temp.ios_tx_context (singleton, principal_type) VALUES (true, 'staff')`],
    ['UPDATE', `UPDATE pg_temp.ios_tx_context SET membership_id = gen_random_uuid()`],
    ['DELETE', `DELETE FROM pg_temp.ios_tx_context`],
    ['TRUNCATE', `TRUNCATE pg_temp.ios_tx_context`],
    ['ALTER', `ALTER TABLE pg_temp.ios_tx_context ADD COLUMN x int`],
  ])('%s on the store is refused', async (_op, sql) => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.alice!.cred.reveal(), 'ctx-tenant', 'read']);
      expect(['42501']).toContain(await code(c.query(sql)));
      await c.query('ROLLBACK');
    } finally {
      await c.end();
    }
  });

  it('internal helper and system/session-minting functions are not callable by ios_app', async () => {
    expect(await code(h.app.query('SELECT auth._ctx_table()'))).toBe('42501');
    expect(await code(h.app.query('SELECT auth.begin_system($1, $2)', [T.id, 'job.x']))).toBe('42501');
    expect(await code(h.app.query(`SELECT * FROM auth.create_session('i', 's', $1, NULL)`, ['z'.repeat(43)]))).toBe('42501');
  });
});

describe('transaction boundaries, rollback and backend reuse', () => {
  it('COMMIT and ROLLBACK both clear the context on the same backend', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']);
      await c.query('COMMIT');
      expect(await who(c)).toEqual({ t: null, u: null, m: null, p: null });
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']);
      await c.query('ROLLBACK');
      expect(await who(c)).toEqual({ t: null, u: null, m: null, p: null });
    } finally {
      await c.end();
    }
  });

  it('a backend reused by a different user never sees the previous identity (pool of 1)', async () => {
    const pool = createPool(h.db.appUrl, 1);
    try {
      const run = async (name: string, slug: string) => {
        const c = await pool.connect();
        try {
          await c.query('BEGIN');
          await c.query('SELECT auth.begin($1, $2, $3)', [u[name]!.cred.reveal(), slug, 'read']);
          const w = await who(c);
          const pid = (await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          await c.query('COMMIT');
          return { ...w, pid };
        } finally {
          c.release();
        }
      };
      const a = await run('olga', 'ctx-tenant');
      const b = await run('oscar', 'other-tenant');
      expect(a.pid).toBe(b.pid); // same backend
      expect(a.u).toBe(u.olga!.userId);
      expect(b).toMatchObject({ u: u.oscar!.userId, t: O.id });
    } finally {
      await pool.end();
    }
  });

  it('a second auth.begin in the same transaction is refused (no identity switch)', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.alice!.cred.reveal(), 'ctx-tenant', 'read']);
      expect(await code(c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']))).toBe('IOS09');
      await c.query('ROLLBACK');
    } finally {
      await c.end();
    }
  });

  it('a context established inside a rolled-back savepoint is gone', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SAVEPOINT s');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']);
      await c.query('ROLLBACK TO SAVEPOINT s');
      expect(await who(c)).toEqual({ t: null, u: null, m: null, p: null });
      await c.query('ROLLBACK');
    } finally {
      await c.end();
    }
  });

  it('DISCARD TEMP mid-transaction fails closed; DISCARD ALL (pooler reset) leaves a clean backend', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']);
      await c.query('DISCARD TEMP');
      expect(await who(c)).toEqual({ t: null, u: null, m: null, p: null });
      expect((await c.query('SELECT count(*)::int AS n FROM roles')).rows[0].n).toBe(0);
      await c.query('ROLLBACK');
      await c.query('DISCARD ALL');
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.alice!.cred.reveal(), 'ctx-tenant', 'read']);
      expect((await who(c)).u).toBe(u.alice!.userId);
      await c.query('COMMIT');
    } finally {
      await c.end();
    }
  });

  it('autocommit: a context lives for exactly one statement', async () => {
    const c = await conn();
    try {
      await c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']);
      expect(await who(c)).toEqual({ t: null, u: null, m: null, p: null });
    } finally {
      await c.end();
    }
  });

  it('two-phase commit cannot carry a context', async () => {
    const c = await conn();
    try {
      await c.query('BEGIN');
      await c.query('SELECT auth.begin($1, $2, $3)', [u.olga!.cred.reveal(), 'ctx-tenant', 'read']);
      expect(await code(c.query(`PREPARE TRANSACTION 'ctx-2pc'`))).not.toBe('ok');
    } finally {
      await c.end();
    }
  });

  it('200 interleaved transactions over 8 backends never cross identities', async () => {
    const pool = createPool(h.db.appUrl, 8);
    const names = ['alice', 'olga', 'oscar'] as const;
    const slug = { alice: 'ctx-tenant', olga: 'ctx-tenant', oscar: 'other-tenant' } as const;
    try {
      const results = await Promise.all(
        Array.from({ length: 200 }, async (_, i) => {
          const n = names[i % 3]!;
          const c = await pool.connect();
          try {
            await c.query('BEGIN');
            await c.query('SELECT auth.begin($1, $2, $3)', [u[n]!.cred.reveal(), slug[n], 'read']);
            await c.query('SELECT pg_sleep(0.001)');
            const w = await who(c);
            await c.query(i % 2 ? 'COMMIT' : 'ROLLBACK');
            return w.u === u[n]!.userId && w.m === u[n]!.membershipId;
          } finally {
            c.release();
          }
        }),
      );
      expect(results.every(Boolean)).toBe(true);
    } finally {
      await pool.end();
    }
  });
});

describe('auth.begin refuses every invalid credential', () => {
  it.each([
    ['forged token', async () => 'f'.repeat(43), 'ctx-tenant', 'IOS01'],
    ['too short', async () => 'short', 'ctx-tenant', 'IOS01'],
    ['revoked', async () => {
      const c = await fx.login(h.admin, u.alice!.userId);
      await h.admin.query(`UPDATE sessions SET revoked_at = now() WHERE token_hash = sha256(convert_to($1, 'UTF8'))`, [c.reveal()]);
      return c.reveal();
    }, 'ctx-tenant', 'IOS01'],
    ['expired', async () => (await fx.login(h.admin, u.alice!.userId, { expiresInSeconds: -1 })).reveal(), 'ctx-tenant', 'IOS01'],
    ['valid token, foreign tenant', async () => u.alice!.cred.reveal(), 'other-tenant', 'IOS04'],
    ['valid token, unknown tenant', async () => u.alice!.cred.reveal(), 'nope', 'IOS04'],
  ] as [string, () => Promise<string>, string, string][])('%s', async (_name, token, slug, expected) => {
    expect(await code(h.app.query('SELECT auth.begin($1, $2, $3)', [await token(), slug, 'read']))).toBe(expected);
  });

  it('invalid mode is refused', async () => {
    expect(await code(h.app.query('SELECT auth.begin($1, $2, $3)', [u.alice!.cred.reveal(), 'ctx-tenant', 'admin']))).toBe('22023');
  });

  it('system context: invalid job name or inactive tenant refused', async () => {
    expect(await code(h.worker.query('SELECT auth.begin_system($1, $2)', [T.id, 'Bad Name']))).toBe('22023');
    expect(await code(h.worker.query('SELECT auth.begin_system($1, $2)', [crypto.randomUUID(), 'job.x']))).toBe('IOS04');
  });
});
