import pg from 'pg';
import { isUuid } from '../ids';
import type { TenantContext } from '../context';

export type Tx = pg.PoolClient;

export interface DbPools {
  /** ios_app: user requests. */
  app: pg.Pool;
}

export function createPool(connectionString: string, max = 10): pg.Pool {
  return new pg.Pool({ connectionString, max, idleTimeoutMillis: 30_000, application_name: 'investoros' });
}

async function inTx<T>(pool: pg.Pool, settings: Record<string, string>, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const names = Object.keys(settings);
    if (names.length) {
      // set_config(..., true) = transaction-local: the setting dies at COMMIT/ROLLBACK, so a pooled
      // connection can never carry one tenant's context into another request.
      const sql = `SELECT ${names.map((_, i) => `set_config($${2 * i + 1}, $${2 * i + 2}, true)`).join(', ')}`;
      await client.query(sql, names.flatMap((n) => [n, settings[n]!]));
    }
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** Runs fn in a transaction bound to a tenant + principal. The ONLY way to touch tenant data. */
export function withTenantTx<T>(pool: pg.Pool, ctx: TenantContext, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (!isUuid(ctx.tenantId)) throw new Error('withTenantTx: invalid tenantId');
  if (ctx.principalType === 'staff') {
    if (!isUuid(ctx.userId) || !isUuid(ctx.membershipId)) throw new Error('withTenantTx: invalid principal');
    return inTx(
      pool,
      { 'app.tenant_id': ctx.tenantId, 'app.user_id': ctx.userId, 'app.membership_id': ctx.membershipId, 'app.principal_type': 'staff' },
      fn,
    );
  }
  return inTx(pool, { 'app.tenant_id': ctx.tenantId, 'app.principal_type': 'system' }, fn);
}

/** User-scoped transaction without a tenant (login, tenant switcher, own sessions). */
export function withUserTx<T>(pool: pg.Pool, userId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (!isUuid(userId)) throw new Error('withUserTx: invalid userId');
  return inTx(pool, { 'app.user_id': userId }, fn);
}

/** No context at all: only the SECURITY DEFINER auth.* functions are useful here. */
export function withAnonymousTx<T>(pool: pg.Pool, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return inTx(pool, {}, fn);
}

/**
 * MVP data guard: refuse to run against any database that is not explicitly marked synthetic.
 * Real customer data is out of scope until the M5 go-live gate.
 */
export async function assertSyntheticDatabase(pool: pg.Pool): Promise<void> {
  const r = await pool.query<{ environment: string }>('SELECT environment FROM meta.synthetic_marker');
  if (r.rows[0]?.environment !== 'synthetic') {
    throw new Error('Refusing to start: database is not marked synthetic (meta.synthetic_marker). Synthetic data only.');
  }
}
