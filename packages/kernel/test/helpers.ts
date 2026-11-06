import pg from 'pg';
import { createTestDatabase, type TestDatabase } from '@investoros/db';
import { createPool } from '../src/db';

export interface Harness {
  db: TestDatabase;
  admin: pg.Client;
  app: pg.Pool;
  close(): Promise<void>;
}

export async function harness(opts: { probe?: boolean } = {}): Promise<Harness> {
  const db = await createTestDatabase(opts);
  const admin = new pg.Client({ connectionString: db.adminUrl });
  await admin.connect();
  const app = createPool(db.appUrl, 4);
  return {
    db,
    admin,
    app,
    async close() {
      await app.end();
      await admin.end();
      await db.drop();
    },
  };
}

export const ISSUER = 'https://idp.synthetic.test';

/** Runs a raw statement as ios_app with an arbitrary context; returns rowCount or the SQLSTATE of the error. */
export async function asApp(
  pool: pg.Pool,
  settings: Record<string, string>,
  sql: string,
  params: unknown[] = [],
): Promise<{ rows: Record<string, unknown>[]; rowCount: number; code?: undefined } | { code: string; rows: []; rowCount: 0 }> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    for (const [k, v] of Object.entries(settings)) await c.query('SELECT set_config($1, $2, true)', [k, v]);
    try {
      const r = await c.query(sql, params);
      return { rows: r.rows, rowCount: r.rowCount ?? 0 };
    } catch (e) {
      return { code: (e as { code: string }).code, rows: [], rowCount: 0 };
    }
  } finally {
    await c.query('ROLLBACK').catch(() => undefined);
    c.release();
  }
}

export const staffSettings = (tenantId: string, userId: string, membershipId: string): Record<string, string> => ({
  'app.tenant_id': tenantId,
  'app.user_id': userId,
  'app.membership_id': membershipId,
  'app.principal_type': 'staff',
});
