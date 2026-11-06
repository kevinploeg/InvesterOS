import pg from 'pg';
import { createTestDatabase, type TestDatabase } from '@investoros/db';
import { createPool, type SessionCredential, type TxMode } from '../src/db';

export interface Harness {
  db: TestDatabase;
  admin: pg.Client;
  app: pg.Pool;
  worker: pg.Pool;
  auth: pg.Pool;
  close(): Promise<void>;
}

export async function harness(opts: { probe?: boolean } = {}): Promise<Harness> {
  const db = await createTestDatabase(opts);
  const admin = new pg.Client({ connectionString: db.adminUrl });
  await admin.connect();
  const app = createPool(db.appUrl, 4);
  const worker = createPool(db.workerUrl, 2);
  const auth = createPool(db.authUrl, 2);
  return {
    db,
    admin,
    app,
    worker,
    auth,
    async close() {
      await Promise.all([app.end(), worker.end(), auth.end()]);
      await admin.end();
      await db.drop();
    },
  };
}

export const ISSUER = 'https://idp.synthetic.test';

/** Who runs a raw statement: a credential (+ tenant slug, or null for user-level), or nobody. */
export type As = { cred: SessionCredential; slug: string | null; mode?: TxMode } | null;

type Result = { rows: Record<string, unknown>[]; rowCount: number; code?: undefined } | { code: string; rows: []; rowCount: 0 };

/**
 * Runs a raw statement as ios_app exactly like a request would: BEGIN, auth.begin(token, slug), statement,
 * ROLLBACK. Returns rows/rowCount, or the SQLSTATE of the first error (from auth.begin or the statement).
 */
export async function asApp(pool: pg.Pool, as: As, sql: string, params: unknown[] = []): Promise<Result> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    try {
      if (as) await c.query('SELECT auth.begin($1, $2, $3)', [as.cred.reveal(), as.slug, as.mode ?? 'write']);
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
