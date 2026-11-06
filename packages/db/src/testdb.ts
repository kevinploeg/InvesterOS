import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { adminUrlFor, dbEnv, roleUrl } from './config';
import { bootstrap, migrate } from './migrate';

export const PROBE_MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'probe-migrations');

export interface TestDatabase {
  name: string;
  /** Superuser connection to this DB. TEST FIXTURES ONLY (bypasses RLS). */
  adminUrl: string;
  appUrl: string;
  workerUrl: string;
  migratorUrl: string;
  drop(): Promise<void>;
}

/** Creates an isolated, fully migrated database. Synthetic data only. */
export async function createTestDatabase(opts: { probe?: boolean } = {}): Promise<TestDatabase> {
  const env = dbEnv();
  const name = `ios_test_${randomBytes(6).toString('hex')}`;
  await bootstrap(env.adminUrl, name, env.passwords);
  const migratorUrl = roleUrl(env, 'ios_migrator', name);
  await migrate(migratorUrl, opts.probe ? [PROBE_MIGRATIONS_DIR] : []);
  const adminUrl = adminUrlFor(env, name);
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`INSERT INTO meta.synthetic_marker (environment) VALUES ('synthetic')`);
  await admin.end();
  return {
    name,
    adminUrl,
    appUrl: roleUrl(env, 'ios_app', name),
    workerUrl: roleUrl(env, 'ios_worker', name),
    migratorUrl,
    async drop() {
      const c = new pg.Client({ connectionString: env.adminUrl });
      await c.connect();
      await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await c.end();
    },
  };
}
