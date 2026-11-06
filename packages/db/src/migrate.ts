import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const here = dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS_DIR = join(here, '..', 'migrations');
const BOOTSTRAP_SQL = join(here, '..', 'bootstrap', 'roles.sql');

export interface RolePasswords {
  app: string;
  migrator: string;
  worker: string;
  auth: string;
}

/**
 * Cluster/database bootstrap. Needs an administrative connection (local superuser or RDS master).
 * Idempotent: creates roles, sets passwords, creates the database owned by ios_owner and locks
 * down CONNECT. Never used by the running application.
 */
export async function bootstrap(adminUrl: string, database: string, passwords: RolePasswords): Promise<void> {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database)) throw new Error(`Invalid database name: ${database}`);
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(await readFile(BOOTSTRAP_SQL, 'utf8'));
    for (const [role, pw] of [
      ['ios_app', passwords.app],
      ['ios_migrator', passwords.migrator],
      ['ios_worker', passwords.worker],
      ['ios_auth', passwords.auth],
    ] as const) {
      await admin.query(`ALTER ROLE ${role} PASSWORD ${admin.escapeLiteral(pw)}`);
    }
    const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [database]);
    if (exists.rowCount === 0) {
      await admin.query(`CREATE DATABASE ${database} OWNER ios_owner`);
    }
    await admin.query(`REVOKE ALL ON DATABASE ${database} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${database} TO ios_app, ios_worker, ios_migrator, ios_auth`);
    // ios_definer holds the per-connection request-context temp table (see migration 0004).
    // Request roles deliberately do NOT get TEMPORARY: they cannot create or shadow temp objects.
    await admin.query(`GRANT TEMPORARY ON DATABASE ${database} TO ios_definer`);
    await admin.query(`GRANT CONNECT, TEMPORARY ON DATABASE ${database} TO ios_owner`);
  } finally {
    await admin.end();
  }
}

export interface MigrationFile {
  version: string;
  name: string;
  sql: string;
  checksum: string;
}

export async function loadMigrations(dir = MIGRATIONS_DIR): Promise<MigrationFile[]> {
  const files = (await readdir(dir)).filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f)).sort();
  return Promise.all(
    files.map(async (f) => {
      const sql = await readFile(join(dir, f), 'utf8');
      return {
        version: f.slice(0, 4),
        name: f.replace(/\.sql$/, ''),
        sql,
        checksum: createHash('sha256').update(sql).digest('hex'),
      };
    }),
  );
}

/**
 * Applies pending migrations as ios_owner (via the migrator login), each in its own transaction.
 * Already-applied migrations are verified by checksum: editing an applied migration is an error.
 */
export async function migrate(migratorUrl: string, extraDirs: string[] = []): Promise<string[]> {
  const client = new pg.Client({ connectionString: migratorUrl });
  await client.connect();
  const applied: string[] = [];
  try {
    await client.query('SET ROLE ios_owner');
    await client.query(`CREATE SCHEMA IF NOT EXISTS meta`);
    await client.query(`REVOKE ALL ON SCHEMA meta FROM PUBLIC`);
    await client.query(`CREATE TABLE IF NOT EXISTS meta.schema_migrations (
      name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    const done = new Map<string, string>(
      (await client.query<{ name: string; checksum: string }>('SELECT name, checksum FROM meta.schema_migrations')).rows.map(
        (r) => [r.name, r.checksum],
      ),
    );
    const all = (await loadMigrations()).concat(...(await Promise.all(extraDirs.map((d) => loadMigrations(d)))));
    for (const m of all) {
      const prior = done.get(m.name);
      if (prior !== undefined) {
        if (prior !== m.checksum) throw new Error(`Applied migration ${m.name} was modified (checksum mismatch)`);
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(m.sql);
        await client.query('INSERT INTO meta.schema_migrations (name, checksum) VALUES ($1, $2)', [m.name, m.checksum]);
        await client.query('COMMIT');
        applied.push(m.name);
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`Migration ${m.name} failed: ${(err as Error).message}`, { cause: err });
      }
    }
  } finally {
    await client.end();
  }
  return applied;
}
