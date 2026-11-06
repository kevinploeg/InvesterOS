import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, lintSchema, migrate, type TestDatabase } from '../src';

let db: TestDatabase;
let admin: pg.Client;

beforeAll(async () => {
  db = await createTestDatabase({ probe: true });
  admin = new pg.Client({ connectionString: db.adminUrl });
  await admin.connect();
});
afterAll(async () => {
  await admin?.end();
  await db?.drop();
});

describe('schema-lint (M0-AC5)', () => {
  it('reports zero violations on the migrated schema', async () => {
    expect(await lintSchema(admin)).toEqual([]);
  });

  it('detects a tenant table without RLS, without a restrictive policy and with a non-composite FK', async () => {
    await admin.query('BEGIN');
    try {
      await admin.query(`SET ROLE ios_owner`);
      await admin.query(`CREATE TABLE bad_table (tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid PRIMARY KEY,
        team_tenant uuid, team_id uuid)`);
      await admin.query(`CREATE TABLE bad_child (tenant_id uuid NOT NULL, id uuid PRIMARY KEY, parent_id uuid REFERENCES bad_table(id))`);
      await admin.query(`CREATE TABLE bad_global (id uuid PRIMARY KEY)`);
      const rules = (await lintSchema(admin)).map((x) => `${x.rule}:${x.object}`);
      expect(rules).toEqual(
        expect.arrayContaining([
          'R1-rls-enabled:bad_table',
          'R1-rls-forced:bad_table',
          'R3-restrictive-tenant-policy:bad_table',
          'R4-composite-fk:bad_child.bad_child_parent_id_fkey',
          'R2-unlisted-global-table:bad_global',
        ]),
      );
    } finally {
      await admin.query('ROLLBACK');
    }
  });

  it('detects a request role with BYPASSRLS', async () => {
    await admin.query('BEGIN');
    try {
      await admin.query('ALTER ROLE ios_worker BYPASSRLS');
      const rules = (await lintSchema(admin)).map((x) => `${x.rule}:${x.object}`);
      expect(rules).toContain('R5-role-privileges:ios_worker');
    } finally {
      await admin.query('ROLLBACK');
    }
  });

  it('request roles hold no BYPASSRLS / SUPERUSER and own no tables (M0-AC3)', async () => {
    const r = await admin.query(`SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('ios_app','ios_worker','ios_definer') ORDER BY 1`);
    expect(r.rows).toEqual([
      { rolname: 'ios_app', rolsuper: false, rolbypassrls: false },
      { rolname: 'ios_definer', rolsuper: false, rolbypassrls: false },
      { rolname: 'ios_worker', rolsuper: false, rolbypassrls: false },
    ]);
  });
});

describe('schema-lint M1-WP1 rules', () => {
  it('R9 detects a policy or function that trusts a GUC; R11 detects TEMPORARY for a request role; R10 definer scope', async () => {
    await admin.query('BEGIN');
    try {
      await admin.query(`SET ROLE ios_owner`);
      await admin.query(`CREATE FUNCTION app.bad_ctx() RETURNS uuid LANGUAGE sql AS $$ SELECT current_setting('app.tenant_id')::uuid $$`);
      await admin.query(`CREATE POLICY teams_guc ON teams FOR SELECT TO ios_app USING (current_setting('app.x', true) = 'y')`);
      await admin.query(`CREATE POLICY teams_definer ON teams FOR SELECT TO ios_definer USING (true)`);
      await admin.query('RESET ROLE');
      await admin.query(`GRANT TEMPORARY ON DATABASE ${db.name} TO ios_app`);
      const rules = (await lintSchema(admin)).map((x) => `${x.rule}:${x.object}`);
      expect(rules).toEqual(expect.arrayContaining([
        'R9-no-guc-identity:app.bad_ctx()',
        'R9-no-guc-identity:teams.teams_guc',
        'R10-definer-scope:teams.teams_definer',
        'R11-no-temp-for-request-roles:ios_app',
      ]));
    } finally {
      await admin.query('ROLLBACK');
    }
  });
});

describe('migrations', () => {
  it('are idempotent and refuse a modified applied migration', async () => {
    expect(await migrate(db.migratorUrl)).toEqual([]);
    await admin.query(`UPDATE meta.schema_migrations SET checksum = 'tampered' WHERE name = '0001_kernel_context'`);
    await expect(migrate(db.migratorUrl)).rejects.toThrow(/checksum mismatch/);
  });
});
