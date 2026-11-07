import type pg from 'pg';

/**
 * Tables without tenant_id. Each must be justified here; anything else in `public`
 * without tenant_id fails the lint.
 */
export const GLOBAL_TABLES: Readonly<Record<string, string>> = {
  tenants: 'The tenant registry itself; readable only for tenants the user is an active member of.',
  users: 'Global identity (a person may belong to several tenants). Holds no tenant business data.',
  user_identities: 'IdP (issuer, subject) bindings. Readable only by the user and the auth definer.',
  sessions: 'Server-side sessions; scoped to the user, not the tenant.',
};

export const REQUIRED_POLICY_ROLES = ['ios_app', 'ios_worker'] as const;
const APP_ROLES = ['ios_app', 'ios_worker', 'ios_definer', 'ios_auth'] as const;

/** Tables on which ios_definer may hold policies (pre-context auth paths only). */
export const DEFINER_TABLES = [
  'users', 'user_identities', 'sessions', 'tenants', 'tenant_memberships', // session + context validation
  'role_assignments', 'role_permissions', 'team_members', 'securable_grants', 'roles', // single permission evaluator + epoch bumps
  'jobs', // job execution re-validation
] as const;

export interface LintViolation {
  rule: string;
  object: string;
  detail: string;
}

/**
 * Structural security checks against pg_catalog. Run in CI after migrations; any violation fails
 * the build. These checks cannot be satisfied by "forgetting" something: they enumerate reality.
 */
export async function lintSchema(db: pg.ClientBase): Promise<LintViolation[]> {
  const v: LintViolation[] = [];

  // R1: every table in public has RLS enabled and forced.
  const tables = await db.query<{ relname: string; rls: boolean; force: boolean; owner: string }>(`
    SELECT c.relname, c.relrowsecurity AS rls, c.relforcerowsecurity AS force, pg_get_userbyid(c.relowner) AS owner
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`);
  for (const t of tables.rows) {
    if (!t.rls) v.push({ rule: 'R1-rls-enabled', object: t.relname, detail: 'ROW LEVEL SECURITY not enabled' });
    if (!t.force) v.push({ rule: 'R1-rls-forced', object: t.relname, detail: 'FORCE ROW LEVEL SECURITY not set' });
    if (t.owner !== 'ios_owner') v.push({ rule: 'R6-owner', object: t.relname, detail: `owned by ${t.owner}, expected ios_owner` });
  }

  // R2: tenant tables have tenant_id NOT NULL; non-tenant tables are allow-listed.
  const cols = await db.query<{ relname: string; notnull: boolean }>(`
    SELECT c.relname, a.attnotnull AS notnull
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND a.attname = 'tenant_id' AND NOT a.attisdropped`);
  const tenantTables = new Set(cols.rows.map((r) => r.relname));
  for (const r of cols.rows) {
    if (!r.notnull) v.push({ rule: 'R2-tenant-id-not-null', object: r.relname, detail: 'tenant_id is nullable' });
  }
  for (const t of tables.rows) {
    if (!tenantTables.has(t.relname) && !(t.relname in GLOBAL_TABLES)) {
      v.push({ rule: 'R2-unlisted-global-table', object: t.relname, detail: 'no tenant_id and not in GLOBAL_TABLES' });
    }
  }

  // R3: every tenant table has a RESTRICTIVE tenant-isolation policy covering ALL commands
  // for every request role, whose USING and WITH CHECK reference app.current_tenant().
  const pols = await db.query<{
    tablename: string; policyname: string; permissive: string; cmd: string; roles: string[]; qual: string | null; with_check: string | null;
  }>(`SELECT tablename, policyname, permissive, cmd, roles::text[] AS roles, qual, with_check
      FROM pg_policies WHERE schemaname = 'public'`);
  for (const t of tenantTables) {
    const iso = pols.rows.find(
      (p) => p.tablename === t && p.permissive === 'RESTRICTIVE' && p.cmd === 'ALL' && p.policyname === `${t}_tenant_isolation`,
    );
    if (!iso) {
      v.push({ rule: 'R3-restrictive-tenant-policy', object: t, detail: `missing RESTRICTIVE FOR ALL policy ${t}_tenant_isolation` });
      continue;
    }
    for (const role of REQUIRED_POLICY_ROLES) {
      if (!iso.roles.includes(role)) v.push({ rule: 'R3-policy-roles', object: t, detail: `isolation policy does not apply to ${role}` });
    }
    if (!iso.qual?.includes('current_tenant()') || !iso.with_check?.includes('current_tenant()')) {
      v.push({ rule: 'R3-policy-expression', object: t, detail: 'USING/WITH CHECK must reference app.current_tenant()' });
    }
  }

  // R4: foreign keys from a tenant table to a tenant table must include tenant_id (composite FK).
  const fks = await db.query<{ conname: string; src: string; dst: string; src_cols: string[]; dst_cols: string[] }>(`
    SELECT con.conname, cs.relname AS src, cd.relname AS dst,
           ARRAY(SELECT a.attname FROM unnest(con.conkey) k JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k)::text[] AS src_cols,
           ARRAY(SELECT a.attname FROM unnest(con.confkey) k JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k)::text[] AS dst_cols
    FROM pg_constraint con
    JOIN pg_class cs ON cs.oid = con.conrelid JOIN pg_namespace ns ON ns.oid = cs.relnamespace
    JOIN pg_class cd ON cd.oid = con.confrelid
    WHERE con.contype = 'f' AND ns.nspname = 'public'`);
  for (const fk of fks.rows) {
    if (tenantTables.has(fk.src) && tenantTables.has(fk.dst)) {
      const i = fk.src_cols.indexOf('tenant_id');
      if (i < 0 || fk.dst_cols[i] !== 'tenant_id') {
        v.push({ rule: 'R4-composite-fk', object: `${fk.src}.${fk.conname}`, detail: `FK to ${fk.dst} does not include tenant_id` });
      }
    }
  }

  // R5: request roles must not be superuser, bypass RLS, own anything, or create roles/DBs.
  const roles = await db.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean; rolcreaterole: boolean; rolcreatedb: boolean }>(
    `SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = ANY($1)`,
    [APP_ROLES],
  );
  for (const name of APP_ROLES) {
    const r = roles.rows.find((x) => x.rolname === name);
    if (!r) { v.push({ rule: 'R5-role-missing', object: name, detail: 'role does not exist' }); continue; }
    if (r.rolsuper || r.rolbypassrls || r.rolcreaterole || r.rolcreatedb) {
      v.push({ rule: 'R5-role-privileges', object: name, detail: 'must be NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB' });
    }
  }
  const owned = await db.query<{ owner: string; n: string }>(`
    SELECT pg_get_userbyid(c.relowner) AS owner, count(*)::text AS n
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ('public', 'app', 'auth', 'meta') AND pg_get_userbyid(c.relowner) IN ('ios_app', 'ios_worker', 'ios_auth')
    GROUP BY 1`);
  for (const o of owned.rows) v.push({ rule: 'R5-request-role-owns-objects', object: o.owner, detail: `owns ${o.n} relations` });

  // R7: SECURITY DEFINER functions must pin search_path and be owned by ios_definer.
  const defs = await db.query<{ fn: string; owner: string; config: string[] | null }>(`
    SELECT p.oid::regprocedure::text AS fn, pg_get_userbyid(p.proowner) AS owner, p.proconfig AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.prosecdef AND n.nspname IN ('public', 'app', 'auth', 'meta')`);
  for (const d of defs.rows) {
    if (d.owner !== 'ios_definer') v.push({ rule: 'R7-definer-owner', object: d.fn, detail: `owned by ${d.owner}` });
    if (!d.config?.some((c) => c.startsWith('search_path='))) v.push({ rule: 'R7-definer-search-path', object: d.fn, detail: 'search_path not pinned' });
  }

  // R8: no function executable by PUBLIC in app/auth schemas.
  const pub = await db.query<{ fn: string }>(`
    SELECT p.oid::regprocedure::text AS fn
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('app', 'auth') AND has_function_privilege('public', p.oid, 'EXECUTE')`);
  for (const f of pub.rows) v.push({ rule: 'R8-public-execute', object: f.fn, detail: 'EXECUTE granted to PUBLIC' });

  // R9: nothing may derive identity/tenant from GUCs (set_config is writable by any session).
  const guc = await db.query<{ obj: string }>(`
    SELECT p.oid::regprocedure::text AS obj FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('public', 'app', 'auth') AND p.prosrc ~* 'current_setting\\s*\\(\\s*''app\\.'
    UNION ALL
    SELECT tablename || '.' || policyname FROM pg_policies
    WHERE schemaname = 'public' AND (coalesce(qual, '') || coalesce(with_check, '')) ~* 'current_setting'`);
  for (const g of guc.rows) v.push({ rule: 'R9-no-guc-identity', object: g.obj, detail: 'reads a GUC; identity must come from auth.begin' });

  // R10: ios_definer policies only on the allow-listed pre-context tables.
  for (const p of pols.rows) {
    if (p.roles.includes('ios_definer') && !(DEFINER_TABLES as readonly string[]).includes(p.tablename)) {
      v.push({ rule: 'R10-definer-scope', object: `${p.tablename}.${p.policyname}`, detail: 'ios_definer policy outside DEFINER_TABLES' });
    }
  }

  // R11: request roles must not hold TEMPORARY (they could otherwise create/shadow temp objects).
  const temp = await db.query<{ rolname: string }>(`
    SELECT r.rolname FROM pg_roles r WHERE r.rolname IN ('ios_app', 'ios_worker', 'ios_auth')
      AND has_database_privilege(r.rolname, current_database(), 'TEMPORARY')`);
  for (const t of temp.rows) v.push({ rule: 'R11-no-temp-for-request-roles', object: t.rolname, detail: 'holds TEMPORARY on the database' });

  return v;
}
