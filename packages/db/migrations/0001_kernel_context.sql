-- 0001: schemas, request-context functions, permission catalog, migration hygiene.
-- Runs as ios_owner (the migration runner does SET ROLE ios_owner).

CREATE SCHEMA IF NOT EXISTS app;   -- context + authorization helper functions (SECURITY INVOKER)
CREATE SCHEMA IF NOT EXISTS auth;  -- the few SECURITY DEFINER functions needed before context exists
-- meta schema (migrations bookkeeping) is created by the runner.

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA app FROM PUBLIC;
REVOKE ALL ON SCHEMA auth FROM PUBLIC;
GRANT USAGE ON SCHEMA public, app, auth TO ios_app, ios_worker;
GRANT USAGE ON SCHEMA public, auth TO ios_definer;
-- ios_definer must hold CREATE on auth so the migrator can transfer function ownership to it.
GRANT CREATE ON SCHEMA auth TO ios_definer;

-- Functions are not executable by PUBLIC unless explicitly granted.
ALTER DEFAULT PRIVILEGES FOR ROLE ios_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Request context. Set ONLY via set_config(name, value, true) inside a transaction
-- (transaction-local), by kernel/db withTenantTx/withUserTx. Missing context => NULL
-- => every policy comparison fails => zero rows (fail closed). A malformed value
-- raises an error (also fail closed).
-- ---------------------------------------------------------------------------
CREATE FUNCTION app.current_tenant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE FUNCTION app.current_user_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;

CREATE FUNCTION app.current_membership() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('app.membership_id', true), '')::uuid $$;

-- 'staff' for user requests; 'system' only for named background jobs. Portal reserved.
CREATE FUNCTION app.principal_type() RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('app.principal_type', true), '') $$;

GRANT EXECUTE ON FUNCTION app.current_tenant(), app.current_user_id(), app.current_membership(),
  app.principal_type() TO ios_app, ios_worker;

-- ---------------------------------------------------------------------------
-- Permission catalog. Mirrors packages/kernel/src/authz/permissions.ts exactly
-- (a test enforces equality). role_permissions references it, so a typo cannot
-- silently create a permission nobody checks.
-- ---------------------------------------------------------------------------
CREATE TABLE meta.permissions (
  key         text PRIMARY KEY CHECK (key ~ '^[a-z]+(\.[a-z_]+)+$'),
  description text NOT NULL,
  scopable    boolean NOT NULL DEFAULT false
);
GRANT SELECT ON meta.permissions TO ios_app, ios_worker;
GRANT USAGE ON SCHEMA meta TO ios_app, ios_worker;

-- Synthetic-data marker. Non-production environments MUST contain exactly this row;
-- the app refuses to start without it. Production provisioning never creates it.
CREATE TABLE meta.synthetic_marker (
  id          boolean PRIMARY KEY DEFAULT true CHECK (id),
  environment text NOT NULL CHECK (environment = 'synthetic'),
  created_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON meta.synthetic_marker TO ios_app, ios_worker;
