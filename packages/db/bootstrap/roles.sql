-- InvestorOS database bootstrap. Run ONCE per cluster by an administrator
-- (local: postgres superuser; AWS RDS: the master user). Idempotent.
--
-- Role model (see docs/security/rls-design.md):
--   ios_owner      NOLOGIN  owns all schema objects. Subject to FORCE RLS like everyone else.
--   ios_migrator   LOGIN    member of ios_owner; used by CI/CD migrations only.
--   ios_app        LOGIN    NOBYPASSRLS; serves every user request. DML only, owns nothing.
--   ios_worker     LOGIN    NOBYPASSRLS; background jobs. Same policies as ios_app.
--   ios_definer    NOLOGIN  NOBYPASSRLS; owns the few SECURITY DEFINER auth functions that must
--                           run before a user/tenant context exists (identity + session lookup).
--                           Has explicit, narrow policies on exactly those tables.
-- No role used by the application has BYPASSRLS or SUPERUSER.
--
-- :'app_password', :'migrator_password', :'worker_password' are psql variables / runner params.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ios_owner') THEN
    CREATE ROLE ios_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ios_definer') THEN
    CREATE ROLE ios_definer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ios_migrator') THEN
    CREATE ROLE ios_migrator LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ios_app') THEN
    CREATE ROLE ios_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ios_worker') THEN
    CREATE ROLE ios_worker LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
$$;

-- The migrator may act as owner (to create objects) and as definer (to hand over
-- ownership of SECURITY DEFINER functions). It never serves requests.
GRANT ios_owner TO ios_migrator;
GRANT ios_definer TO ios_migrator;
