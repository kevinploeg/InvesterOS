-- 0004 (M1-WP1): DB-verified, session-bound request context.
--
-- Before: RLS trusted GUCs (app.tenant_id, app.membership_id, ...) set with set_config(). Any session
-- able to run SQL as ios_app could set them and act as another member.
-- After: the ONLY way to obtain a context is auth.begin(<raw session token>, <tenant slug>, <mode>),
-- which validates the session, user, tenant and membership inside the database and stores the result
-- in a per-connection temp table owned by ios_definer (ON COMMIT DELETE ROWS). The app.current_*()
-- functions read only that table. GUCs are no longer consulted anywhere (schema-lint R9).
--
-- Why a temp table and not a shared table keyed by (backend pid, transaction start time):
-- wall-clock timestamps are not monotonic and backend pids are reused, so a stale committed row could
-- match a later transaction. A temp table is private to the connection, emptied at every COMMIT and
-- ROLLBACK, and request roles hold no TEMPORARY privilege, so they cannot create, shadow, read or write it.
-- See docs/security/m1-clarifications.md (C2) and packages/kernel/test/context-safety.test.ts.

-- ---------------------------------------------------------------------------
-- Session policy (single row; not writable by request roles)
-- ---------------------------------------------------------------------------
CREATE TABLE meta.auth_policy (
  id                      boolean PRIMARY KEY DEFAULT true CHECK (id),
  idle_seconds            integer NOT NULL DEFAULT 1800 CHECK (idle_seconds BETWEEN 60 AND 86400),
  absolute_seconds        integer NOT NULL DEFAULT 43200 CHECK (absolute_seconds BETWEEN 300 AND 604800),
  last_seen_granularity_s integer NOT NULL DEFAULT 60 CHECK (last_seen_granularity_s BETWEEN 0 AND 300)
);
INSERT INTO meta.auth_policy DEFAULT VALUES;

GRANT USAGE ON SCHEMA meta TO ios_definer;
GRANT SELECT ON meta.auth_policy TO ios_definer;
GRANT CREATE ON SCHEMA app TO ios_definer; -- needed to transfer ownership of context functions

-- ---------------------------------------------------------------------------
-- Narrow access for ios_definer (it has NO BYPASSRLS: these policies are its only reach)
-- ---------------------------------------------------------------------------
CREATE POLICY tenants_definer_read ON tenants FOR SELECT TO ios_definer USING (true);
CREATE POLICY tenant_memberships_definer_read ON tenant_memberships FOR SELECT TO ios_definer USING (true);
CREATE POLICY sessions_definer_insert ON sessions FOR INSERT TO ios_definer WITH CHECK (true);
GRANT SELECT ON tenants, tenant_memberships TO ios_definer;
GRANT INSERT ON sessions TO ios_definer;
GRANT UPDATE (revoked_at, active_tenant_id, active_membership_id) ON sessions TO ios_definer;

-- ios_app no longer touches sessions directly: every session operation goes through auth.* functions.
DROP POLICY sessions_self ON sessions;
REVOKE ALL ON sessions FROM ios_app;

-- ---------------------------------------------------------------------------
-- Internal: make sure the per-connection context table exists and is ours.
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth._ctx_table() RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_owner oid;
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NULL THEN
    CREATE TEMP TABLE ios_tx_context (
      singleton      boolean PRIMARY KEY DEFAULT true CHECK (singleton),
      principal_type text NOT NULL CHECK (principal_type IN ('user', 'staff', 'system')),
      session_id     uuid,
      user_id        uuid,
      tenant_id      uuid,
      membership_id  uuid,
      job_name       text,
      established_at timestamptz NOT NULL DEFAULT clock_timestamp()
    ) ON COMMIT DELETE ROWS;
  END IF;
  SELECT c.relowner INTO v_owner FROM pg_class c WHERE c.oid = to_regclass('pg_temp.ios_tx_context');
  IF v_owner IS DISTINCT FROM 'ios_definer'::regrole::oid THEN
    RAISE EXCEPTION 'request context storage is not owned by ios_definer' USING ERRCODE = 'IOS99';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_temp.ios_tx_context) THEN
    RAISE EXCEPTION 'request context already established in this transaction' USING ERRCODE = 'IOS09';
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- auth.begin: validate a raw session token and establish the request context.
--   p_tenant_slug NULL  -> user-level context (tenant switcher, own memberships)
--   p_tenant_slug given -> staff context in that tenant; requires an ACTIVE membership in an ACTIVE tenant
-- Errors: IOS01 = no valid session (HTTP 401); IOS04 = tenant not accessible (HTTP 404, no disclosure).
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth.begin(p_token text, p_tenant_slug text, p_mode text)
  RETURNS TABLE (session_id uuid, user_id uuid, tenant_id uuid, tenant_slug text, membership_id uuid, active_tenant_slug text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_pol   meta.auth_policy%ROWTYPE;
  v_sess  record;
  v_mem   record;
BEGIN
  PERFORM auth._ctx_table();
  IF p_mode IS NULL OR p_mode NOT IN ('read', 'write') THEN
    RAISE EXCEPTION 'invalid mode' USING ERRCODE = '22023';
  END IF;
  IF p_token IS NULL OR length(p_token) NOT BETWEEN 32 AND 128 THEN
    RAISE EXCEPTION 'no valid session' USING ERRCODE = 'IOS01';
  END IF;
  SELECT * INTO v_pol FROM meta.auth_policy;

  SELECT s.id, s.user_id, s.last_seen_at, s.active_tenant_id INTO v_sess
  FROM public.sessions s JOIN public.users u ON u.id = s.user_id
  WHERE s.token_hash = sha256(convert_to(p_token, 'UTF8'))
    AND s.revoked_at IS NULL
    AND s.expires_at > now()
    AND s.last_seen_at > now() - make_interval(secs => v_pol.idle_seconds)
    AND u.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no valid session' USING ERRCODE = 'IOS01';
  END IF;

  -- Sliding idle window, written at most once per granularity period (avoids a write per request).
  IF v_sess.last_seen_at < now() - make_interval(secs => v_pol.last_seen_granularity_s) THEN
    UPDATE public.sessions SET last_seen_at = now() WHERE id = v_sess.id;
  END IF;

  IF p_tenant_slug IS NULL THEN
    INSERT INTO pg_temp.ios_tx_context (principal_type, session_id, user_id) VALUES ('user', v_sess.id, v_sess.user_id);
    RETURN QUERY SELECT v_sess.id, v_sess.user_id, NULL::uuid, NULL::text, NULL::uuid,
      (SELECT t.slug FROM public.tenants t WHERE t.id = v_sess.active_tenant_id);
    RETURN;
  END IF;

  SELECT t.id AS tid, t.slug, m.id AS mid INTO v_mem
  FROM public.tenants t
  JOIN public.tenant_memberships m ON m.tenant_id = t.id
  WHERE t.slug = p_tenant_slug AND t.status = 'active'
    AND m.user_id = v_sess.user_id AND m.status = 'active' AND m.principal_type = 'staff';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant not accessible' USING ERRCODE = 'IOS04';
  END IF;

  INSERT INTO pg_temp.ios_tx_context (principal_type, session_id, user_id, tenant_id, membership_id)
  VALUES ('staff', v_sess.id, v_sess.user_id, v_mem.tid, v_mem.mid);
  RETURN QUERY SELECT v_sess.id, v_sess.user_id, v_mem.tid, v_mem.slug, v_mem.mid,
    (SELECT t.slug FROM public.tenants t WHERE t.id = v_sess.active_tenant_id);
END
$$;

-- System principal for named background jobs. Only the worker login may obtain it.
CREATE FUNCTION auth.begin_system(p_tenant_id uuid, p_job_name text) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  IF session_user <> 'ios_worker' THEN
    RAISE EXCEPTION 'system context is reserved for ios_worker' USING ERRCODE = '42501';
  END IF;
  IF p_job_name IS NULL OR p_job_name !~ '^[a-z][a-z0-9_.]{1,62}$' THEN
    RAISE EXCEPTION 'invalid job name' USING ERRCODE = '22023';
  END IF;
  PERFORM auth._ctx_table();
  PERFORM 1 FROM public.tenants t WHERE t.id = p_tenant_id AND t.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant not accessible' USING ERRCODE = 'IOS04';
  END IF;
  INSERT INTO pg_temp.ios_tx_context (principal_type, tenant_id, job_name) VALUES ('system', p_tenant_id, p_job_name);
END
$$;

-- Session creation: ONLY the ios_auth login (OIDC callback), after the app validated the ID token.
-- Binding is (issuer, subject); e-mail is never used. Returns no row for unknown/disabled identities.
CREATE FUNCTION auth.create_session(p_issuer text, p_subject text, p_token text, p_previous_token text)
  RETURNS TABLE (session_id uuid, user_id uuid, active_tenant_slug text, expires_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_pol  meta.auth_policy%ROWTYPE;
  v_user uuid;
  v_mem  record;
  v_id   uuid := gen_random_uuid();
  v_exp  timestamptz;
BEGIN
  IF session_user <> 'ios_auth' THEN
    RAISE EXCEPTION 'session creation is reserved for ios_auth' USING ERRCODE = '42501';
  END IF;
  IF p_token IS NULL OR length(p_token) NOT BETWEEN 32 AND 128 THEN
    RAISE EXCEPTION 'invalid token' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO v_pol FROM meta.auth_policy;
  SELECT u.id INTO v_user
  FROM public.user_identities ui JOIN public.users u ON u.id = ui.user_id
  WHERE ui.issuer = p_issuer AND ui.subject = p_subject AND u.status = 'active';
  IF v_user IS NULL THEN
    RETURN;
  END IF;
  IF p_previous_token IS NOT NULL THEN -- rotation on login: the previous session dies
    UPDATE public.sessions s SET revoked_at = now()
    WHERE s.token_hash = sha256(convert_to(p_previous_token, 'UTF8')) AND s.revoked_at IS NULL;
  END IF;
  SELECT m.tenant_id, m.id, t.slug INTO v_mem
  FROM public.tenant_memberships m JOIN public.tenants t ON t.id = m.tenant_id
  WHERE m.user_id = v_user AND m.status = 'active' AND t.status = 'active'
  ORDER BY t.slug LIMIT 1;
  v_exp := now() + make_interval(secs => v_pol.absolute_seconds);
  INSERT INTO public.sessions (id, token_hash, user_id, active_tenant_id, active_membership_id, expires_at)
  VALUES (v_id, sha256(convert_to(p_token, 'UTF8')), v_user, v_mem.tenant_id, v_mem.id, v_exp);
  RETURN QUERY SELECT v_id, v_user, v_mem.slug::text, v_exp;
END
$$;

-- Logout: revokes the session of the CURRENT context only.
CREATE FUNCTION auth.revoke_current_session() RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_sid uuid;
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NOT NULL THEN
    SELECT c.session_id INTO v_sid FROM pg_temp.ios_tx_context c;
  END IF;
  IF v_sid IS NULL THEN
    RAISE EXCEPTION 'no valid session' USING ERRCODE = 'IOS01';
  END IF;
  UPDATE public.sessions SET revoked_at = now() WHERE id = v_sid AND revoked_at IS NULL;
END
$$;

-- ---------------------------------------------------------------------------
-- Context readers: replace the GUC-based versions from 0001. They read ONLY the context table.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.current_tenant() RETURNS uuid
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NULL THEN RETURN NULL; END IF;
  RETURN (SELECT c.tenant_id FROM pg_temp.ios_tx_context c);
END
$$;

CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS uuid
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NULL THEN RETURN NULL; END IF;
  RETURN (SELECT c.user_id FROM pg_temp.ios_tx_context c);
END
$$;

CREATE OR REPLACE FUNCTION app.current_membership() RETURNS uuid
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NULL THEN RETURN NULL; END IF;
  RETURN (SELECT c.membership_id FROM pg_temp.ios_tx_context c);
END
$$;

CREATE OR REPLACE FUNCTION app.principal_type() RETURNS text
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NULL THEN RETURN NULL; END IF;
  RETURN (SELECT c.principal_type FROM pg_temp.ios_tx_context c);
END
$$;

-- ---------------------------------------------------------------------------
-- Tenant isolation policies: evaluate the context once per statement (InitPlan).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT tablename, policyname FROM pg_policies
    WHERE schemaname = 'public' AND policyname = tablename || '_tenant_isolation' AND tablename <> 'tenant_memberships'
  LOOP
    EXECUTE format(
      'ALTER POLICY %I ON %I USING (tenant_id = (SELECT app.current_tenant())) WITH CHECK (tenant_id = (SELECT app.current_tenant()))',
      r.policyname, r.tablename);
  END LOOP;
END
$$;
ALTER POLICY tenant_memberships_tenant_isolation ON tenant_memberships
  USING (tenant_id = (SELECT app.current_tenant()) OR user_id = (SELECT app.current_user_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant()));

-- ---------------------------------------------------------------------------
-- Ownership + grants. Ownership transfer needs the migrator's own membership in ios_definer.
-- ---------------------------------------------------------------------------
RESET ROLE;
ALTER FUNCTION auth._ctx_table() OWNER TO ios_definer;
ALTER FUNCTION auth.begin(text, text, text) OWNER TO ios_definer;
ALTER FUNCTION auth.begin_system(uuid, text) OWNER TO ios_definer;
ALTER FUNCTION auth.create_session(text, text, text, text) OWNER TO ios_definer;
ALTER FUNCTION auth.revoke_current_session() OWNER TO ios_definer;
ALTER FUNCTION app.current_tenant() OWNER TO ios_definer;
ALTER FUNCTION app.current_user_id() OWNER TO ios_definer;
ALTER FUNCTION app.current_membership() OWNER TO ios_definer;
ALTER FUNCTION app.principal_type() OWNER TO ios_definer;

REVOKE ALL ON FUNCTION auth._ctx_table(), auth.begin(text, text, text), auth.begin_system(uuid, text),
  auth.create_session(text, text, text, text), auth.revoke_current_session() FROM PUBLIC, ios_app, ios_worker;
REVOKE ALL ON FUNCTION app.current_tenant(), app.current_user_id(), app.current_membership(), app.principal_type() FROM PUBLIC;
-- auth._ctx_table is internal: only callable by the definer-owned functions themselves.
GRANT EXECUTE ON FUNCTION auth.begin(text, text, text), auth.revoke_current_session() TO ios_app, ios_worker;
GRANT EXECUTE ON FUNCTION auth.begin_system(uuid, text) TO ios_worker;
GRANT EXECUTE ON FUNCTION auth.create_session(text, text, text, text) TO ios_auth;
GRANT USAGE ON SCHEMA auth TO ios_auth;
GRANT EXECUTE ON FUNCTION app.current_tenant(), app.current_user_id(), app.current_membership(), app.principal_type()
  TO ios_app, ios_worker;
-- The M0 pre-context functions are superseded by auth.begin / auth.create_session.
DROP FUNCTION auth.lookup_session(bytea, integer);
DROP FUNCTION auth.resolve_identity(text, text);
SET ROLE ios_owner;
