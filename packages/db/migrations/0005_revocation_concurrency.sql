-- 0005 (M1-WP2): immediate revocation and race-free permission changes.
--
-- 1. tenant_memberships.authz_epoch is bumped (row UPDATE) by every rights-changing mutation for every
--    affected membership: role assignments (direct or team), team membership, role permissions, grants,
--    user disable. Membership status changes update the row themselves.
-- 2. auth.begin in 'write' mode takes FOR SHARE on the actor's membership row (and the tenant row).
--    A concurrent revocation must UPDATE that row, so it waits for in-flight writes; writes that start
--    after the revocation commits re-check the row and are refused. No time-of-check/time-of-use window.
-- 3. auth.begin in 'iam' mode first takes a per-tenant advisory lock, THEN the row locks. All IAM
--    mutations run in 'iam' mode (enforced by triggers in 0006), so they serialise without deadlocks.
-- 4. Background jobs: enqueued in the user's transaction (actor recorded by the DB), executed through
--    auth.begin_job, which re-validates the enqueuer at execution time.

ALTER TABLE tenant_memberships ADD COLUMN authz_epoch bigint NOT NULL DEFAULT 0;

-- app.has_permission becomes definer-owned and calls the app.current_*() readers.
GRANT USAGE ON SCHEMA app TO ios_definer;

-- ios_definer may lock and bump memberships (FOR SHARE needs UPDATE privilege on a column).
CREATE POLICY tenant_memberships_definer_update ON tenant_memberships FOR UPDATE TO ios_definer USING (true) WITH CHECK (true);
GRANT UPDATE (authz_epoch) ON tenant_memberships TO ios_definer;
CREATE POLICY tenants_definer_lock ON tenants FOR UPDATE TO ios_definer USING (true) WITH CHECK (true);
GRANT UPDATE (status) ON tenants TO ios_definer; -- required for FOR SHARE; no definer function updates tenants

-- Read access for the single permission evaluator (auth.member_has_permission).
CREATE POLICY role_assignments_definer_read ON role_assignments FOR SELECT TO ios_definer USING (true);
CREATE POLICY role_permissions_definer_read ON role_permissions FOR SELECT TO ios_definer USING (true);
CREATE POLICY team_members_definer_read ON team_members FOR SELECT TO ios_definer USING (true);
CREATE POLICY securable_grants_definer_read ON securable_grants FOR SELECT TO ios_definer USING (true);
CREATE POLICY roles_definer_read ON roles FOR SELECT TO ios_definer USING (true);
GRANT SELECT ON role_assignments, role_permissions, team_members, securable_grants, roles TO ios_definer;

-- ---------------------------------------------------------------------------
-- Single source of truth for tenant-wide effective permissions (direct + team, scope 'tenant').
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth.member_has_permission(p_tenant uuid, p_membership uuid, p_permission text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT EXISTS (
    SELECT 1
    FROM public.role_assignments ra
    JOIN public.role_permissions rp ON rp.tenant_id = ra.tenant_id AND rp.role_id = ra.role_id
    WHERE ra.tenant_id = p_tenant
      AND ra.scope_type = 'tenant'
      AND rp.permission = p_permission
      AND (ra.membership_id = p_membership
           OR ra.team_id IN (SELECT tm.team_id FROM public.team_members tm
                             WHERE tm.tenant_id = p_tenant AND tm.membership_id = p_membership))
  )
$$;

-- app.has_permission: same signature as before, now evaluated by the single definer-owned evaluator for the
-- DB-established context. Request roles cannot ask about arbitrary (tenant, membership) pairs.
CREATE OR REPLACE FUNCTION app.has_permission(p_permission text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT EXISTS (
           SELECT 1 FROM public.tenant_memberships m
           WHERE m.tenant_id = app.current_tenant() AND m.id = app.current_membership()
             AND m.user_id = app.current_user_id() AND m.status = 'active')
     AND auth.member_has_permission(app.current_tenant(), app.current_membership(), p_permission)
$$;

-- ---------------------------------------------------------------------------
-- Epoch bumps
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth._bump(p_tenant uuid, p_memberships uuid[]) RETURNS void
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  UPDATE public.tenant_memberships SET authz_epoch = authz_epoch + 1
  WHERE tenant_id = p_tenant AND id = ANY (p_memberships)
$$;

CREATE FUNCTION auth._team_members(p_tenant uuid, p_team uuid) RETURNS uuid[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT coalesce(array_agg(membership_id), '{}') FROM public.team_members WHERE tenant_id = p_tenant AND team_id = p_team
$$;

CREATE FUNCTION auth.trg_bump_epoch() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_j jsonb;
  v_tenant uuid;
  v_targets uuid[];
BEGIN
  FOR v_j IN
    SELECT x.j FROM (VALUES (CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END),
                            (CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END)) AS x(j)
    WHERE x.j IS NOT NULL
  LOOP
    v_tenant := (v_j ->> 'tenant_id')::uuid;
    IF TG_TABLE_NAME IN ('role_assignments', 'securable_grants') THEN
      IF v_j ->> 'membership_id' IS NOT NULL THEN
        v_targets := ARRAY[(v_j ->> 'membership_id')::uuid];
      ELSE
        v_targets := auth._team_members(v_tenant, (v_j ->> 'team_id')::uuid);
      END IF;
    ELSIF TG_TABLE_NAME = 'team_members' THEN
      v_targets := ARRAY[(v_j ->> 'membership_id')::uuid];
    ELSE -- role_permissions: everyone holding the role, directly or via a team
      SELECT coalesce(array_agg(DISTINCT x.mid), '{}') INTO v_targets FROM (
        SELECT ra.membership_id AS mid FROM public.role_assignments ra
        WHERE ra.tenant_id = v_tenant AND ra.role_id = (v_j ->> 'role_id')::uuid AND ra.membership_id IS NOT NULL
        UNION
        SELECT tm.membership_id FROM public.role_assignments ra
        JOIN public.team_members tm ON tm.tenant_id = ra.tenant_id AND tm.team_id = ra.team_id
        WHERE ra.tenant_id = v_tenant AND ra.role_id = (v_j ->> 'role_id')::uuid) x;
    END IF;
    PERFORM auth._bump(v_tenant, v_targets);
  END LOOP;
  RETURN NULL;
END
$$;

CREATE TRIGGER role_assignments_bump AFTER INSERT OR UPDATE OR DELETE ON role_assignments FOR EACH ROW EXECUTE FUNCTION auth.trg_bump_epoch();
CREATE TRIGGER team_members_bump AFTER INSERT OR UPDATE OR DELETE ON team_members FOR EACH ROW EXECUTE FUNCTION auth.trg_bump_epoch();
CREATE TRIGGER role_permissions_bump AFTER INSERT OR UPDATE OR DELETE ON role_permissions FOR EACH ROW EXECUTE FUNCTION auth.trg_bump_epoch();
CREATE TRIGGER securable_grants_bump AFTER INSERT OR UPDATE OR DELETE ON securable_grants FOR EACH ROW EXECUTE FUNCTION auth.trg_bump_epoch();

-- Disabling a user bumps all their memberships (all tenants) so in-flight writes are serialised too.
CREATE FUNCTION auth.trg_user_disabled() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  IF NEW.status <> OLD.status THEN
    UPDATE public.tenant_memberships SET authz_epoch = authz_epoch + 1 WHERE user_id = NEW.id;
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER users_status_bump AFTER UPDATE OF status ON users FOR EACH ROW EXECUTE FUNCTION auth.trg_user_disabled();

-- ---------------------------------------------------------------------------
-- Background jobs (primitive only; no job framework in M1)
-- ---------------------------------------------------------------------------
CREATE TABLE jobs (
  tenant_id     uuid NOT NULL REFERENCES tenants (id),
  id            uuid NOT NULL,
  kind          text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{1,62}$'),
  permission    text NOT NULL REFERENCES meta.permissions (key),
  payload       jsonb NOT NULL DEFAULT '{}'::jsonb,
  enqueued_by   uuid NOT NULL,
  status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'refused', 'failed')),
  refusal       text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, enqueued_by) REFERENCES tenant_memberships (tenant_id, id)
);
CREATE INDEX jobs_queued_idx ON jobs (created_at) WHERE status = 'queued';
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY jobs_tenant_isolation ON jobs AS RESTRICTIVE FOR ALL TO ios_app, ios_worker
  USING (tenant_id = (SELECT app.current_tenant())) WITH CHECK (tenant_id = (SELECT app.current_tenant()));
-- Users enqueue as THEMSELVES (actor taken from the DB context, not from the request) and see their own jobs.
CREATE POLICY jobs_enqueue ON jobs FOR INSERT TO ios_app
  WITH CHECK (enqueued_by = (SELECT app.current_membership()) AND status = 'queued' AND (SELECT app.membership_active()));
CREATE POLICY jobs_read_own ON jobs FOR SELECT TO ios_app USING (enqueued_by = (SELECT app.current_membership()));
CREATE POLICY jobs_definer ON jobs FOR ALL TO ios_definer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON jobs TO ios_app;
GRANT SELECT, UPDATE (status, refusal, finished_at) ON jobs TO ios_definer;

-- auth.begin_job: worker-only. Claims a queued job and re-validates the ENQUEUER now (membership active,
-- tenant active, permission still held). On success the context is the enqueuer (principal 'staff').
-- On failure the job is marked refused (same transaction; the worker commits) and NO context is set.
CREATE FUNCTION auth.begin_job(p_job_id uuid) RETURNS TABLE (outcome text, tenant_id uuid, membership_id uuid, kind text, payload jsonb)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_job public.jobs%ROWTYPE;
  v_user uuid;
  v_reason text;
BEGIN
  IF session_user <> 'ios_worker' THEN
    RAISE EXCEPTION 'jobs are executed by ios_worker only' USING ERRCODE = '42501';
  END IF;
  PERFORM auth._ctx_table();
  SELECT * INTO v_job FROM public.jobs j WHERE j.id = p_job_id AND j.status = 'queued' FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unavailable'::text, NULL::uuid, NULL::uuid, NULL::text, NULL::jsonb;
    RETURN;
  END IF;
  -- Lock the enqueuer's membership exactly like a 'write' request (serialises with revocations).
  SELECT m.user_id INTO v_user FROM public.tenant_memberships m
  JOIN public.tenants t ON t.id = m.tenant_id AND t.status = 'active'
  JOIN public.users u ON u.id = m.user_id AND u.status = 'active'
  WHERE m.tenant_id = v_job.tenant_id AND m.id = v_job.enqueued_by AND m.status = 'active'
  FOR SHARE OF m;
  IF v_user IS NULL THEN
    v_reason := 'enqueuer_inactive';
  ELSIF NOT auth.member_has_permission(v_job.tenant_id, v_job.enqueued_by, v_job.permission) THEN
    v_reason := 'permission_revoked';
  END IF;
  IF v_reason IS NOT NULL THEN
    UPDATE public.jobs SET status = 'refused', refusal = v_reason, finished_at = now()
    WHERE jobs.tenant_id = v_job.tenant_id AND jobs.id = v_job.id;
    RETURN QUERY SELECT 'refused:' || v_reason, v_job.tenant_id, v_job.enqueued_by, v_job.kind, NULL::jsonb;
    RETURN;
  END IF;
  UPDATE public.jobs SET status = 'running' WHERE jobs.tenant_id = v_job.tenant_id AND jobs.id = v_job.id;
  INSERT INTO pg_temp.ios_tx_context (principal_type, user_id, tenant_id, membership_id, job_name)
  VALUES ('staff', v_user, v_job.tenant_id, v_job.enqueued_by, v_job.kind);
  RETURN QUERY SELECT 'ok'::text, v_job.tenant_id, v_job.enqueued_by, v_job.kind, v_job.payload;
END
$$;

CREATE FUNCTION auth.complete_job(p_job_id uuid, p_ok boolean) RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_tenant uuid;
BEGIN
  IF session_user <> 'ios_worker' THEN
    RAISE EXCEPTION 'jobs are executed by ios_worker only' USING ERRCODE = '42501';
  END IF;
  SELECT c.tenant_id INTO v_tenant FROM pg_temp.ios_tx_context c;
  UPDATE public.jobs SET status = CASE WHEN p_ok THEN 'done' ELSE 'failed' END, finished_at = now()
  WHERE tenant_id = v_tenant AND id = p_job_id AND status = 'running';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job is not running in this context' USING ERRCODE = '55000';
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- auth.begin v2: + locking modes, + tenant switch with token rotation
-- ---------------------------------------------------------------------------
-- auth.begin is owned by ios_definer: replacing it requires the migrator's own membership in that role.
RESET ROLE;
CREATE OR REPLACE FUNCTION auth.begin(p_token text, p_tenant_slug text, p_mode text)
  RETURNS TABLE (session_id uuid, user_id uuid, tenant_id uuid, tenant_slug text, membership_id uuid, active_tenant_slug text)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_pol   meta.auth_policy%ROWTYPE;
  v_sess  record;
  v_mem   record;
BEGIN
  PERFORM auth._ctx_table();
  IF p_mode IS NULL OR p_mode NOT IN ('read', 'write', 'iam') THEN
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
  IF v_sess.last_seen_at < now() - make_interval(secs => v_pol.last_seen_granularity_s) THEN
    UPDATE public.sessions SET last_seen_at = now() WHERE id = v_sess.id;
  END IF;

  IF p_tenant_slug IS NULL THEN
    IF p_mode <> 'read' THEN
      RAISE EXCEPTION 'user-level context is read-only' USING ERRCODE = '22023';
    END IF;
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

  IF p_mode IN ('write', 'iam') THEN
    IF p_mode = 'iam' THEN
      -- Lock order for IAM: advisory (tenant) -> tenant row -> membership row. Prevents deadlocks between IAM transactions.
      PERFORM pg_advisory_xact_lock(hashtextextended('ios.iam:' || v_mem.tid::text, 0));
    END IF;
    -- Re-check under lock: a revocation that committed while we waited is seen here (READ COMMITTED re-evaluation).
    PERFORM 1 FROM public.tenants t WHERE t.id = v_mem.tid AND t.status = 'active' FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant not accessible' USING ERRCODE = 'IOS04';
    END IF;
    PERFORM 1 FROM public.tenant_memberships m WHERE m.tenant_id = v_mem.tid AND m.id = v_mem.mid AND m.status = 'active' FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant not accessible' USING ERRCODE = 'IOS04';
    END IF;
  END IF;

  INSERT INTO pg_temp.ios_tx_context (principal_type, session_id, user_id, tenant_id, membership_id)
  VALUES ('staff', v_sess.id, v_sess.user_id, v_mem.tid, v_mem.mid);
  RETURN QUERY SELECT v_sess.id, v_sess.user_id, v_mem.tid, v_mem.slug, v_mem.mid,
    (SELECT t.slug FROM public.tenants t WHERE t.id = v_sess.active_tenant_id);
END
$$;

-- Tenant switch = token rotation. Call inside a user-level context (auth.begin with NULL tenant).
-- Revokes the current session and creates a new one (same user, same absolute expiry) for the target tenant.
CREATE FUNCTION auth.switch_tenant(p_new_token text, p_tenant_slug text) RETURNS TABLE (session_id uuid, expires_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_ctx record;
  v_old record;
  v_mem record;
  v_id uuid := gen_random_uuid();
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NOT NULL THEN
    SELECT * INTO v_ctx FROM pg_temp.ios_tx_context;
  END IF;
  IF v_ctx.session_id IS NULL OR v_ctx.principal_type <> 'user' THEN
    RAISE EXCEPTION 'tenant switch requires a user-level context' USING ERRCODE = 'IOS01';
  END IF;
  IF p_new_token IS NULL OR length(p_new_token) NOT BETWEEN 32 AND 128 THEN
    RAISE EXCEPTION 'invalid token' USING ERRCODE = '22023';
  END IF;
  SELECT t.id AS tid, m.id AS mid INTO v_mem
  FROM public.tenants t JOIN public.tenant_memberships m ON m.tenant_id = t.id
  WHERE t.slug = p_tenant_slug AND t.status = 'active' AND m.user_id = v_ctx.user_id AND m.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant not accessible' USING ERRCODE = 'IOS04';
  END IF;
  UPDATE public.sessions s SET revoked_at = now() WHERE s.id = v_ctx.session_id AND s.revoked_at IS NULL
  RETURNING s.expires_at INTO v_old;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no valid session' USING ERRCODE = 'IOS01';
  END IF;
  INSERT INTO public.sessions (id, token_hash, user_id, active_tenant_id, active_membership_id, expires_at)
  VALUES (v_id, sha256(convert_to(p_new_token, 'UTF8')), v_ctx.user_id, v_mem.tid, v_mem.mid, v_old.expires_at);
  RETURN QUERY SELECT v_id, v_old.expires_at;
END
$$;

ALTER FUNCTION auth.member_has_permission(uuid, uuid, text) OWNER TO ios_definer;
ALTER FUNCTION app.has_permission(text) OWNER TO ios_definer;
ALTER FUNCTION auth._bump(uuid, uuid[]) OWNER TO ios_definer;
ALTER FUNCTION auth._team_members(uuid, uuid) OWNER TO ios_definer;
ALTER FUNCTION auth.trg_bump_epoch() OWNER TO ios_definer;
ALTER FUNCTION auth.trg_user_disabled() OWNER TO ios_definer;
ALTER FUNCTION auth.begin_job(uuid) OWNER TO ios_definer;
ALTER FUNCTION auth.complete_job(uuid, boolean) OWNER TO ios_definer;
ALTER FUNCTION auth.switch_tenant(text, text) OWNER TO ios_definer;
REVOKE ALL ON FUNCTION auth.member_has_permission(uuid, uuid, text), auth._bump(uuid, uuid[]), auth._team_members(uuid, uuid),
  auth.trg_bump_epoch(), auth.trg_user_disabled(), auth.begin_job(uuid), auth.complete_job(uuid, boolean),
  auth.switch_tenant(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.has_permission(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.has_permission(text) TO ios_app, ios_worker;
GRANT EXECUTE ON FUNCTION auth.begin_job(uuid), auth.complete_job(uuid, boolean) TO ios_worker;
GRANT EXECUTE ON FUNCTION auth.switch_tenant(text, text) TO ios_app;
SET ROLE ios_owner;
