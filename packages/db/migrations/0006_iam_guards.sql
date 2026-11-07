-- 0006 (M1-WP3): IAM invariants enforced in the database.
--
-- Every IAM mutation made under a staff request context must:
--   (a) run in 'iam' mode (per-tenant advisory lock => IAM changes are serialised; no write skew);
--   (b) not touch the actor's own rights (no self-assignment, no self team-join, no editing a role you hold,
--       no self-grant, no self-suspension);
--   (c) satisfy the SUBSET RULE: the actor holds every permission that is handed out OR taken away,
--       at the same scope (so an admin cannot create, grant, or strip owner-level rights);
--   (d) leave at least one active owner in the tenant.
-- System jobs may not mutate IAM at all. Contexts without a principal (migrations, fixtures run by the
-- superuser) are not request paths: request roles cannot write anything without a context (RLS).

-- ---------------------------------------------------------------------------
-- Context table gains the transaction mode, so triggers can verify (a) without trusting the app.
-- ---------------------------------------------------------------------------
RESET ROLE;
CREATE OR REPLACE FUNCTION auth._ctx_table() RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_owner oid;
BEGIN
  -- A connection may still hold a context table created by an older definition: recreate it.
  IF to_regclass('pg_temp.ios_tx_context') IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pg_temp.ios_tx_context') AND attname = 'mode' AND NOT attisdropped) THEN
    DROP TABLE pg_temp.ios_tx_context;
  END IF;
  IF to_regclass('pg_temp.ios_tx_context') IS NULL THEN
    CREATE TEMP TABLE ios_tx_context (
      singleton      boolean PRIMARY KEY DEFAULT true CHECK (singleton),
      principal_type text NOT NULL CHECK (principal_type IN ('user', 'staff', 'system')),
      mode           text CHECK (mode IN ('read', 'write', 'iam')),
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
    INSERT INTO pg_temp.ios_tx_context (principal_type, session_id, user_id, mode) VALUES ('user', v_sess.id, v_sess.user_id, p_mode);
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

  INSERT INTO pg_temp.ios_tx_context (principal_type, session_id, user_id, tenant_id, membership_id, mode)
  VALUES ('staff', v_sess.id, v_sess.user_id, v_mem.tid, v_mem.mid, p_mode);
  RETURN QUERY SELECT v_sess.id, v_sess.user_id, v_mem.tid, v_mem.slug, v_mem.mid,
    (SELECT t.slug FROM public.tenants t WHERE t.id = v_sess.active_tenant_id);
END
$$;


-- ---------------------------------------------------------------------------
-- Permission helpers (definer; single implementation)
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth.member_has_scoped_permission(p_tenant uuid, p_membership uuid, p_securable uuid, p_permission text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT EXISTS (
    SELECT 1
    FROM public.role_assignments ra
    JOIN public.role_permissions rp ON rp.tenant_id = ra.tenant_id AND rp.role_id = ra.role_id
    WHERE ra.tenant_id = p_tenant AND ra.scope_type = 'securable' AND ra.scope_id = p_securable
      AND rp.permission = p_permission
      AND (ra.membership_id = p_membership
           OR ra.team_id IN (SELECT tm.team_id FROM public.team_members tm WHERE tm.tenant_id = p_tenant AND tm.membership_id = p_membership))
  )
$$;

-- Permissions of a role the actor does NOT hold at the given scope (empty = subset rule satisfied).
CREATE FUNCTION auth._missing_for_role(p_tenant uuid, p_actor uuid, p_role uuid, p_scope uuid) RETURNS text[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT coalesce(array_agg(rp.permission ORDER BY rp.permission), '{}')
  FROM public.role_permissions rp
  WHERE rp.tenant_id = p_tenant AND rp.role_id = p_role
    AND NOT auth.member_has_permission(p_tenant, p_actor, rp.permission)
    AND NOT (p_scope IS NOT NULL AND auth.member_has_scoped_permission(p_tenant, p_actor, p_scope, rp.permission))
$$;

-- Tenant-wide effective permissions of a membership.
CREATE FUNCTION auth._effective_permissions(p_tenant uuid, p_membership uuid) RETURNS text[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT coalesce(array_agg(DISTINCT rp.permission), '{}')
  FROM public.role_assignments ra
  JOIN public.role_permissions rp ON rp.tenant_id = ra.tenant_id AND rp.role_id = ra.role_id
  WHERE ra.tenant_id = p_tenant AND ra.scope_type = 'tenant'
    AND (ra.membership_id = p_membership
         OR ra.team_id IN (SELECT tm.team_id FROM public.team_members tm WHERE tm.tenant_id = p_tenant AND tm.membership_id = p_membership))
$$;

CREATE FUNCTION auth._actor_teams(p_tenant uuid, p_actor uuid) RETURNS uuid[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS
$$
  SELECT coalesce(array_agg(team_id), '{}') FROM public.team_members WHERE tenant_id = p_tenant AND membership_id = p_actor
$$;

CREATE FUNCTION auth._deny(p_reason text, p_detail text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
BEGIN
  RAISE EXCEPTION 'IAM change refused: %', p_reason USING ERRCODE = 'IOS03', DETAIL = coalesce(p_detail, '');
END
$$;

-- ---------------------------------------------------------------------------
-- Row-level guard
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth.trg_iam_guard() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_principal text;
  v_mode   text;
  v_tenant uuid;
  v_actor  uuid;
  v_rows  jsonb[];
  v_j     jsonb;
  v_teams uuid[];
  v_missing text[];
  v_role  uuid;
  v_scope uuid;
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NOT NULL THEN
    SELECT c.principal_type, c.mode, c.tenant_id, c.membership_id INTO v_principal, v_mode, v_tenant, v_actor
    FROM pg_temp.ios_tx_context c;
  END IF;
  IF v_principal IS NULL THEN
    RETURN NULL; -- not a request path (superuser maintenance / fixtures)
  END IF;
  IF v_principal <> 'staff' OR v_actor IS NULL THEN
    PERFORM auth._deny('only staff requests may change IAM', NULL);
  END IF;
  -- Ignore pure epoch bumps on tenant_memberships (performed by auth._bump).
  IF TG_TABLE_NAME = 'tenant_memberships' AND TG_OP = 'UPDATE'
     AND (to_jsonb(NEW) - 'authz_epoch') = (to_jsonb(OLD) - 'authz_epoch') THEN
    RETURN NULL;
  END IF;
  IF v_mode IS DISTINCT FROM 'iam' THEN
    PERFORM auth._deny('iam mode required', TG_TABLE_NAME);
  END IF;

  v_teams := auth._actor_teams(v_tenant, v_actor);
  v_rows := ARRAY[]::jsonb[];
  IF TG_OP <> 'DELETE' THEN v_rows := v_rows || to_jsonb(NEW); END IF;
  IF TG_OP <> 'INSERT' THEN v_rows := v_rows || to_jsonb(OLD); END IF;

  FOREACH v_j IN ARRAY v_rows LOOP
    IF TG_TABLE_NAME IN ('role_assignments', 'securable_grants', 'team_members') THEN
      IF (v_j ->> 'membership_id')::uuid = v_actor
         OR (v_j ->> 'team_id')::uuid = ANY (v_teams) THEN
        PERFORM auth._deny('self_mutation', TG_TABLE_NAME);
      END IF;
    END IF;

    IF TG_TABLE_NAME = 'role_assignments' THEN
      v_missing := auth._missing_for_role(v_tenant, v_actor, (v_j ->> 'role_id')::uuid, (v_j ->> 'scope_id')::uuid);
      IF cardinality(v_missing) > 0 THEN
        PERFORM auth._deny('subset_rule', array_to_string(v_missing, ','));
      END IF;

    ELSIF TG_TABLE_NAME = 'team_members' THEN
      FOR v_role, v_scope IN
        SELECT ra.role_id, ra.scope_id FROM public.role_assignments ra
        WHERE ra.tenant_id = v_tenant AND ra.team_id = (v_j ->> 'team_id')::uuid
      LOOP
        v_missing := auth._missing_for_role(v_tenant, v_actor, v_role, v_scope);
        IF cardinality(v_missing) > 0 THEN
          PERFORM auth._deny('subset_rule', array_to_string(v_missing, ','));
        END IF;
      END LOOP;

    ELSIF TG_TABLE_NAME = 'role_permissions' THEN
      IF EXISTS (SELECT 1 FROM public.role_assignments ra
                 WHERE ra.tenant_id = v_tenant AND ra.role_id = (v_j ->> 'role_id')::uuid
                   AND (ra.membership_id = v_actor OR ra.team_id = ANY (v_teams))) THEN
        PERFORM auth._deny('self_mutation', 'role held by actor');
      END IF;
      IF NOT auth.member_has_permission(v_tenant, v_actor, v_j ->> 'permission') THEN
        PERFORM auth._deny('subset_rule', v_j ->> 'permission');
      END IF;

    ELSIF TG_TABLE_NAME = 'tenant_memberships' THEN
      IF (v_j ->> 'id')::uuid = v_actor THEN
        PERFORM auth._deny('self_mutation', 'own membership');
      END IF;
      -- Changing another member's status requires holding everything they hold (no demoting a stronger member).
      SELECT coalesce(array_agg(p ORDER BY p), '{}') INTO v_missing
      FROM unnest(auth._effective_permissions(v_tenant, (v_j ->> 'id')::uuid)) p
      WHERE NOT auth.member_has_permission(v_tenant, v_actor, p);
      IF cardinality(v_missing) > 0 THEN
        PERFORM auth._deny('subset_rule', array_to_string(v_missing, ','));
      END IF;
    END IF;
  END LOOP;
  RETURN NULL;
END
$$;

-- ---------------------------------------------------------------------------
-- Statement-level guard: the tenant keeps at least one active owner.
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth.trg_last_owner() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS
$$
DECLARE
  v_tenant uuid;
BEGIN
  IF to_regclass('pg_temp.ios_tx_context') IS NOT NULL THEN
    SELECT c.tenant_id INTO v_tenant FROM pg_temp.ios_tx_context c WHERE c.principal_type = 'staff';
  END IF;
  IF v_tenant IS NULL THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships m
    JOIN public.users u ON u.id = m.user_id AND u.status = 'active'
    JOIN public.roles r ON r.tenant_id = m.tenant_id AND r.key = 'owner' AND r.is_system
    JOIN public.role_assignments ra ON ra.tenant_id = m.tenant_id AND ra.role_id = r.id AND ra.scope_type = 'tenant'
    WHERE m.tenant_id = v_tenant AND m.status = 'active'
      AND (ra.membership_id = m.id
           OR ra.team_id IN (SELECT tm.team_id FROM public.team_members tm WHERE tm.tenant_id = m.tenant_id AND tm.membership_id = m.id))
  ) THEN
    PERFORM auth._deny('last_owner', 'the tenant must keep at least one active owner');
  END IF;
  RETURN NULL;
END
$$;

SET ROLE ios_owner;
CREATE TRIGGER role_assignments_iam_guard AFTER INSERT OR UPDATE OR DELETE ON role_assignments FOR EACH ROW EXECUTE FUNCTION auth.trg_iam_guard();
CREATE TRIGGER team_members_iam_guard AFTER INSERT OR UPDATE OR DELETE ON team_members FOR EACH ROW EXECUTE FUNCTION auth.trg_iam_guard();
CREATE TRIGGER role_permissions_iam_guard AFTER INSERT OR UPDATE OR DELETE ON role_permissions FOR EACH ROW EXECUTE FUNCTION auth.trg_iam_guard();
CREATE TRIGGER securable_grants_iam_guard AFTER INSERT OR UPDATE OR DELETE ON securable_grants FOR EACH ROW EXECUTE FUNCTION auth.trg_iam_guard();
CREATE TRIGGER tenant_memberships_iam_guard AFTER UPDATE OR DELETE ON tenant_memberships FOR EACH ROW EXECUTE FUNCTION auth.trg_iam_guard();
CREATE TRIGGER role_assignments_last_owner AFTER UPDATE OR DELETE ON role_assignments FOR EACH STATEMENT EXECUTE FUNCTION auth.trg_last_owner();
CREATE TRIGGER team_members_last_owner AFTER DELETE ON team_members FOR EACH STATEMENT EXECUTE FUNCTION auth.trg_last_owner();
CREATE TRIGGER tenant_memberships_last_owner AFTER UPDATE OR DELETE ON tenant_memberships FOR EACH STATEMENT EXECUTE FUNCTION auth.trg_last_owner();

RESET ROLE;
ALTER FUNCTION auth.member_has_scoped_permission(uuid, uuid, uuid, text) OWNER TO ios_definer;
ALTER FUNCTION auth._missing_for_role(uuid, uuid, uuid, uuid) OWNER TO ios_definer;
ALTER FUNCTION auth._effective_permissions(uuid, uuid) OWNER TO ios_definer;
ALTER FUNCTION auth._actor_teams(uuid, uuid) OWNER TO ios_definer;
ALTER FUNCTION auth._deny(text, text) OWNER TO ios_definer;
ALTER FUNCTION auth.trg_iam_guard() OWNER TO ios_definer;
ALTER FUNCTION auth.trg_last_owner() OWNER TO ios_definer;
REVOKE ALL ON FUNCTION auth.member_has_scoped_permission(uuid, uuid, uuid, text), auth._missing_for_role(uuid, uuid, uuid, uuid),
  auth._effective_permissions(uuid, uuid), auth._actor_teams(uuid, uuid), auth._deny(text, text),
  auth.trg_iam_guard(), auth.trg_last_owner() FROM PUBLIC;
SET ROLE ios_owner;
