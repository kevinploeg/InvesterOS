# Database authorization design: tenant isolation and information barriers

Status: **implemented in M0**. It is tested by `packages/kernel/test/{isolation,restricted,authz}.test.ts` and `packages/db/test/schema.test.ts`.

## 1. Roles

| Role | Login | BYPASSRLS | Purpose |
|---|---|---|---|
| `ios_owner` | no | no | Owns all objects, and is itself subject to `FORCE RLS` |
| `ios_migrator` | yes (CI/CD only) | no | Migrations; member of `ios_owner` and `ios_definer` |
| `ios_app` | yes | **no** | Every user request: DML on granted tables only |
| `ios_worker` | yes | **no** | Background jobs, under the same policies |
| `ios_definer` | no | **no** | Owns 2 SECURITY DEFINER functions (identity and session lookup). It reaches rows only through explicit `*_definer_*` policies on exactly those tables |

**No role in this system has BYPASSRLS or SUPERUSER.** That also works on AWS RDS, where creating BYPASSRLS roles is restricted. Schema-lint rule R5 enforces it.

## 2. Request context

`withTenantTx(pool, ctx, fn)` opens a transaction and sets `app.tenant_id`, `app.user_id`, `app.membership_id` and `app.principal_type` with `set_config(..., true)`, which makes them transaction-local. There is no other route to tenant data. `pg` is banned outside `kernel/db` by both ESLint and dependency-cruiser.

- No context: `app.current_tenant()` returns NULL and every policy evaluates false, so zero rows are returned (tested on every table).
- A malformed value raises a cast error (fail closed, tested).
- After COMMIT or ROLLBACK the connection has no context left (tested with pool size 1).

## 3. Policy pattern

```
<table>_tenant_isolation   AS RESTRICTIVE FOR ALL TO ios_app, ios_worker
                           USING (tenant_id = app.current_tenant()) WITH CHECK (same)
<table>_read / _write      PERMISSIVE, per command, can only narrow further
```

Restrictive policies are ANDed with every permissive one. No future policy, including the investor portal's, can therefore cross the tenant boundary. Schema-lint rule R3 requires this restrictive policy, by name, for both request roles, on every table that has `tenant_id`.

Writes to identity and access tables also require a permission, checked in SQL by `app.has_permission(...)`. System roles cannot be modified through the app at all.

## 4. Information barriers: restricted projects and other sensitive resources (A7)

### Model

- **`securables`**: every protectable object (project, fund, opportunity, offering) has exactly one securable row, with `classification ∈ {standard, restricted}`.
- **`securable_grants`**: `read` or `write` access for one membership **or one team**, optionally with `expires_at`, recording who granted it.
- **Children** (tasks, interactions, documents, subscriptions, ledger lines, audit events and future AI embeddings) carry `securable_id` and a composite FK to it.

### Enforcement in the database

| Object | SELECT | INSERT / UPDATE / DELETE |
|---|---|---|
| `securables` | `standard` **OR** live grant (direct or team) **OR** `restricted.oversight` | requires `securables.manage`; changing or deleting a restricted securable also requires a **write grant** |
| child tables | `app.securable_visible(tenant_id, securable_id)`, which reads `securables` **under its own RLS** | `app.securable_writable(...)`: standard, or restricted with a write grant |
| `audit_events` | `audit.read` **AND** the securable is visible | append-only |
| `securable_grants` | own grants, team grants, or `access.manage` | `access.manage`, and `granted_by` must equal the acting membership |

Consequences, each covered by a test:

- **Owners and admins do not see restricted resources without a grant.** Tenant-wide roles are not enough.
- A **read grant** gives read access only. Writes are refused or affect 0 rows.
- An **expired grant** or a **suspended membership** removes access immediately.
- **Compliance oversight** is read-only and covers all restricted resources. In the application layer it is flagged (`oversight: true`) for mandatory auditing.
- **Reclassifying** a resource as restricted hides all its children at once. Nothing is denormalised, so nothing has to be recomputed.
- **Aggregates** (`count(*)`) count only visible rows.
- **No existence oracle:** inserting a child that points at an invisible restricted securable gives the same SQLSTATE (42501) as pointing at a non-existent one.
- **Audit records** about a restricted resource are invisible to auditors without access, except compliance.

### Application layer (defence in depth, not a replacement)

`authorize(access, permission, resource)` applies the same rules, plus scoped roles (a role on a single securable). A test checks for every user type that `authorize()` never allows something the database refuses.

### Performance

Policies call helper functions as a scalar sub-select, e.g. `(SELECT app.granted_securables('read'))`. Postgres then evaluates them **once per statement** (InitPlan) instead of once per row. Child tables do one indexed EXISTS on `securables(tenant_id, id)` per row. We will measure this in M3 at realistic volumes, for example 10k projects and 1M child rows.

### Known gap (deliberate, closed in M2)

A holder of `access.manage` (owner or admin) can grant **themselves** access. This is attributable (`granted_by` is enforced) and tested. From M2, a grant on a restricted securable requires a four-eyes approval request, and self-grants are refused.

## 5. Pre-login paths

`auth.resolve_identity(issuer, subject)` and `auth.lookup_session(token_hash, idle_seconds)` are SECURITY DEFINER functions owned by `ios_definer`:

- with a pinned `search_path`;
- executable only by `ios_app` (rule R8: no PUBLIC EXECUTE);
- `ios_definer` itself has no BYPASSRLS and sees only `users`, `user_identities` and `sessions` through dedicated policies.

## 6. Known limitations and how they are handled

1. **Context spoofing through SQL.** `set_config` can be called by anyone who can execute arbitrary SQL as `ios_app`. RLS protects against **bugs in queries** (a forgotten `WHERE`, a wrong join). It does not protect against **SQL injection with arbitrary statements**. Mitigations: parameterised queries only (no string concatenation, a lint rule from M1), no raw `pg` outside the kernel, and least privilege (the app has no DDL and owns nothing). A signed context, verified by a definer function, is a possible extra layer. It isn't proposed yet because the cost and complexity are high for marginal gain.
2. **Referential integrity checks bypass RLS** (Postgres behaviour). Every cross-tenant FK is composite, so a reference can never point outside the tenant. Within a tenant, the existence-oracle test above covers it.
3. **Background jobs** use `ios_worker` and the same policies. A job acting on behalf of a user is re-authorized when it runs. A `system` job has `principal_type = 'system'` and only reaches what system policies explicitly allow. In M0 that is only writing system audit events.
4. **AI retrieval (future).** Embedding tables carry `tenant_id` and `securable_id` and the same policies. Retrieval runs in the user's context, never as a system principal.
5. **Object storage (M3+).** Object storage sits outside the database, so RLS doesn't apply there. The control:
   - a metadata row with `securable_id` under RLS is the gate;
   - a presigned URL is issued only after that row is visible;
   - the TTL is at most 5 minutes;
   - keys are `t/{tenant_id}/{uuid}` and never supplied by the client;
   - the bucket is private and encrypted with SSE-KMS.
