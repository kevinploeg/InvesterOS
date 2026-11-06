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

## 2. Request context (DB-verified since M1-WP1)

Every transaction starts with `SELECT * FROM auth.begin(<raw session token>, <tenant slug | NULL>, 'read'|'write')`. This is done by `withTenantTx` / `withUserTx`.

What `auth.begin` (SECURITY DEFINER, owned by `ios_definer`) does:
1. Hashes the token.
2. Checks the session (not revoked, not expired, idle window), the user (active), the tenant (active) and the membership (active, staff).
3. Writes the resulting context into **`pg_temp.ios_tx_context`**:
   - a temp table private to the connection;
   - owned by `ios_definer`;
   - `ON COMMIT DELETE ROWS`;
   - at most one row per transaction.

The policy functions (`app.current_tenant()`, `current_user_id()`, `current_membership()`, `principal_type()`) read **only** that table. GUCs and `set_config` play no part any more (schema-lint R9).

| Property | Mechanism | Test |
|---|---|---|
| Context cannot be spoofed via SQL | Readers ignore GUCs; request roles have no TEMPORARY privilege, so they cannot create, shadow, read or write the store | `context-safety.test.ts` |
| No stale context | `ON COMMIT DELETE ROWS` + rollback semantics; autocommit = one statement | idem |
| Connection reuse (pool, PgBouncer transaction/session mode) | The store is per connection and empty outside a transaction; `DISCARD ALL` simply recreates it | idem (pool of 1, 200 interleaved transactions over 8 connections) |
| No identity switch within a transaction | Primary key on a singleton column → second `auth.begin` = `IOS09` | idem |
| Savepoint rollback | Context established inside it disappears (fail closed) | idem |
| Sessions can't be minted through `ios_app` | Only `ios_auth` can call `auth.create_session`; `ios_app` has no privileges on `sessions` | `auth.test.ts` |

Not supported: PgBouncer **statement** mode (a transaction spans several statements) and two-phase commit. The latter is refused by Postgres.

Errors: `IOS01` → HTTP 401 (no valid session), `IOS04` → HTTP 404 (tenant/membership not accessible, no disclosure).

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

## 5. Pre-context paths

- `auth.create_session(issuer, subject, token, previous_token)`: only for the `ios_auth` login (OIDC callback, **after** the app validated the ID token).
- `auth.begin` / `auth.revoke_current_session`: `ios_app` and `ios_worker`.
- `auth.begin_system`: only when `session_user = 'ios_worker'`.

All are SECURITY DEFINER with a pinned `search_path`, owned by `ios_definer`, which has NO BYPASSRLS. Its reach is limited to explicit policies on `users`, `user_identities`, `sessions`, `tenants` and `tenant_memberships` (schema-lint R10).

## 6. Known limitations and how they are handled

1. **Context spoofing through SQL: fixed in M1-WP1** (§2). Remaining: anyone who can execute SQL as `ios_app` **and** holds a valid session token acts with that token's rights, i.e. their own. A compromised application server sees every token in transit; no DB mechanism can prevent that.
2. **Referential integrity checks bypass RLS** (Postgres behaviour). Every cross-tenant FK is composite, so a reference can never point outside the tenant. Within a tenant, the existence-oracle test above covers it.
3. **Background jobs** use `ios_worker` and the same policies. A job acting on behalf of a user is re-authorized when it runs. A `system` job has `principal_type = 'system'` and only reaches what system policies explicitly allow. In M0 that is only writing system audit events.
4. **AI retrieval (future).** Embedding tables carry `tenant_id` and `securable_id` and the same policies. Retrieval runs in the user's context, never as a system principal.
5. **Object storage (M3+).** Object storage sits outside the database, so RLS doesn't apply there. The control:
   - a metadata row with `securable_id` under RLS is the gate;
   - a presigned URL is issued only after that row is visible;
   - the TTL is at most 5 minutes;
   - keys are `t/{tenant_id}/{uuid}` and never supplied by the client;
   - the bucket is private and encrypted with SSE-KMS.
