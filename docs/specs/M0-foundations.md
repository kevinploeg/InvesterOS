# M0: Foundations, tenant isolation, authentication skeleton, authorization kernel

Approved scope: M0 only. M1 starts only after the owner has reviewed the M0 test report.

## In scope
Monorepo, CI, database roles and RLS, kernel (db context, authz, auth, audit), synthetic seed, a minimal web shell (login, tenant workspace, logout), a mock OIDC provider for dev and test, documentation.

## Out of scope
The real IdP (Zitadel, M1), invitations and admin UI (M1), domain tables (M3+), any deployment, any real data.

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| AC1 | pnpm monorepo; module boundaries enforced (dependency-cruiser + ESLint) | `pnpm lint`; deliberate violation detected (see test report) |
| AC2 | CI: lint, typecheck, unit + integration on real Postgres, schema lint, build, E2E, dependency audit, secret scan | `.github/workflows/ci.yml` |
| AC3 | Roles per rls-design §1; `ios_app`/`ios_worker`/`ios_definer` without SUPERUSER/BYPASSRLS, owning nothing | `schema.test.ts`, lint R5/R6 |
| AC4 | Kernel tables: tenants, users, user_identities, tenant_memberships, teams, team_members, roles, role_permissions, role_assignments, securables, securable_grants, sessions, audit_events, meta.permissions, meta.synthetic_marker | migrations 0001–0003 |
| AC5 | Schema lint fails on a missing RLS/FORCE/restrictive policy/composite FK/unlisted global table/privileged role/definer without search_path/PUBLIC execute | `schema.test.ts` (positive + negative) |
| AC6 | Generated isolation suite per tenant table (SELECT/UPDATE/DELETE/INSERT/move, no context, malformed context, composite FKs, pool hygiene) | `isolation.test.ts` |
| AC6b | Information barrier for restricted securables in the database (A7) | `restricted.test.ts` |
| AC7 | Audit append-only (app and owner), atomic with the change, not forgeable | `db-audit.test.ts` |
| AC8 | OIDC Authorization Code + PKCE (S256), state, nonce; replay and tampering refused | `auth.test.ts`, E2E |
| AC9 | Binding on (issuer, subject); no e-mail matching | `auth.test.ts` |
| AC10 | Server-side sessions: hashed token, rotation, idle + absolute expiry, revocation, disabled user | `auth.test.ts`, E2E |
| AC11 | Unauthenticated: pages → /login, API → 401 | E2E |
| AC12 | Permission registry = DB catalog | `authz.test.ts` |
| AC13 | `authorize()`: tenant, scoped, team-inherited, restricted (read/write/oversight) | `authz.test.ts` |
| AC14 | Matrix of all system roles × all permissions; SQL `has_permission` = TS | `authz.test.ts` |
| AC15 | Foreign or unknown tenant slug → 404, indistinguishable | `auth.test.ts`, E2E |
| AC16 | Synthetic seed (3 tenants, 30 users, 1 multi-tenant user); the app refuses an unmarked database | `packages/testing`, `db-audit.test.ts` |
| AC17 | 100% statement/branch/function/line coverage on the kernel | vitest thresholds |
| AC18 | Test report + ADRs delivered to the owner; **no M1 work before approval** | `docs/reports/M0-test-report.md` |
