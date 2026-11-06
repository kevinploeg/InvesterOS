# M0 test report

Date: 2026-11-06 · Branch: `m0-foundations` · Data: **synthetic only** · Deployment: **none**

## Result

| Gate | Result |
|---|---|
| ESLint + dependency-cruiser (module boundaries) | ✅ 0 violations. A deliberate violation (raw `pg` + fixtures import in the web app) is caught by both tools |
| Typecheck (all packages + E2E) | ✅ |
| `pnpm audit --prod --audit-level high` | ✅ no known vulnerabilities |
| Schema lint on a freshly migrated database | ✅ 0 violations |
| Unit + integration (real Postgres) | ✅ 239 tests (db 5, kernel 234) |
| Kernel coverage (statements/branches/functions/lines) | ✅ 100 / 100 / 100 / 100 |
| Production build (Next.js 16.4.5) | ✅ |
| E2E (Playwright, Chromium, production build, mock IdP) | ✅ 11/11 |
| CI on GitHub Actions | ✅ [run 42298715337](https://github.com/kevinploeg/InvesterOS/actions/runs/42298715337): verify (lint, typecheck, audit, 239 tests, 100% kernel coverage, schema lint, build, 11 E2E) + gitleaks, on PostgreSQL 17.11 |

Locally tested on PostgreSQL **16.15**. CI uses **postgres:17**. The code uses no 17-only features.

## Per test file

| File | Tests | Covers |
|---|---|---|
| `packages/db/test/schema.test.ts` | 5 | AC3, AC5: lint positive + negative (missing RLS/FORCE/restrictive policy, non-composite FK, unlisted global table, BYPASSRLS role); migration checksum protection |
| `packages/kernel/test/isolation.test.ts` | 14 | AC6: generated per tenant table: SELECT/UPDATE/DELETE/INSERT/move to another tenant; no context → 0 rows (incl. global tables); malformed context → error; composite FKs refuse cross-tenant references (even as superuser); pool hygiene after COMMIT/ROLLBACK |
| `packages/kernel/test/restricted.test.ts` | 28 | AC6b/A7: read/write barrier, owner/admin without grant see nothing, read vs write grant, team grant, expired grant, suspended membership, compliance oversight read-only, aggregates, no existence oracle, de-classifying refused, forged `granted_by` refused, audit visibility, app-layer vs DB parity |
| `packages/kernel/test/authz.test.ts` | 162 | AC12–14: registry = DB catalog; 6 roles × 24 permissions matrix; scoped, team-inherited and restricted rules; SQL `has_permission` = TS; system roles immutable; no self-assignment; role-matrix document up to date |
| `packages/kernel/test/auth.test.ts` | 19 | AC8–10, AC15: OIDC + PKCE against the mock IdP; state tampering/expiry; code replay; same subject at another issuer → no access; disabled/unknown user; sessions (hash only, rotation, idle, absolute, revocation, disabled user); tenant resolution, switching, suspended tenant/membership |
| `packages/kernel/test/db-audit.test.ts` | 11 | AC7, AC16: audit append-only (app + owner incl. TRUNCATE), atomic with rollback, not forgeable (system actor / other actor), PII redaction; synthetic guard; transaction-helper validation |
| `e2e/auth.spec.ts` | 11 | AC11, AC15, A8, A9: unauthenticated → redirect/401; forged cookie; login via OIDC; cookie flags; foreign tenant = 404 = non-existent; tenant switch; unknown identity refused; logout + cookie replay → 401; CSRF on logout; tampered callback; security headers; NL locale + synthetic banner |

## Findings during M0 (fixed)

1. **`Referrer-Policy: no-referrer` broke the CSRF check.** Under the Fetch spec, browsers then send `Origin: null` on form POSTs, so legitimate logouts were refused. Fixed with `same-origin`: no referrer goes to other sites, and the Origin check works. Found by E2E.
2. **Postgres `ANY ((SELECT fn()))` on arrays** was parsed as a subquery comparison (`uuid = uuid[]`). Fixed with an explicit `::uuid[]` cast. The InitPlan optimisation is preserved.
3. **Ownership transfer to `ios_definer`** failed under `SET ROLE ios_owner`. The migration now transfers ownership as the migrator, without giving the owner role extra memberships.

## Open items and known gaps (deliberate)

| Item | Risk | Planned |
|---|---|---|
| Access managers can grant themselves access to restricted resources (attributable through `granted_by`) | Medium | M2: four-eyes on grants, self-grants refused |
| CSP still allows `'unsafe-inline'` for scripts | Medium | M5: nonce-based CSP |
| GitHub Actions on tags instead of SHAs (could not be verified from this environment) | Medium | M1-AC12 |
| CI warning: actions on Node 20 (deprecated) | Low | M1-AC8.1 |
| No server actions yet, so the server-action guard is untested | Low | M1-AC10, together with the first mutation |
| Typed query builder not chosen yet (ADR-0006) | Low | M1 |
| `redact()` is key-based (also redacts e.g. `team_name`, i.e. conservative) | Low | M1 logging policy |
| SQL injection could spoof context (see rls-design §6) | Low with current controls | parameterisation lint in M1 |
| Zitadel vendor verification (ADR-0004) | Blocks M1 | owner + DPO |

## Reproduce locally

Requires Node 22, pnpm 10 and Postgres 16+ reachable via `DATABASE_ADMIN_URL`. See `README.md`.
