# Threat model (STRIDE): status after M0

| # | Threat | STRIDE | Control | Test / evidence | Status |
|---|---|---|---|---|---|
| T1 | Cross-tenant read/write through a missing filter | I, T | RESTRICTIVE tenant policy + FORCE RLS on every table | `isolation.test.ts` (generated per table: SELECT/UPDATE/DELETE/INSERT/move) | ✅ M0 |
| T2 | Cross-tenant FK reference | T | Composite `(tenant_id, …)` FKs; schema-lint R4 | `isolation.test.ts` composite FKs (via superuser, so independent of RLS) | ✅ M0 |
| T3 | Context leaking on a pooled connection | I | `set_config(..., true)` inside a transaction only | pool-hygiene test (pool size 1, after COMMIT and ROLLBACK) | ✅ M0 |
| T4 | Tenant spoofing via URL | S | Slug is only a selector, matched against an active membership; otherwise 404 | `auth.test.ts`, E2E "foreign tenant = 404 = non-existent" | ✅ M0 |
| T5 | IDOR within a tenant / information barrier | E, I | Securables + grants in RLS, plus `authorize()` | `restricted.test.ts` (28 tests) | ✅ M0 (mechanism); applied to domain tables in M3 |
| T6 | Authorization only in middleware/UI | E | No auth in `proxy.ts`; checks in route handlers, server components and the DB | E2E unauthenticated → 401/redirect; DB tests without the app layer | ✅ M0 |
| T7 | Account takeover through e-mail matching | S | Binding on `(issuer, subject)` only | `auth.test.ts` same subject at another issuer → no user | ✅ M0 |
| T8 | SSO misconfiguration (an org's IdP signs in for another tenant) | S | IdP org → tenant mapping, verified domains | — | ⏳ M1 |
| T9 | Self-escalation (granting yourself a role or access) | E | Write policies need `iam.roles.manage` / `access.manage`; system roles immutable; `granted_by` enforced | `authz.test.ts`, `restricted.test.ts` | ⚠️ partial: access managers can self-grant (audited) → four-eyes in M2 |
| T10 | Session theft or fixation | S | httpOnly, SameSite=Lax, `__Host-` + Secure over https, random 256-bit token, only the hash stored, rotation on login, idle (30 min) and absolute (12 h) expiry, server-side revocation | `auth.test.ts`, E2E cookie flags + replay after logout | ✅ M0 |
| T11 | Insider at InvestorOS (support access) | I | No production data exists (synthetic only); break-glass JIT procedure | — | ⏳ M5 |
| T12 | Leaked migrator or provisioner credentials | E | Migrator only in CI/CD; app has no DDL | schema-lint R5/R6 | ⚠️ secrets management in M5 |
| T13 | PII in logs or audit | I | Audit `redact()` on PII keys; structured logging policy | `db-audit.test.ts` | ⚠️ logging policy in M1 |
| T14 | Audit tampering | R | INSERT-only grants + trigger also blocking owner UPDATE/DELETE/TRUNCATE | `db-audit.test.ts` | ✅ M0; hash chain + WORM in M2 |
| T15 | Supply chain (npm, Actions) | T | Lockfile, `minimumReleaseAge` 3 days, install scripts off, `pnpm audit` in CI | CI | ⚠️ Actions not SHA-pinned yet (M1) |
| T16 | Job running with stale rights | E | Re-authorize when the job runs | — | ⏳ first job in M2 |
| T17 | Real data in non-production | C | `meta.synthetic_marker`: the app refuses to start without it; the seed refuses non-dev databases | `db-audit.test.ts`, E2E boot | ✅ M0 |
| T18 | AI prompt injection / cross-tenant retrieval | I | RLS on embeddings, retrieval in the user's context | — | ⏳ AI milestone |
| T19 | CSRF on state-changing endpoints | T | SameSite=Lax + Origin check; `Referrer-Policy: same-origin` (needed so browsers send Origin) | E2E logout with foreign Origin → 403 | ✅ M0 |
| T20 | Clickjacking / XSS impact | T, I | CSP `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`; React escaping | E2E headers | ⚠️ `script-src 'unsafe-inline'` → nonce-based CSP in M5 |
| T21 | Open redirect / Host-header injection after login | S | Callback URL and redirects built from the configured `APP_BASE_URL`, never from Host | code review | ✅ M0 |
| T22 | Context spoofing through `set_config` (SQL as `ios_app`) | E, S | M0: parameterised queries only, no raw `pg` in the app. M1: DB-verified, session-bound context (`auth.begin`, no GUC trust) | M1 tests D1–D4 | ⚠️ **open gap in M0**, fixed in M1-WP1 |
