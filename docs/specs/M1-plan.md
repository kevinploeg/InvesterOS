# M1 implementation plan (final, awaiting authorization)

Scope: [M1-identity.md](M1-identity.md) rev. 2 AC1–AC8, as amended by [m1-clarifications.md](../security/m1-clarifications.md) rev. 3 (C1–C3).

Architecture stays a modular monolith. New code goes into `packages/kernel` (auth, context, iam) and `apps/web` (admin screens). **No** new services, no Redis, no policy engine, no ORM, no workflow engine, no mail provider.

## Work packages (in order; each ends with green CI)

| # | Package | Contents | Tests / exit | Depends on |
|---|---|---|---|---|
| WP0 | **Zitadel test instance + evidence matrix** | EU test instance with synthetic users and orgs; record all login methods; build `assurance-matrix.ts` + token fixtures; canary job | Matrix complete for every C1 row; V7, V8, V15–V17 answered | Owner: test instance + API credentials |
| WP1 | **DB-verified context** | Migration 0004: `auth.tx_context`, `auth.begin`, context functions without GUCs, policies to `(SELECT …)`; `withTenantTx` takes the session token; M0 tests migrated | D1–D4; all 239 M0 tests green on the new mechanism; benchmark D8 | — |
| WP2 | **Revocation and concurrency** | `authz_epoch`, `FOR SHARE` in write mode, advisory lock for IAM, throttled `last_seen_at` | D6, D7, R1, R2, R5 | WP1 |
| WP3 | **IAM in the DB** | Subset trigger, last-owner guard, self-mutation guard; custom roles, teams, scoped assignments | AC4, D5, generated escalation tests | WP2 |
| WP4 | **OIDC hardening + assurance** | Algorithm allowlist, `max_age`/`auth_time`, assurance decision function, `auth_events` (truncated IP), recent-auth for privileged actions | AC1 (incl. A1–A6) | WP0, WP1 |
| WP5 | **Tenant SSO** | `tenant_idp_bindings`, org mapping, `sso_required`, org policy check via API + daily drift check | AC2 | WP0, WP4 |
| WP6 | **Invitations** | Token (hash), 72 h, single-use with row lock, e-mail match on `email_verified`, existing-account path, link shown once | AC3 incl. concurrency | WP3, WP4 |
| WP7 | **Server-action guard + admin UI** | `guardedAction(permission, schema, handler)`, action registry, admin screens for members/teams/roles/grants/SSO/invitations (EN/NL) | AC7 generated per registered action; E2E | WP3–WP6 |
| WP8 | **Audit and logging** | Privileged actions, denials, sensitive reads; PII scan test; structured logging with redaction | AC6, AC8.3 | WP3–WP7 |
| WP9 | **Hygiene** | Actions on SHAs + Node 24 versions, Renovate, ESLint rule against caching tenant data, `staleTimes.dynamic=0` | AC8.1, R3 | — (in parallel) |
| WP10 | **Report** | M1 test report, security review of identity flows, updated threat model | AC8.5 | all |

## Decisions included in this plan
- **Query layer (ADR-0006):** no ORM or query builder. Hand-written, parameterised SQL with typed row interfaces in the kernel. RLS and `auth.begin` stay explicit and visible. Revisit at M3 if CRUD volume makes it necessary.
- **`phishing_resistant`:** not delivered in M1 (C1 rule 3).
- **Background jobs:** only the `auth.begin_job` primitive plus a minimal job table. No job framework (pg-boss) until there is a real job (M2).

## Risks
| Risk | Mitigation |
|---|---|
| Zitadel issues no distinguishable `amr` for federated + MFA (V7) | Federated SSO then only with Zitadel-enforced MFA plus the policy check; if even that can't be proven → federated SSO not in M1, local Zitadel accounts with MFA only |
| `auth.begin` overhead per transaction too high | D8 benchmark; fallback: cache session validation per request (not across requests) |
| Org claim (V8) unavailable | Tenant mapping by Zitadel project grant per org (alternative mechanism, verified in WP0) |
| WP0 depends on you (test instance, credentials) | WP1–WP3 and WP9 can start without Zitadel |

## Explicitly not in M1
Investor portal, SCIM, own e-mail delivery, `phishing_resistant` level, policy engine, job framework, production deployment, real data.
