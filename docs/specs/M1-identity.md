# M1: Identity and tenancy (DRAFT, not approved)

Prerequisites: M0 approved, and the Zitadel vendor verification (ADR-0004) completed with a positive result.

| # | Criterion |
|---|---|
| AC1 | Zitadel Cloud (EU) as OIDC provider; MFA required, checked through the `amr`/`acr` claim (a login without MFA is refused) |
| AC2 | Per-tenant SSO (OIDC/SAML) through Zitadel organisations; org → tenant mapping, verified domains; test with a foreign-org claim |
| AC3 | Tenant provisioning through a dedicated provisioning path (not `ios_app`), seeding system roles; audited |
| AC4 | Invitation flow: single-use, 72 h, bound to an e-mail at invite time but linked to (issuer, sub) on first login; audited |
| AC5 | Admin UI: members, teams, role assignments (tenant and scoped), custom roles (registry permissions only) |
| AC6 | Guards: you can't grant permissions you don't hold; you can't remove the last owner; you can't suspend yourself |
| AC7 | Tenant switch rotates the session token |
| AC8 | Suspension revokes active sessions immediately |
| AC9 | Every identity mutation is audited in the same transaction; `restricted.oversight` reads are audited |
| AC10 | Server-action guard (`guardedAction(permission, handler)`), with a test calling actions directly without a session |
| AC11 | Logging policy: structured logs, PII redaction, EU-hosted telemetry |
| AC12 | All GitHub Actions pinned to commit SHAs; Renovate |
| AC13 | Isolation suite, authorization matrix and E2E extended to all new tables, actions and flows |
| AC14 | Test report + security review of the identity flows to the owner |
