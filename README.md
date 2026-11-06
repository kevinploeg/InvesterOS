# InvestorOS

A secure multi-tenant investment operations platform for European private capital firms.

> **Status: M0 (foundations).** Synthetic data only. Not deployed. Do not use real customer, personal or financial data.

## Layout

```
apps/web               Next.js 16 UI: thin layer, no business logic
packages/kernel        Security kernel: db context (RLS), authz, auth (OIDC + sessions), audit, ids
packages/db            SQL migrations, roles bootstrap, schema lint, test-database helper
packages/testing       Synthetic seed (dev / e2e)
tooling/mock-oidc      Local OIDC provider: DEV/TEST ONLY
e2e/                   Playwright tests
docs/                  architecture, security, specs, ADRs, reports
```

## Local development

Requires Node 22, pnpm 10 and PostgreSQL 16+ with an admin login.

```bash
pnpm install
```

```bash
cp .env.example .env && set -a && . ./.env && set +a
```

```bash
pnpm db:bootstrap && pnpm db:migrate && pnpm db:lint && pnpm db:seed
```

```bash
pnpm --filter @investoros/mock-oidc start
```

```bash
pnpm --filter @investoros/web dev
```

Sign in at http://127.0.0.1:3000 with a seeded subject such as `synthetic-user-01`. The mock IdP accepts any subject; InvestorOS only admits seeded identities.

## Checks

```bash
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm test:e2e
```

## Key documents
- [Domain model (rev. 2)](docs/architecture/domain-model.md) · [Ledger & holdings](docs/architecture/ledger.md)
- [RLS & information barriers](docs/security/rls-design.md) · [Threat model](docs/security/threat-model.md) · [Role matrix](docs/security/role-matrix.md)
- [M0 spec](docs/specs/M0-foundations.md) · [M1 draft](docs/specs/M1-identity.md) · [M0 test report](docs/reports/M0-test-report.md) · [Open questions](docs/open-questions.md)
