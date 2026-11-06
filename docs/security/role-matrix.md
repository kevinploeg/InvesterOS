# System role × permission matrix

Generated from `packages/kernel/src/authz/{permissions,roles}.ts` by `pnpm --filter @investoros/kernel gen:role-matrix`.
A test fails if this file is out of date, so every change to role permissions shows up in review.

Notes:
- No role reaches **restricted** resources through this matrix alone. A live grant on the securable is required in addition
  (read-only permissions can alternatively be satisfied by `restricted.oversight`, which is audited).
- System roles are immutable through the application (enforced by RLS). Custom roles arrive in M1.

| Permission | owner | admin | investment_professional | investor_relations | compliance | read_only |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `tenant.settings.manage` | ✔ | ✔ |  |  |  |  |
| `iam.members.read` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `iam.members.manage` | ✔ | ✔ |  |  |  |  |
| `iam.teams.manage` | ✔ | ✔ |  |  |  |  |
| `iam.roles.manage` | ✔ | ✔ |  |  |  |  |
| `access.manage` | ✔ | ✔ |  |  |  |  |
| `securables.manage` | ✔ | ✔ |  |  |  |  |
| `restricted.oversight` |  |  |  |  | ✔ |  |
| `audit.read` | ✔ | ✔ |  |  | ✔ | ✔ |
| `investors.read` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `investors.write` | ✔ |  |  | ✔ |  |  |
| `projects.read` (scopable) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `projects.write` (scopable) | ✔ |  | ✔ |  |  |  |
| `opportunities.read` (scopable) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `opportunities.write` (scopable) | ✔ |  | ✔ |  |  |  |
| `offerings.read` (scopable) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `offerings.write` (scopable) | ✔ |  |  | ✔ |  |  |
| `subscriptions.approve` (scopable) | ✔ |  |  |  | ✔ |  |
| `crm.read` (scopable) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `crm.write` (scopable) | ✔ |  | ✔ | ✔ |  |  |
| `tasks.read` (scopable) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `tasks.write` (scopable) | ✔ |  | ✔ | ✔ |  |  |
| `ledger.read` (scopable) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `ledger.post` | ✔ |  |  |  |  |  |
