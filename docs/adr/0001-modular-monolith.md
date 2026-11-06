# ADR-0001: Modular monolith on Next.js + Postgres

Status: accepted (architecture approval)

Decision: one deployable unit (Next.js 16, App Router) with a strict layer structure. `apps/web` is a thin UI layer. Business logic and security live in `packages/kernel` and, from M3, in `modules/*`. Boundaries are enforced with dependency-cruiser and ESLint.

Rationale: one team, one domain, strong transactional consistency (ledger, audit). Microservices would only add distributed-transaction problems.

Consequence: a module can be split out later along its public API.
