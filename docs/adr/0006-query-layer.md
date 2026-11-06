# ADR-0006: Query layer: parameterised SQL in the kernel during M0; Drizzle decision in M1

Status: proposed

M0 contains almost no CRUD. The kernel uses `pg` directly, with parameters only, behind `withTenantTx`. The choice of a typed query builder (Drizzle or Kysely) is made in M1 when the first CRUD screens arrive, on two criteria: it must work within `withTenantTx` (one transaction with the context set) and it must not require raw string interpolation.

Deviation from the original proposal (Drizzle from day one): deliberately postponed, because M0 only needed SQL migrations and policies, which are clearer as hand-written SQL.
