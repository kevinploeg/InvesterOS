# ADR-0002: Shared schema + RLS (restrictive tenant policy, FORCE, composite FKs)

Status: accepted, implemented in M0

Decision: every tenant table has `tenant_id`, a RESTRICTIVE tenant policy for all request roles, `FORCE ROW LEVEL SECURITY`, and composite FKs. No role used by the application has BYPASSRLS. Context is transaction-local via `set_config(..., true)`.

Alternatives: schema-per-tenant (migrations unworkable at scale), database-per-tenant (cost; kept as a later option for large customers).

See docs/security/rls-design.md.
