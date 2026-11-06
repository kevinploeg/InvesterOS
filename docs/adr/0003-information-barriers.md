# ADR-0003: Information barriers through securables in RLS

Status: proposed (implemented and tested in M0 as a mechanism; applied to domain tables from M3)

Decision: sensitive objects register a `securable` with classification `standard|restricted`. Children carry `securable_id`. Visibility and write rights for restricted resources are enforced in RLS through grants (membership or team, with optional expiry). Tenant-wide roles, including owner and admin, give no access to restricted resources. Compliance gets read-only oversight.

Alternatives:
(a) application-layer filtering only. Rejected by the owner (A7).
(b) denormalising `is_restricted` onto every child. Rejected: reclassifying would require mass updates and risks inconsistency.
(c) an external policy engine (OpenFGA/Cedar). Not needed now; `authorize()` is the abstraction where one could plug in.

Known gap: self-grants by access managers until M2 (four-eyes).
