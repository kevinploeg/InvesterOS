-- 0007 (M1-WP2 follow-up, found by the D8 benchmark): set-based visibility checks.
--
-- A policy that calls app.securable_visible(tenant_id, securable_id) runs a sub-query PER ROW, and the
-- grant/permission lookups inside it are re-evaluated per call. On 1M child rows this exceeded the 15 s
-- statement timeout. The set-based form below is evaluated ONCE per statement as a hashed sub-plan and
-- reads `securables` under its own RLS, so restricted securables without a grant are excluded exactly as
-- before (same semantics, tested by restricted.test.ts).
--
-- Pattern for every child table from M3 on (enforced by review, documented in rls-design.md §4):
--   SELECT: securable_id IN (SELECT s.id FROM securables s)
--   writes: securable_id IN (SELECT s.id FROM securables s
--                            WHERE s.classification = 'standard'
--                               OR s.id = ANY ((SELECT app.granted_securables('write'))::uuid[]))
ALTER POLICY audit_events_read ON audit_events
  USING ((SELECT app.has_permission('audit.read'))
         AND (securable_id IS NULL OR securable_id IN (SELECT s.id FROM securables s)));
