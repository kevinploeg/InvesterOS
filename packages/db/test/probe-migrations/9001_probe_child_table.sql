-- TEST-ONLY migration (never in migrations/). A child table that inherits visibility from a
-- securable, exactly as projects' tasks, interactions, documents, subscriptions and ledger
-- lines will from M3. It proves the information-barrier pattern before any domain table exists.
CREATE TABLE probe_notes (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  id           uuid NOT NULL,
  securable_id uuid NOT NULL,
  body         text NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, securable_id) REFERENCES securables (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE probe_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_notes FORCE ROW LEVEL SECURITY;
CREATE POLICY probe_notes_tenant_isolation ON probe_notes AS RESTRICTIVE FOR ALL TO ios_app, ios_worker
  USING (tenant_id = app.current_tenant()) WITH CHECK (tenant_id = app.current_tenant());
CREATE POLICY probe_notes_read ON probe_notes FOR SELECT TO ios_app, ios_worker
  USING (app.securable_visible(tenant_id, securable_id));
CREATE POLICY probe_notes_insert ON probe_notes FOR INSERT TO ios_app
  WITH CHECK (app.securable_writable(tenant_id, securable_id));
CREATE POLICY probe_notes_update ON probe_notes FOR UPDATE TO ios_app
  USING (app.securable_writable(tenant_id, securable_id)) WITH CHECK (app.securable_writable(tenant_id, securable_id));
CREATE POLICY probe_notes_delete ON probe_notes FOR DELETE TO ios_app
  USING (app.securable_writable(tenant_id, securable_id));
GRANT SELECT, INSERT, UPDATE, DELETE ON probe_notes TO ios_app;
GRANT SELECT ON probe_notes TO ios_worker;
