-- db/init/007_tenant_rls.sql
-- ════════════════════════════════════════════════════════════════
-- Migration: Row-Level Security — Tenant Isolation
-- Run order: After 006_add_tenancy.sql
-- Idempotent: Yes
--
-- CRITICAL SECURITY NOTES:
--   1. The app must connect as 'edars_app' role, NOT 'postgres'.
--      Superusers (postgres) bypass RLS entirely.
--   2. The LOCAL flag in set_config means the tenant context is
--      cleared when the transaction ends. This prevents context
--      bleeding between pooled connections.
--   3. Update DATABASE_URL in .env to use:
--      postgresql://edars_app:YOUR_PASSWORD@db:5432/edars
-- ════════════════════════════════════════════════════════════════

-- ── 1. Create the app role (non-superuser) ────────────────────

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT FROM pg_roles WHERE rolname = 'edars_app'
  ) THEN
    -- Password is set here but MUST be overridden via .env
    -- The real password comes from DB_APP_PASSWORD env var
    -- applied during container startup or provisioning.
    CREATE ROLE edars_app LOGIN PASSWORD 'PLACEHOLDER_CHANGE_VIA_ENV';
    RAISE NOTICE 'Role edars_app created. '
      'Update password with: ALTER ROLE edars_app PASSWORD ''<your-password>''';
  END IF;
END;
$$;

-- Grant minimum required permissions
GRANT SELECT, INSERT, UPDATE
  ON ALL TABLES IN SCHEMA public TO edars_app;

GRANT USAGE, SELECT
  ON ALL SEQUENCES IN SCHEMA public TO edars_app;

GRANT EXECUTE
  ON ALL FUNCTIONS IN SCHEMA public TO edars_app;

-- Future tables created after this migration will also grant permissions
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE ON TABLES TO edars_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO edars_app;

-- ── 2. Enable RLS on all data tables ─────────────────────────

ALTER TABLE users      ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log  ENABLE ROW LEVEL SECURITY;

-- FORCE RLS also applies to table owners (extra safety layer)
ALTER TABLE users      FORCE ROW LEVEL SECURITY;
ALTER TABLE reports    FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log  FORCE ROW LEVEL SECURITY;

-- ── 3. Tenant isolation policies ─────────────────────────────
-- Pattern: drop-and-recreate for idempotency.
-- The app_current_tenant_id setting is set per-transaction by
-- set_tenant_context() before any query runs.

-- users
DROP POLICY IF EXISTS tenant_isolation ON users;
DROP POLICY IF EXISTS superuser_bypass  ON users;

CREATE POLICY tenant_isolation ON users
  AS PERMISSIVE
  FOR ALL
  TO edars_app
  USING (
    tenant_id = current_setting('app.current_tenant_id', true)::UUID
  )
  WITH CHECK (
    tenant_id = current_setting('app.current_tenant_id', true)::UUID
  );

-- postgres superuser retains full access (for migrations only)
CREATE POLICY superuser_bypass ON users
  AS PERMISSIVE
  FOR ALL
  TO postgres
  USING (true)
  WITH CHECK (true);

-- reports
DROP POLICY IF EXISTS tenant_isolation ON reports;
DROP POLICY IF EXISTS superuser_bypass  ON reports;

CREATE POLICY tenant_isolation ON reports
  AS PERMISSIVE
  FOR ALL
  TO edars_app
  USING (
    tenant_id = current_setting('app.current_tenant_id', true)::UUID
  )
  WITH CHECK (
    tenant_id = current_setting('app.current_tenant_id', true)::UUID
  );

CREATE POLICY superuser_bypass ON reports
  AS PERMISSIVE
  FOR ALL
  TO postgres
  USING (true)
  WITH CHECK (true);

-- audit_log (read and insert only — updates/deletes blocked by trigger)
DROP POLICY IF EXISTS tenant_isolation ON audit_log;
DROP POLICY IF EXISTS superuser_bypass  ON audit_log;

CREATE POLICY tenant_isolation ON audit_log
  AS PERMISSIVE
  FOR ALL
  TO edars_app
  USING (
    tenant_id = current_setting('app.current_tenant_id', true)::UUID
  )
  WITH CHECK (
    tenant_id = current_setting('app.current_tenant_id', true)::UUID
  );

CREATE POLICY superuser_bypass ON audit_log
  AS PERMISSIVE
  FOR ALL
  TO postgres
  USING (true)
  WITH CHECK (true);

-- ── 4. Tenant context function ────────────────────────────────
-- Called by the gateway's getTenantClient() before every query.
-- LOCAL=true means the setting clears when the transaction ends,
-- preventing context leakage in connection pools.

CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
  IF p_tenant_id IS NULL THEN
    RAISE EXCEPTION 'set_tenant_context: tenant_id cannot be null'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  -- LOCAL = clears at end of transaction (essential for pool safety)
  PERFORM set_config('app.current_tenant_id', p_tenant_id::TEXT, true);
END;
$$;

-- ── 5. Verification query ─────────────────────────────────────
-- After running this migration, verify with:
--
-- SELECT schemaname, tablename, policyname, roles, cmd
-- FROM pg_policies
-- WHERE tablename IN ('users', 'reports', 'audit_log')
-- ORDER BY tablename, policyname;
--
-- You should see tenant_isolation and superuser_bypass
-- policies for each table.
