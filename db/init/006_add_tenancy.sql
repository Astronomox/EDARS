-- db/init/006_add_tenancy.sql
-- ════════════════════════════════════════════════════════════════
-- Migration: Add tenant_id FK to all data tables
-- Run order: After 005_tenants.sql
-- Idempotent: Yes
--
-- NOTE: If your schema uses different table names, update the
--       table names below to match your 001_schema.sql exactly.
-- ════════════════════════════════════════════════════════════════

-- ── 1. Add tenant_id columns ─────────────────────────────────
-- ON DELETE RESTRICT is intentional: you cannot delete a tenant
-- while data still references it. This prevents accidental wipes.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(id) ON DELETE RESTRICT;

ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS tenant_id UUID
  REFERENCES tenants(id) ON DELETE RESTRICT;

-- ── 2. Backfill existing rows to the dev seed tenant ─────────
-- Any rows that existed before multi-tenancy are assigned to
-- the dev org. This is safe for development only.
-- In production: never use ON CONFLICT — all rows must have
-- an explicit tenant before going live.

DO $$
DECLARE
  v_dev_tenant_id UUID;
BEGIN
  SELECT id INTO v_dev_tenant_id
  FROM tenants
  WHERE slug = 'edars-dev';

  IF v_dev_tenant_id IS NULL THEN
    RAISE EXCEPTION 'Dev tenant (edars-dev) not found. '
      'Run 005_tenants.sql first.';
  END IF;

  UPDATE users
  SET tenant_id = v_dev_tenant_id
  WHERE tenant_id IS NULL;

  UPDATE reports
  SET tenant_id = v_dev_tenant_id
  WHERE tenant_id IS NULL;

  -- Temporarily disable immutability trigger for backfill
  ALTER TABLE audit_log DISABLE TRIGGER trg_audit_no_update;

  UPDATE audit_log
  SET tenant_id = v_dev_tenant_id
  WHERE tenant_id IS NULL;

  ALTER TABLE audit_log ENABLE TRIGGER trg_audit_no_update;
END;
$$;

-- ── 3. Enforce NOT NULL now that backfill is complete ─────────
-- Written as idempotent DO blocks — safe to re-run.

DO $$
BEGIN
  -- users.tenant_id
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'users'
      AND column_name = 'tenant_id'
      AND is_nullable = 'YES'
  ) THEN
    ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
  END IF;

  -- reports.tenant_id
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'reports'
      AND column_name = 'tenant_id'
      AND is_nullable = 'YES'
  ) THEN
    ALTER TABLE reports ALTER COLUMN tenant_id SET NOT NULL;
  END IF;

  -- audit_log.tenant_id
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'audit_log'
      AND column_name = 'tenant_id'
      AND is_nullable = 'YES'
  ) THEN
    ALTER TABLE audit_log ALTER COLUMN tenant_id SET NOT NULL;
  END IF;
END;
$$;

-- ── 4. Performance indexes ────────────────────────────────────
-- Every query that filters or joins by tenant_id will use these.
-- Composite indexes also serve ORDER BY queries on those columns.

CREATE INDEX IF NOT EXISTS idx_users_tenant_id
  ON users(tenant_id);

CREATE INDEX IF NOT EXISTS idx_users_tenant_role
  ON users(tenant_id, role);

CREATE INDEX IF NOT EXISTS idx_users_tenant_email
  ON users(tenant_id, email);

CREATE INDEX IF NOT EXISTS idx_reports_tenant_id
  ON reports(tenant_id);

CREATE INDEX IF NOT EXISTS idx_reports_tenant_created
  ON reports(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id
  ON audit_log(tenant_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_user
  ON audit_log(tenant_id, user_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_action
  ON audit_log(tenant_id, action, created_at DESC);
