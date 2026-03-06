-- ═══════════════════════════════════════════════════════════════
-- EDARS Migration 006 — Add tenant_id to All Data Tables
-- ═══════════════════════════════════════════════════════════════
-- Adds tenant_id UUID FK to every per-organisation data table,
-- backfills existing rows with the dev tenant, then enforces
-- NOT NULL.
--
-- DEPENDS ON: 005_tenants.sql (tenants table must exist)
-- IDEMPOTENT: Safe to run multiple times.
-- ═══════════════════════════════════════════════════════════════

-- ─── 1. Add tenant_id columns ───────────────────────────────
-- ON DELETE RESTRICT: you cannot delete a tenant while their
-- data exists. This prevents accidental data loss.

-- 1a. departments
ALTER TABLE departments
    ADD COLUMN IF NOT EXISTS tenant_id UUID
    REFERENCES tenants(id) ON DELETE RESTRICT;

-- 1b. users
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id UUID
    REFERENCES tenants(id) ON DELETE RESTRICT;

-- 1c. reports (partitioned table — column added to parent)
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS tenant_id UUID;
-- Cannot add FK on partitioned table directly in PG16;
-- constraint enforced at application level + RLS.

-- 1d. transactions (partitioned table)
ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- 1e. audit_log (partitioned table)
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- 1f. user_departments (junction table — inherits tenancy from users)
-- No tenant_id needed here: tenancy is enforced via the user and
-- department rows, both of which carry tenant_id.


-- ─── 2. Backfill existing rows with dev tenant ─────────────
-- All pre-existing data belongs to the 'edars-dev' tenant.
-- WHERE tenant_id IS NULL ensures re-running is safe.

UPDATE departments
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'edars-dev')
WHERE tenant_id IS NULL;

UPDATE users
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'edars-dev')
WHERE tenant_id IS NULL;

UPDATE reports
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'edars-dev')
WHERE tenant_id IS NULL;

UPDATE transactions
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'edars-dev')
WHERE tenant_id IS NULL;

UPDATE audit_log
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'edars-dev')
WHERE tenant_id IS NULL;


-- ─── 3. Make tenant_id NOT NULL (after backfill) ────────────
-- Each ALTER is wrapped in a DO block that checks whether the
-- constraint already exists, making this idempotent.

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'departments'
          AND column_name = 'tenant_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE departments ALTER COLUMN tenant_id SET NOT NULL;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users'
          AND column_name = 'tenant_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'reports'
          AND column_name = 'tenant_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE reports ALTER COLUMN tenant_id SET NOT NULL;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'transactions'
          AND column_name = 'tenant_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE transactions ALTER COLUMN tenant_id SET NOT NULL;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_log'
          AND column_name = 'tenant_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE audit_log ALTER COLUMN tenant_id SET NOT NULL;
    END IF;
END $$;


-- ─── 4. Indexes ─────────────────────────────────────────────
-- Single-column indexes for FK lookups
CREATE INDEX IF NOT EXISTS idx_departments_tenant_id
    ON departments (tenant_id);

CREATE INDEX IF NOT EXISTS idx_users_tenant_id
    ON users (tenant_id);

CREATE INDEX IF NOT EXISTS idx_reports_tenant_id
    ON reports (tenant_id);

CREATE INDEX IF NOT EXISTS idx_transactions_tenant_id
    ON transactions (tenant_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id
    ON audit_log (tenant_id);

-- Composite indexes for common tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_users_tenant_role
    ON users (tenant_id, role);

CREATE INDEX IF NOT EXISTS idx_users_tenant_email
    ON users (tenant_id, email);

CREATE INDEX IF NOT EXISTS idx_reports_tenant_created
    ON reports (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_transactions_tenant_date
    ON transactions (tenant_id, transaction_date DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created
    ON audit_log (tenant_id, created_at DESC);
