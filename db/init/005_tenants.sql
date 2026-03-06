-- ═══════════════════════════════════════════════════════════════
-- EDARS Migration 005 — Tenants Table
-- ═══════════════════════════════════════════════════════════════
-- Creates the tenants table, tenant provisioning procedure,
-- and seeds the dev tenant.
--
-- IDEMPOTENT: Safe to run multiple times with zero errors
-- and zero duplicate data.
-- ═══════════════════════════════════════════════════════════════

-- ─── 1. Tenants Table ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT NOT NULL,
    slug                  TEXT NOT NULL UNIQUE,
    plan                  TEXT NOT NULL DEFAULT 'free'
                              CHECK (plan IN ('free', 'growth', 'enterprise')),
    is_active             BOOLEAN NOT NULL DEFAULT true,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    max_users             INTEGER NOT NULL DEFAULT 3,
    data_retention_days   INTEGER NOT NULL DEFAULT 30,
    suspended_at          TIMESTAMPTZ DEFAULT NULL,
    suspension_reason     TEXT DEFAULT NULL,
    deletion_requested_at TIMESTAMPTZ DEFAULT NULL,
    deletion_scheduled_at TIMESTAMPTZ DEFAULT NULL,
    deleted_at            TIMESTAMPTZ DEFAULT NULL
);

-- Indexes for common lookups
CREATE INDEX IF NOT EXISTS idx_tenants_slug      ON tenants (slug);
CREATE INDEX IF NOT EXISTS idx_tenants_plan      ON tenants (plan);
CREATE INDEX IF NOT EXISTS idx_tenants_is_active ON tenants (is_active);


-- ─── 2. Stored Procedure: create_tenant ─────────────────────
-- Validates the slug, checks for duplicates, inserts and returns
-- the full new tenant row.
--
-- @param p_name TEXT   — Display name for the organisation
-- @param p_slug TEXT   — URL-safe identifier (lowercase, hyphens only)
-- @param p_plan TEXT   — One of: 'free', 'growth', 'enterprise'
-- @returns SETOF tenants — The full new tenant row
--
-- Raises:
--   'INVALID_SLUG'       if p_slug fails regex validation
--   'TENANT_SLUG_TAKEN'  if the slug is already in use
CREATE OR REPLACE FUNCTION create_tenant(
    p_name TEXT,
    p_slug TEXT,
    p_plan TEXT DEFAULT 'free'
)
RETURNS SETOF tenants
LANGUAGE plpgsql
AS $$
DECLARE
    v_new_tenant tenants%ROWTYPE;
BEGIN
    -- Validate slug format: lowercase alphanumeric + hyphens,
    -- 3–63 chars, must start and end with alphanumeric
    IF p_slug !~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' THEN
        RAISE EXCEPTION 'INVALID_SLUG'
            USING HINT = 'Slug must be 3-63 characters, lowercase '
                         'alphanumeric and hyphens only, must start '
                         'and end with a letter or digit.';
    END IF;

    -- Check for duplicate slug (race-safe via UNIQUE constraint,
    -- but we raise a clear message before hitting the constraint)
    IF EXISTS (SELECT 1 FROM tenants WHERE slug = p_slug) THEN
        RAISE EXCEPTION 'TENANT_SLUG_TAKEN'
            USING HINT = 'The slug "' || p_slug || '" is already in use.';
    END IF;

    -- Validate plan value
    IF p_plan NOT IN ('free', 'growth', 'enterprise') THEN
        RAISE EXCEPTION 'INVALID_PLAN'
            USING HINT = 'Plan must be one of: free, growth, enterprise.';
    END IF;

    -- Insert the new tenant
    INSERT INTO tenants (name, slug, plan)
    VALUES (p_name, p_slug, p_plan)
    RETURNING * INTO v_new_tenant;

    RETURN NEXT v_new_tenant;
END;
$$;


-- ─── 3. Dev Seed Tenant ─────────────────────────────────────
-- ON CONFLICT ensures idempotency — running twice does nothing.
INSERT INTO tenants (name, slug, plan, max_users, data_retention_days)
VALUES ('EDARS Dev Org', 'edars-dev', 'enterprise', 999, 36500)
ON CONFLICT (slug) DO NOTHING;
