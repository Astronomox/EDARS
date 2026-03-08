-- db/init/005_tenants.sql
-- ════════════════════════════════════════════════════════════════
-- Migration: Multi-tenancy — Tenants table
-- Run order: After 004_advanced.sql
-- Idempotent: Yes (safe to run multiple times)
-- ════════════════════════════════════════════════════════════════

-- ── 1. Tenants table ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
  id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name                  TEXT        NOT NULL,
  slug                  TEXT        NOT NULL,
  plan                  TEXT        NOT NULL DEFAULT 'free',
  is_active             BOOLEAN     NOT NULL DEFAULT true,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  max_users             INTEGER     NOT NULL DEFAULT 3,
  data_retention_days   INTEGER     NOT NULL DEFAULT 30,
  suspended_at          TIMESTAMPTZ          DEFAULT NULL,
  suspension_reason     TEXT                 DEFAULT NULL,
  deletion_requested_at TIMESTAMPTZ          DEFAULT NULL,
  deletion_scheduled_at TIMESTAMPTZ          DEFAULT NULL,
  deleted_at            TIMESTAMPTZ          DEFAULT NULL,

  CONSTRAINT tenants_slug_unique    UNIQUE (slug),
  CONSTRAINT tenants_plan_check     CHECK  (plan IN ('free', 'growth', 'enterprise')),
  CONSTRAINT tenants_slug_format    CHECK  (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
  CONSTRAINT tenants_max_users_pos  CHECK  (max_users > 0),
  CONSTRAINT tenants_retention_pos  CHECK  (data_retention_days > 0)
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug       ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_is_active  ON tenants(is_active);
CREATE INDEX IF NOT EXISTS idx_tenants_plan       ON tenants(plan);

-- ── 2. Stored procedure: create_tenant ───────────────────────
-- Creates a new tenant with validation.
-- Raises exceptions on invalid slug format or slug collision.

CREATE OR REPLACE FUNCTION create_tenant(
  p_name TEXT,
  p_slug TEXT,
  p_plan TEXT DEFAULT 'free'
)
RETURNS tenants
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
  v_tenant tenants;
BEGIN
  -- Validate slug format
  IF p_slug !~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' THEN
    RAISE EXCEPTION 'INVALID_SLUG: % is not a valid tenant slug. '
      'Use lowercase letters, numbers, and hyphens only (3-63 chars).', p_slug
      USING ERRCODE = 'check_violation';
  END IF;

  -- Check slug uniqueness
  IF EXISTS (SELECT 1 FROM tenants WHERE slug = p_slug) THEN
    RAISE EXCEPTION 'TENANT_SLUG_TAKEN: The slug % is already in use.', p_slug
      USING ERRCODE = 'unique_violation';
  END IF;

  -- Validate plan
  IF p_plan NOT IN ('free', 'growth', 'enterprise') THEN
    RAISE EXCEPTION 'INVALID_PLAN: % is not a valid plan. '
      'Choose free, growth, or enterprise.', p_plan
      USING ERRCODE = 'check_violation';
  END IF;

  -- Insert and return
  INSERT INTO tenants (name, slug, plan)
  VALUES (p_name, p_slug, p_plan)
  RETURNING * INTO v_tenant;

  RETURN v_tenant;
END;
$$;

-- ── 3. Dev seed tenant ────────────────────────────────────────
-- This is the tenant used in local development.
-- All existing seed users from 003_seed.sql will be backfilled
-- to this tenant in migration 006.

INSERT INTO tenants (name, slug, plan, max_users, data_retention_days)
VALUES ('EDARS Dev Org', 'edars-dev', 'enterprise', 999, 36500)
ON CONFLICT (slug) DO NOTHING;
