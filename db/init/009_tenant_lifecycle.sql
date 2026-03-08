-- db/init/009_tenant_lifecycle.sql
-- ════════════════════════════════════════════════════════════════
-- Migration: Tenant Lifecycle & GDPR Right to Erasure
-- Run order: After 008_consent.sql
-- Idempotent: Yes
--
-- GDPR Article 17 gives users the right to request deletion of
-- their personal data. This migration implements a safe, auditable
-- erasure process with a mandatory 30-day hold period.
--
-- The process:
--   1. Admin calls request_tenant_deletion() → sets deletion date
--   2. System waits 30 days (legal hold — allows dispute resolution)
--   3. Admin calls execute_tenant_deletion() → anonymises all PII
--   4. Audit trail is preserved but PII within it is redacted
--   5. The tenant row itself is kept for YOUR audit trail
-- ════════════════════════════════════════════════════════════════

-- ── 1. request_tenant_deletion ────────────────────────────────
-- Schedules a tenant for deletion 30 days from now.
-- Does NOT delete or anonymise anything immediately.

CREATE OR REPLACE FUNCTION request_tenant_deletion(
  p_tenant_id UUID,
  p_requested_by_user_id UUID DEFAULT NULL
)
RETURNS tenants
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
  v_tenant tenants;
BEGIN
  -- Validate tenant exists and is not already deleted/scheduled
  SELECT * INTO v_tenant
  FROM tenants
  WHERE id = p_tenant_id
  FOR UPDATE;  -- lock row to prevent race conditions

  IF NOT FOUND THEN
    RAISE EXCEPTION 'TENANT_NOT_FOUND: %', p_tenant_id
      USING ERRCODE = 'no_data_found';
  END IF;

  IF v_tenant.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'TENANT_ALREADY_DELETED: Tenant % was deleted on %',
      p_tenant_id, v_tenant.deleted_at
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  IF v_tenant.deletion_requested_at IS NOT NULL THEN
    RAISE EXCEPTION 'DELETION_ALREADY_REQUESTED: '
      'Deletion scheduled for %. Cancel first if you need to reschedule.',
      v_tenant.deletion_scheduled_at
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  -- Schedule deletion
  UPDATE tenants SET
    deletion_requested_at = NOW(),
    deletion_scheduled_at = NOW() + INTERVAL '30 days',
    is_active             = false   -- disable immediately
  WHERE id = p_tenant_id
  RETURNING * INTO v_tenant;

  -- Write to audit_log — this write uses postgres role (migration context)
  -- In production, the gateway writes this audit entry instead
  BEGIN
    INSERT INTO audit_log (
      tenant_id, user_id, action, resource,
      resource_id, ip, correlation_id, timestamp
    ) VALUES (
      p_tenant_id,
      COALESCE(p_requested_by_user_id, '00000000-0000-0000-0000-000000000000'),
      'TENANT_DELETION_REQUESTED',
      'tenants',
      p_tenant_id,
      '0.0.0.0',
      'system-' || gen_random_uuid(),
      NOW()
    );
  EXCEPTION WHEN OTHERS THEN
    -- Audit write failure must not block the operation in migration context
    RAISE WARNING 'Audit log write failed during deletion request: %', SQLERRM;
  END;

  RETURN v_tenant;
END;
$$;

-- ── 2. execute_tenant_deletion ────────────────────────────────
-- Permanently anonymises all PII for a tenant.
-- Can only run after deletion_scheduled_at has passed.
--
-- What happens:
--   - User PII (email, name, password) → anonymised/redacted
--   - IPs in audit_log → replaced with 0.0.0.0
--   - Report data → deleted
--   - Tenant row → marked deleted but NOT removed (for your audit trail)
--
-- What is preserved:
--   - audit_log rows (action, timestamp, resource) — for legal compliance
--   - tenant row with deleted_at timestamp — for your records

CREATE OR REPLACE FUNCTION execute_tenant_deletion(p_tenant_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
  v_tenant        tenants;
  v_user_count    INTEGER;
  v_report_count  INTEGER;
BEGIN
  -- Fetch and lock the tenant row
  SELECT * INTO v_tenant
  FROM tenants
  WHERE id = p_tenant_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'TENANT_NOT_FOUND: %', p_tenant_id;
  END IF;

  IF v_tenant.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'TENANT_ALREADY_DELETED: Tenant was deleted on %',
      v_tenant.deleted_at;
  END IF;

  IF v_tenant.deletion_scheduled_at IS NULL THEN
    RAISE EXCEPTION 'DELETION_NOT_REQUESTED: '
      'Call request_tenant_deletion() first.';
  END IF;

  -- Enforce 30-day hold
  IF v_tenant.deletion_scheduled_at > NOW() THEN
    RAISE EXCEPTION 'DELETION_HOLD_ACTIVE: '
      'Deletion is scheduled for %. '
      'Cannot execute before then (30-day legal hold).',
      v_tenant.deletion_scheduled_at;
  END IF;

  -- ── Step 1: Anonymise user PII ─────────────────────────────
  -- We overwrite with deterministic values so the row still
  -- exists for referential integrity, but contains no PII.
  UPDATE users SET
    email                       = 'deleted-' || id || '@redacted.invalid',
    name                        = 'Deleted User',
    password_hash               = 'REDACTED',
    tos_accepted_at             = NULL,
    privacy_policy_accepted_at  = NULL
  WHERE tenant_id = p_tenant_id;

  GET DIAGNOSTICS v_user_count = ROW_COUNT;

  -- ── Step 2: Redact IPs in audit_log ───────────────────────
  -- IP addresses are PII under GDPR/NDPA.
  -- We keep the log entries for compliance but remove the IP.
  UPDATE audit_log SET
    ip = '0.0.0.0'
  WHERE tenant_id = p_tenant_id;

  -- ── Step 3: Delete report data ────────────────────────────
  DELETE FROM reports WHERE tenant_id = p_tenant_id;
  GET DIAGNOSTICS v_report_count = ROW_COUNT;

  -- ── Step 4: Write final audit entry ───────────────────────
  INSERT INTO audit_log (
    tenant_id, user_id, action, resource,
    resource_id, ip, correlation_id, timestamp
  ) VALUES (
    p_tenant_id,
    '00000000-0000-0000-0000-000000000000',
    'TENANT_DATA_WIPED',
    'tenants',
    p_tenant_id,
    '0.0.0.0',
    'system-' || gen_random_uuid(),
    NOW()
  );

  -- ── Step 5: Mark tenant as deleted ────────────────────────
  -- We do NOT delete the tenant row — it is part of your audit trail.
  UPDATE tenants SET deleted_at = NOW()
  WHERE id = p_tenant_id;

  RETURN format(
    'Tenant %s data wiped. %s users anonymised, %s reports deleted.',
    p_tenant_id, v_user_count, v_report_count
  );
END;
$$;
