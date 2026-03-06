-- ═══════════════════════════════════════════════════════════════
-- EDARS Migration 010 — Tenant Lifecycle (Suspension & Deletion)
-- ═══════════════════════════════════════════════════════════════
-- Implements GDPR Right to Erasure (Art. 17) via a two-phase
-- deletion process:
--   Phase 1: request_tenant_deletion() — marks the tenant,
--            schedules deletion for 30 days later (legal hold)
--   Phase 2: execute_tenant_deletion() — anonymises PII,
--            deletes report data, marks tenant as deleted
--
-- Deletion means ANONYMISATION, not just a deleted_at flag.
-- Real data is overwritten, not hidden.
--
-- The tenant row itself is NEVER deleted — you need the
-- audit trail record.
--
-- DEPENDS ON: 007_tenant_rls.sql (RLS must be in place)
-- IDEMPOTENT: Uses CREATE OR REPLACE.
-- ═══════════════════════════════════════════════════════════════


-- ═══════════════════════════════════════════════════════════════
-- 1. request_tenant_deletion(p_tenant_id UUID)
-- ═══════════════════════════════════════════════════════════════
-- - Sets deletion_requested_at = NOW()
-- - Sets deletion_scheduled_at = NOW() + 30 days (legal hold)
-- - Writes audit entry: TENANT_DELETION_REQUESTED
-- - Does NOT delete any data
-- - Returns the updated tenant row
CREATE OR REPLACE FUNCTION request_tenant_deletion(p_tenant_id UUID)
RETURNS SETOF tenants
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tenant tenants%ROWTYPE;
BEGIN
    -- Verify tenant exists and is not already deleted
    SELECT * INTO v_tenant FROM tenants WHERE id = p_tenant_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'TENANT_NOT_FOUND'
            USING HINT = 'No tenant with ID ' || p_tenant_id;
    END IF;

    IF v_tenant.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'TENANT_ALREADY_DELETED'
            USING HINT = 'This tenant was already deleted on '
                         || v_tenant.deleted_at::TEXT;
    END IF;

    IF v_tenant.deletion_requested_at IS NOT NULL THEN
        RAISE EXCEPTION 'DELETION_ALREADY_REQUESTED'
            USING HINT = 'Deletion was already requested on '
                         || v_tenant.deletion_requested_at::TEXT
                         || '. Scheduled for '
                         || v_tenant.deletion_scheduled_at::TEXT;
    END IF;

    -- Mark the tenant for deletion with 30-day legal hold
    UPDATE tenants SET
        deletion_requested_at = NOW(),
        deletion_scheduled_at = NOW() + INTERVAL '30 days',
        is_active = FALSE,
        suspended_at = COALESCE(suspended_at, NOW()),
        suspension_reason = COALESCE(suspension_reason, 'Pending deletion')
    WHERE id = p_tenant_id
    RETURNING * INTO v_tenant;

    -- Audit trail
    INSERT INTO audit_log (tenant_id, action, resource_type, resource_id, metadata, created_at)
    VALUES (
        p_tenant_id,
        'TENANT_DELETION_REQUESTED',
        'tenants',
        p_tenant_id::TEXT,
        jsonb_build_object(
            'scheduled_for', v_tenant.deletion_scheduled_at,
            'tenant_name', v_tenant.name,
            'tenant_slug', v_tenant.slug,
            'timestamp', NOW()
        ),
        NOW()
    );

    RETURN NEXT v_tenant;
END;
$$;


-- ═══════════════════════════════════════════════════════════════
-- 2. execute_tenant_deletion(p_tenant_id UUID)
-- ═══════════════════════════════════════════════════════════════
-- - RAISES EXCEPTION if deletion_scheduled_at is in the future
-- - RAISES EXCEPTION if already deleted
-- - Anonymises PII in users (email, name, password_hash)
-- - Anonymises IP addresses in audit_log
-- - Deletes report data
-- - Deletes transaction data
-- - Writes final audit entry: TENANT_DATA_WIPED
-- - Sets deleted_at on the tenant row
-- - Does NOT delete the tenant row itself
CREATE OR REPLACE FUNCTION execute_tenant_deletion(p_tenant_id UUID)
RETURNS SETOF tenants
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tenant tenants%ROWTYPE;
    v_user_count INT;
    v_report_count INT;
    v_tx_count INT;
BEGIN
    -- Verify tenant exists
    SELECT * INTO v_tenant FROM tenants WHERE id = p_tenant_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'TENANT_NOT_FOUND'
            USING HINT = 'No tenant with ID ' || p_tenant_id;
    END IF;

    -- Cannot delete before 30-day legal hold period
    IF v_tenant.deletion_scheduled_at IS NULL THEN
        RAISE EXCEPTION 'DELETION_NOT_REQUESTED'
            USING HINT = 'Call request_tenant_deletion() first.';
    END IF;

    IF v_tenant.deletion_scheduled_at > NOW() THEN
        RAISE EXCEPTION 'DELETION_HOLD_PERIOD'
            USING HINT = 'Cannot delete before '
                         || v_tenant.deletion_scheduled_at::TEXT
                         || '. Legal hold period has not expired.';
    END IF;

    -- Cannot delete twice
    IF v_tenant.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'TENANT_ALREADY_DELETED'
            USING HINT = 'This tenant was already deleted on '
                         || v_tenant.deleted_at::TEXT;
    END IF;

    -- ─── Phase 1: Anonymise PII in users ────────────────────
    -- Replace identifying data with non-reversible placeholders.
    -- The row still exists (for audit FK integrity) but contains
    -- no personal information.
    UPDATE users SET
        email         = 'deleted-' || id || '@redacted.invalid',
        full_name     = 'Deleted User',
        password_hash = 'REDACTED',
        is_active     = FALSE,
        tos_accepted_at = NULL,
        tos_version = NULL,
        privacy_policy_accepted_at = NULL,
        privacy_policy_version = NULL
    WHERE tenant_id = p_tenant_id;

    GET DIAGNOSTICS v_user_count = ROW_COUNT;

    -- ─── Phase 2: Anonymise IP addresses in audit_log ───────
    -- Keep the log rows (legal protection for YOU), but remove
    -- the person's IP address.
    --
    -- NOTE: audit_log has BEFORE UPDATE triggers that prevent
    -- mutation. We must temporarily disable them.
    ALTER TABLE audit_log DISABLE TRIGGER trg_audit_no_update;

    UPDATE audit_log SET
        ip_address = '0.0.0.0'::INET,
        user_agent = 'REDACTED'
    WHERE tenant_id = p_tenant_id;

    ALTER TABLE audit_log ENABLE TRIGGER trg_audit_no_update;

    -- ─── Phase 3: Delete report data ────────────────────────
    DELETE FROM reports WHERE tenant_id = p_tenant_id;
    GET DIAGNOSTICS v_report_count = ROW_COUNT;

    -- ─── Phase 4: Delete transaction data ───────────────────
    DELETE FROM transactions WHERE tenant_id = p_tenant_id;
    GET DIAGNOSTICS v_tx_count = ROW_COUNT;

    -- ─── Phase 5: Delete user_departments junctions ─────────
    DELETE FROM user_departments
    WHERE user_id IN (
        SELECT id FROM users WHERE tenant_id = p_tenant_id
    );

    -- ─── Phase 6: Delete department records ─────────────────
    -- (After user_departments are cleaned up)
    DELETE FROM departments WHERE tenant_id = p_tenant_id;

    -- ─── Phase 7: Final audit entry ─────────────────────────
    -- This is written BEFORE we mark deleted_at, so the tenant
    -- isolation policy still allows the INSERT.
    ALTER TABLE audit_log DISABLE TRIGGER trg_audit_no_update;

    INSERT INTO audit_log (tenant_id, action, resource_type, resource_id, metadata, created_at)
    VALUES (
        p_tenant_id,
        'TENANT_DATA_WIPED',
        'tenants',
        p_tenant_id::TEXT,
        jsonb_build_object(
            'users_anonymised', v_user_count,
            'reports_deleted', v_report_count,
            'transactions_deleted', v_tx_count,
            'timestamp', NOW()
        ),
        NOW()
    );

    ALTER TABLE audit_log ENABLE TRIGGER trg_audit_no_update;

    -- ─── Phase 8: Mark tenant as deleted ────────────────────
    UPDATE tenants SET
        deleted_at = NOW(),
        is_active  = FALSE
    WHERE id = p_tenant_id
    RETURNING * INTO v_tenant;

    RETURN NEXT v_tenant;
END;
$$;
