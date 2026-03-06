-- ═══════════════════════════════════════════════════════════════
-- EDARS Migration 007 — Row-Level Security for Tenant Isolation
-- ═══════════════════════════════════════════════════════════════
-- Replaces the existing department-only RLS policies with
-- tenant-scoped policies. Every query now requires
-- app.current_tenant_id to be set or returns zero rows.
--
-- DEPENDS ON: 006_add_tenancy.sql (tenant_id columns must exist)
-- IDEMPOTENT: Uses DROP POLICY IF EXISTS before CREATE.
-- ═══════════════════════════════════════════════════════════════

-- ─── 1. Enable RLS on all data tables ───────────────────────
-- (Some of these may already be enabled from 002_rls.sql —
--  running ALTER TABLE ENABLE ROW LEVEL SECURITY is idempotent.)

ALTER TABLE departments  ENABLE ROW LEVEL SECURITY;
ALTER TABLE users        ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports      ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log    ENABLE ROW LEVEL SECURITY;

ALTER TABLE departments  FORCE ROW LEVEL SECURITY;
ALTER TABLE users        FORCE ROW LEVEL SECURITY;
ALTER TABLE reports      FORCE ROW LEVEL SECURITY;
ALTER TABLE transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log    FORCE ROW LEVEL SECURITY;


-- ─── 2. Ensure edars_app role exists ────────────────────────
-- This role is what Node/Python apps connect as.
-- It must NEVER be a superuser — superusers bypass RLS.

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_roles WHERE rolname = 'edars_app'
    ) THEN
        CREATE ROLE edars_app LOGIN PASSWORD 'CHANGE_THIS_IN_ENV';
    END IF;
END $$;

-- Grant necessary permissions (idempotent — GRANT is safe to repeat)
GRANT SELECT, INSERT, UPDATE
    ON ALL TABLES IN SCHEMA public TO edars_app;
GRANT USAGE, SELECT
    ON ALL SEQUENCES IN SCHEMA public TO edars_app;
GRANT EXECUTE
    ON ALL FUNCTIONS IN SCHEMA public TO edars_app;

-- Audit log: INSERT only (no UPDATE/DELETE by design)
REVOKE UPDATE, DELETE ON audit_log FROM edars_app;


-- ═══════════════════════════════════════════════════════════════
-- 3. TENANT ISOLATION POLICIES
-- ═══════════════════════════════════════════════════════════════
-- Strategy:
--   - edars_app: can only see/modify rows matching their tenant_id
--   - postgres (superuser): admin bypass for migrations and ops
--
-- Every policy uses current_setting('app.current_tenant_id', true)
-- which is set per-transaction by the gateway's getTenantClient().

-- ─── 3a. DEPARTMENTS ────────────────────────────────────────
DROP POLICY IF EXISTS tenant_isolation ON departments;
DROP POLICY IF EXISTS admin_bypass     ON departments;

CREATE POLICY tenant_isolation ON departments
    AS PERMISSIVE FOR ALL TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

CREATE POLICY admin_bypass ON departments
    AS PERMISSIVE FOR ALL TO postgres
    USING (true);


-- ─── 3b. USERS ──────────────────────────────────────────────
DROP POLICY IF EXISTS tenant_isolation ON users;
DROP POLICY IF EXISTS admin_bypass     ON users;

CREATE POLICY tenant_isolation ON users
    AS PERMISSIVE FOR ALL TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

CREATE POLICY admin_bypass ON users
    AS PERMISSIVE FOR ALL TO postgres
    USING (true);


-- ─── 3c. REPORTS ────────────────────────────────────────────
-- Drop old department-only policies from 002_rls.sql
DROP POLICY IF EXISTS reports_dept_isolation        ON reports;
DROP POLICY IF EXISTS reports_insert                ON reports;
DROP POLICY IF EXISTS reports_tenant_dept_isolation  ON reports;
DROP POLICY IF EXISTS reports_tenant_insert          ON reports;
DROP POLICY IF EXISTS tenant_isolation              ON reports;
DROP POLICY IF EXISTS admin_bypass                  ON reports;

CREATE POLICY tenant_isolation ON reports
    AS PERMISSIVE FOR ALL TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            current_setting('app.current_user_role', true) = 'admin'
            OR department_id IN (
                SELECT ud.department_id FROM user_departments ud
                WHERE ud.user_id = current_setting('app.current_user_id', true)::INT
                UNION
                SELECT u.department_id FROM users u
                WHERE u.id = current_setting('app.current_user_id', true)::INT
            )
        )
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

CREATE POLICY admin_bypass ON reports
    AS PERMISSIVE FOR ALL TO postgres
    USING (true);


-- ─── 3d. TRANSACTIONS ──────────────────────────────────────
DROP POLICY IF EXISTS transactions_dept_isolation        ON transactions;
DROP POLICY IF EXISTS transactions_tenant_dept_isolation  ON transactions;
DROP POLICY IF EXISTS tenant_isolation                   ON transactions;
DROP POLICY IF EXISTS admin_bypass                       ON transactions;

CREATE POLICY tenant_isolation ON transactions
    AS PERMISSIVE FOR ALL TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            current_setting('app.current_user_role', true) = 'admin'
            OR department_id IN (
                SELECT ud.department_id FROM user_departments ud
                WHERE ud.user_id = current_setting('app.current_user_id', true)::INT
                UNION
                SELECT u.department_id FROM users u
                WHERE u.id = current_setting('app.current_user_id', true)::INT
            )
        )
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

CREATE POLICY admin_bypass ON transactions
    AS PERMISSIVE FOR ALL TO postgres
    USING (true);


-- ─── 3e. AUDIT_LOG ──────────────────────────────────────────
DROP POLICY IF EXISTS audit_admin_only        ON audit_log;
DROP POLICY IF EXISTS audit_insert_all        ON audit_log;
DROP POLICY IF EXISTS audit_tenant_admin_only ON audit_log;
DROP POLICY IF EXISTS audit_tenant_insert     ON audit_log;
DROP POLICY IF EXISTS tenant_isolation        ON audit_log;
DROP POLICY IF EXISTS admin_bypass            ON audit_log;

-- SELECT: Only admins within the same tenant can read audit logs
CREATE POLICY tenant_isolation ON audit_log
    AS PERMISSIVE FOR SELECT TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND current_setting('app.current_user_role', true) = 'admin'
    );

-- INSERT: Anyone within the tenant can write audit entries
-- (the middleware writes these, not end users directly)
CREATE POLICY tenant_audit_insert ON audit_log
    AS PERMISSIVE FOR INSERT TO edars_app
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

CREATE POLICY admin_bypass ON audit_log
    AS PERMISSIVE FOR ALL TO postgres
    USING (true);


-- ═══════════════════════════════════════════════════════════════
-- 4. TENANT CONTEXT FUNCTION
-- ═══════════════════════════════════════════════════════════════
-- Called by the gateway's getTenantClient() before every query.
-- The 'true' flag on set_config means LOCAL — the setting is
-- cleared when the transaction/session ends, preventing one
-- tenant's context from bleeding into the next request.

CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'set_tenant_context: tenant_id cannot be null';
    END IF;

    PERFORM set_config(
        'app.current_tenant_id',
        p_tenant_id::TEXT,
        true   -- LOCAL = cleared when transaction ends
    );
END;
$$;


-- ═══════════════════════════════════════════════════════════════
-- 5. DEFAULT FUTURE GRANTS
-- ═══════════════════════════════════════════════════════════════
-- Ensure any tables created by future migrations are also
-- accessible by edars_app.

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE ON TABLES TO edars_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO edars_app;
