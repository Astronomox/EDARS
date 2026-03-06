-- ═══════════════════════════════════════════════════════════════
-- EDARS — Row-Level Security (RLS) Policies
-- ═══════════════════════════════════════════════════════════════
-- Enforces department-level data isolation at the database engine level.
-- Even a misconfigured application query cannot leak cross-department data.

-- ─── Application Role ────────────────────────────────────────
-- The API gateway connects as this role. RLS policies apply to it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'edars_app') THEN
        CREATE ROLE edars_app LOGIN PASSWORD 'app_role_password_change_me';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE edars TO edars_app;
GRANT USAGE ON SCHEMA public TO edars_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO edars_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO edars_app;
-- Audit log: INSERT only (no UPDATE/DELETE by design)
REVOKE UPDATE, DELETE ON audit_log FROM edars_app;

-- ═══════════════════════════════════════════════════════════════
-- ENABLE RLS ON DATA TABLES
-- ═══════════════════════════════════════════════════════════════
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owners (defence in depth)
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

-- ═══════════════════════════════════════════════════════════════
-- RLS POLICIES — REPORTS
-- ═══════════════════════════════════════════════════════════════
-- The app sets current_setting('app.current_user_id') and
-- current_setting('app.current_user_role') per transaction.

-- Viewers & Analysts: own department only
CREATE POLICY reports_dept_isolation ON reports
    FOR SELECT
    TO edars_app
    USING (
        current_setting('app.current_user_role', true) = 'admin'
        OR department_id IN (
            SELECT ud.department_id FROM user_departments ud
            WHERE ud.user_id = current_setting('app.current_user_id', true)::int
            UNION
            SELECT u.department_id FROM users u
            WHERE u.id = current_setting('app.current_user_id', true)::int
        )
    );

-- Insert: users can create reports in their own department(s)
CREATE POLICY reports_insert ON reports
    FOR INSERT
    TO edars_app
    WITH CHECK (
        department_id IN (
            SELECT ud.department_id FROM user_departments ud
            WHERE ud.user_id = current_setting('app.current_user_id', true)::int
            UNION
            SELECT u.department_id FROM users u
            WHERE u.id = current_setting('app.current_user_id', true)::int
        )
    );

-- ═══════════════════════════════════════════════════════════════
-- RLS POLICIES — TRANSACTIONS
-- ═══════════════════════════════════════════════════════════════
CREATE POLICY transactions_dept_isolation ON transactions
    FOR SELECT
    TO edars_app
    USING (
        current_setting('app.current_user_role', true) = 'admin'
        OR department_id IN (
            SELECT ud.department_id FROM user_departments ud
            WHERE ud.user_id = current_setting('app.current_user_id', true)::int
            UNION
            SELECT u.department_id FROM users u
            WHERE u.id = current_setting('app.current_user_id', true)::int
        )
    );

-- ═══════════════════════════════════════════════════════════════
-- RLS POLICIES — AUDIT LOG
-- ═══════════════════════════════════════════════════════════════
-- Only admins can read audit logs
CREATE POLICY audit_admin_only ON audit_log
    FOR SELECT
    TO edars_app
    USING (
        current_setting('app.current_user_role', true) = 'admin'
    );

-- Everyone can insert audit entries (via the app middleware)
CREATE POLICY audit_insert_all ON audit_log
    FOR INSERT
    TO edars_app
    WITH CHECK (true);
