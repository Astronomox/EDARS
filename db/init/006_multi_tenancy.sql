-- ═══════════════════════════════════════════════════════════════
-- EDARS — Multi-Tenancy Migration (006)
-- ═══════════════════════════════════════════════════════════════
-- Adds tenant isolation at the database engine level. Every data
-- table gains a tenant_id FK.  All RLS policies are rewritten to
-- enforce cross-tenant isolation on top of existing department
-- scoping. Includes tenant provisioning and usage metering.
--
-- IDEMPOTENT: Safe to run multiple times.
-- ═══════════════════════════════════════════════════════════════

-- ─── 1. Tenant Plan Enum ────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tenant_plan') THEN
        CREATE TYPE tenant_plan AS ENUM ('free', 'growth', 'enterprise');
    END IF;
END
$$;

-- ─── 2. Tenants Table ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id              SERIAL PRIMARY KEY,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(128) NOT NULL UNIQUE,
    plan            tenant_plan NOT NULL DEFAULT 'free',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug);
CREATE INDEX IF NOT EXISTS idx_tenants_uuid ON tenants (uuid);
CREATE INDEX IF NOT EXISTS idx_tenants_plan ON tenants (plan);

-- Auto-update updated_at on tenants
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_tenants_updated_at'
    ) THEN
        CREATE TRIGGER trg_tenants_updated_at
            BEFORE UPDATE ON tenants
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END
$$;

-- ─── 3. Add tenant_id to existing tables ────────────────────
-- Each ALTER is guarded by a column-existence check.

-- 3a. departments
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'departments' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE departments ADD COLUMN tenant_id INT;
    END IF;
END $$;

-- 3b. users
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE users ADD COLUMN tenant_id INT;
    END IF;
END $$;

-- 3c. reports (partitioned — column must exist on parent)
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'reports' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE reports ADD COLUMN tenant_id INT;
    END IF;
END $$;

-- 3d. transactions (partitioned)
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'transactions' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE transactions ADD COLUMN tenant_id INT;
    END IF;
END $$;

-- 3e. audit_log (partitioned)
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_log' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE audit_log ADD COLUMN tenant_id INT;
    END IF;
END $$;

-- ─── 4. Seed default tenant & backfill ──────────────────────
-- All pre-existing data belongs to tenant 1 ("EDARS Internal").
INSERT INTO tenants (id, name, slug, plan)
VALUES (1, 'EDARS Internal', 'edars-internal', 'enterprise')
ON CONFLICT (id) DO NOTHING;

-- Backfill existing rows. Guarded with WHERE tenant_id IS NULL
-- so re-running is safe.
UPDATE departments   SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE users         SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE reports       SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE transactions  SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE audit_log     SET tenant_id = 1 WHERE tenant_id IS NULL;

-- Now make tenant_id NOT NULL (after backfill)
DO $$ BEGIN
    ALTER TABLE departments   ALTER COLUMN tenant_id SET NOT NULL;
    ALTER TABLE departments   ALTER COLUMN tenant_id SET DEFAULT 1;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE users         ALTER COLUMN tenant_id SET NOT NULL;
    ALTER TABLE users         ALTER COLUMN tenant_id SET DEFAULT 1;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE reports       ALTER COLUMN tenant_id SET NOT NULL;
    ALTER TABLE reports       ALTER COLUMN tenant_id SET DEFAULT 1;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE transactions  ALTER COLUMN tenant_id SET NOT NULL;
    ALTER TABLE transactions  ALTER COLUMN tenant_id SET DEFAULT 1;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE audit_log     ALTER COLUMN tenant_id SET NOT NULL;
    ALTER TABLE audit_log     ALTER COLUMN tenant_id SET DEFAULT 1;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- ─── 5. Indexes on tenant_id ────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_departments_tenant   ON departments (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant         ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant       ON reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_transactions_tenant  ON transactions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant         ON audit_log (tenant_id);

-- Composite indexes for common tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_users_tenant_email   ON users (tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_users_tenant_dept    ON users (tenant_id, department_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_dept  ON reports (tenant_id, department_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_tenant_dept       ON transactions (tenant_id, department_id, transaction_date DESC);


-- ═══════════════════════════════════════════════════════════════
-- 6. REWRITE RLS POLICIES — Tenant Isolation
-- ═══════════════════════════════════════════════════════════════
-- Drop existing policies, then recreate with tenant_id guard.

-- 6a. Reports
DROP POLICY IF EXISTS reports_dept_isolation ON reports;
DROP POLICY IF EXISTS reports_insert ON reports;

CREATE POLICY reports_tenant_dept_isolation ON reports
    FOR SELECT TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::int
        AND (
            current_setting('app.current_user_role', true) = 'admin'
            OR department_id IN (
                SELECT ud.department_id FROM user_departments ud
                WHERE ud.user_id = current_setting('app.current_user_id', true)::int
                UNION
                SELECT u.department_id FROM users u
                WHERE u.id = current_setting('app.current_user_id', true)::int
            )
        )
    );

CREATE POLICY reports_tenant_insert ON reports
    FOR INSERT TO edars_app
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::int
        AND department_id IN (
            SELECT ud.department_id FROM user_departments ud
            WHERE ud.user_id = current_setting('app.current_user_id', true)::int
            UNION
            SELECT u.department_id FROM users u
            WHERE u.id = current_setting('app.current_user_id', true)::int
        )
    );

-- 6b. Transactions
DROP POLICY IF EXISTS transactions_dept_isolation ON transactions;

CREATE POLICY transactions_tenant_dept_isolation ON transactions
    FOR SELECT TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::int
        AND (
            current_setting('app.current_user_role', true) = 'admin'
            OR department_id IN (
                SELECT ud.department_id FROM user_departments ud
                WHERE ud.user_id = current_setting('app.current_user_id', true)::int
                UNION
                SELECT u.department_id FROM users u
                WHERE u.id = current_setting('app.current_user_id', true)::int
            )
        )
    );

-- 6c. Audit Log
DROP POLICY IF EXISTS audit_admin_only ON audit_log;
DROP POLICY IF EXISTS audit_insert_all ON audit_log;

CREATE POLICY audit_tenant_admin_only ON audit_log
    FOR SELECT TO edars_app
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::int
        AND current_setting('app.current_user_role', true) = 'admin'
    );

-- Insert: must match tenant_id from session context
CREATE POLICY audit_tenant_insert ON audit_log
    FOR INSERT TO edars_app
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::int
    );


-- ═══════════════════════════════════════════════════════════════
-- 7. USAGE METERING TABLE
-- ═══════════════════════════════════════════════════════════════
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'usage_event_type') THEN
        CREATE TYPE usage_event_type AS ENUM (
            'api_call', 'report_generated', 'nlq_query', 'user_invited',
            'export_requested', 'login', 'data_pipeline_run'
        );
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS usage_events (
    id              BIGSERIAL,
    tenant_id       INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         INT REFERENCES users(id) ON DELETE SET NULL,
    event_type      usage_event_type NOT NULL,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- usage_events partitions
DO $$ BEGIN
    CREATE TABLE IF NOT EXISTS usage_events_2026_q1 PARTITION OF usage_events
        FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TABLE IF NOT EXISTS usage_events_2026_q2 PARTITION OF usage_events
        FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TABLE IF NOT EXISTS usage_events_2026_q3 PARTITION OF usage_events
        FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TABLE IF NOT EXISTS usage_events_2026_q4 PARTITION OF usage_events
        FOR VALUES FROM ('2026-10-01') TO ('2027-01-01');
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_usage_tenant     ON usage_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_type       ON usage_events (event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_type ON usage_events (tenant_id, event_type, created_at DESC);

-- Grant permissions
GRANT SELECT, INSERT ON usage_events TO edars_app;
GRANT USAGE ON SEQUENCE usage_events_id_seq TO edars_app;
GRANT SELECT, INSERT, UPDATE ON tenants TO edars_app;
GRANT USAGE ON SEQUENCE tenants_id_seq TO edars_app;


-- ═══════════════════════════════════════════════════════════════
-- 8. TENANT PROVISIONING PROCEDURE
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION create_tenant(
    p_name      VARCHAR,
    p_slug      VARCHAR,
    p_plan      tenant_plan DEFAULT 'free',
    p_admin_email    VARCHAR DEFAULT NULL,
    p_admin_name     VARCHAR DEFAULT NULL,
    p_admin_password_hash VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    tenant_id   INT,
    tenant_uuid UUID,
    admin_uuid  UUID
) AS $$
DECLARE
    v_tenant_id  INT;
    v_tenant_uuid UUID;
    v_dept_id    INT;
    v_admin_id   INT;
    v_admin_uuid UUID;
BEGIN
    -- Create tenant
    INSERT INTO tenants (name, slug, plan)
    VALUES (p_name, p_slug, p_plan)
    RETURNING id, uuid INTO v_tenant_id, v_tenant_uuid;

    -- Create default department
    INSERT INTO departments (name, description, tenant_id)
    VALUES ('General', 'Default department for ' || p_name, v_tenant_id)
    RETURNING id INTO v_dept_id;

    -- Create admin user if credentials provided
    IF p_admin_email IS NOT NULL AND p_admin_password_hash IS NOT NULL THEN
        INSERT INTO users (email, password_hash, full_name, role, department_id, tenant_id)
        VALUES (
            p_admin_email,
            p_admin_password_hash,
            COALESCE(p_admin_name, 'Tenant Admin'),
            'admin',
            v_dept_id,
            v_tenant_id
        )
        RETURNING id, uuid INTO v_admin_id, v_admin_uuid;

        -- Assign to default department
        INSERT INTO user_departments (user_id, department_id)
        VALUES (v_admin_id, v_dept_id);

        -- Audit the provisioning
        INSERT INTO audit_log (tenant_id, user_id, action, resource_type, resource_id, metadata)
        VALUES (v_tenant_id, v_admin_id, 'TENANT_PROVISIONED', 'tenant', v_tenant_uuid::VARCHAR,
                jsonb_build_object(
                    'tenant_name', p_name,
                    'slug', p_slug,
                    'plan', p_plan::TEXT,
                    'timestamp', NOW()
                ));
    END IF;

    RETURN QUERY SELECT v_tenant_id, v_tenant_uuid, v_admin_uuid;
END;
$$ LANGUAGE plpgsql;


-- ═══════════════════════════════════════════════════════════════
-- 9. USAGE SUMMARY VIEW (for billing)
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_usage_summary AS
SELECT
    t.id AS tenant_id,
    t.name AS tenant_name,
    t.slug,
    t.plan,
    ue.event_type,
    DATE_TRUNC('month', ue.created_at) AS month,
    COUNT(*) AS event_count
FROM tenants t
LEFT JOIN usage_events ue ON ue.tenant_id = t.id
WHERE ue.created_at >= DATE_TRUNC('month', NOW()) - INTERVAL '3 months'
GROUP BY t.id, t.name, t.slug, t.plan, ue.event_type, DATE_TRUNC('month', ue.created_at)
ORDER BY t.id, month DESC, event_count DESC;

GRANT SELECT ON v_usage_summary TO edars_app;
