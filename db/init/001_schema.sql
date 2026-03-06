-- ═══════════════════════════════════════════════════════════════
-- EDARS — Enterprise Data Analytics & Reporting System
-- Database Schema v1.0  |  PostgreSQL 16
-- ═══════════════════════════════════════════════════════════════
-- Executed automatically by docker-entrypoint-initdb.d on first run.

-- ─── Extensions ──────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── ENUM Types ──────────────────────────────────────────────
CREATE TYPE user_role AS ENUM ('viewer', 'analyst', 'manager', 'admin');
CREATE TYPE report_status AS ENUM ('pending', 'processing', 'completed', 'failed');
CREATE TYPE report_type AS ENUM ('sales_summary', 'user_activity', 'department_kpis');

-- ═══════════════════════════════════════════════════════════════
-- TABLE: departments
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE departments (
    id              SERIAL PRIMARY KEY,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_departments_uuid ON departments (uuid);

-- ═══════════════════════════════════════════════════════════════
-- TABLE: users
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    full_name       VARCHAR(255) NOT NULL,
    role            user_role NOT NULL DEFAULT 'viewer',
    department_id   INT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_uuid ON users (uuid);
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_department ON users (department_id);
CREATE INDEX idx_users_role ON users (role);

-- ═══════════════════════════════════════════════════════════════
-- TABLE: user_departments (many-to-many for managers)
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE user_departments (
    user_id         INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    department_id   INT NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, department_id)
);

-- ═══════════════════════════════════════════════════════════════
-- TABLE: reports  (partitioned by quarter)
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE reports (
    id              SERIAL,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4(),
    title           VARCHAR(255) NOT NULL,
    report_type     report_type NOT NULL,
    status          report_status NOT NULL DEFAULT 'pending',
    parameters      JSONB DEFAULT '{}',
    result_data     JSONB,
    department_id   INT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
    created_by      INT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX idx_reports_uuid ON reports (uuid);
CREATE INDEX idx_reports_department ON reports (department_id);
CREATE INDEX idx_reports_created_by ON reports (created_by);
CREATE INDEX idx_reports_status ON reports (status);
CREATE INDEX idx_reports_type ON reports (report_type);

-- Quarterly partitions (2025–2026)
CREATE TABLE reports_2025_q1 PARTITION OF reports FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE reports_2025_q2 PARTITION OF reports FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE reports_2025_q3 PARTITION OF reports FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE reports_2025_q4 PARTITION OF reports FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE reports_2026_q1 PARTITION OF reports FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');
CREATE TABLE reports_2026_q2 PARTITION OF reports FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
CREATE TABLE reports_2026_q3 PARTITION OF reports FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');
CREATE TABLE reports_2026_q4 PARTITION OF reports FOR VALUES FROM ('2026-10-01') TO ('2027-01-01');

-- ═══════════════════════════════════════════════════════════════
-- TABLE: transactions (partitioned by quarter)
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE transactions (
    id              SERIAL,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4(),
    department_id   INT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
    amount          NUMERIC(15, 2) NOT NULL,
    currency        VARCHAR(3) NOT NULL DEFAULT 'USD',
    description     TEXT,
    category        VARCHAR(128),
    metadata        JSONB DEFAULT '{}',
    transaction_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX idx_transactions_uuid ON transactions (uuid);
CREATE INDEX idx_transactions_department ON transactions (department_id);
CREATE INDEX idx_transactions_date ON transactions (transaction_date);
CREATE INDEX idx_transactions_category ON transactions (category);

CREATE TABLE transactions_2025_q1 PARTITION OF transactions FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE transactions_2025_q2 PARTITION OF transactions FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE transactions_2025_q3 PARTITION OF transactions FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE transactions_2025_q4 PARTITION OF transactions FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE transactions_2026_q1 PARTITION OF transactions FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');
CREATE TABLE transactions_2026_q2 PARTITION OF transactions FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
CREATE TABLE transactions_2026_q3 PARTITION OF transactions FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');
CREATE TABLE transactions_2026_q4 PARTITION OF transactions FOR VALUES FROM ('2026-10-01') TO ('2027-01-01');

-- ═══════════════════════════════════════════════════════════════
-- TABLE: audit_log (partitioned, append-only)
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE audit_log (
    id              SERIAL,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4(),
    user_id         INT REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(64) NOT NULL,
    resource_type   VARCHAR(64) NOT NULL,
    resource_id     VARCHAR(128),
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX idx_audit_user ON audit_log (user_id);
CREATE INDEX idx_audit_action ON audit_log (action);
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_id);
CREATE INDEX idx_audit_created ON audit_log (created_at);

CREATE TABLE audit_log_2025_q1 PARTITION OF audit_log FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE audit_log_2025_q2 PARTITION OF audit_log FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE audit_log_2025_q3 PARTITION OF audit_log FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE audit_log_2025_q4 PARTITION OF audit_log FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE audit_log_2026_q1 PARTITION OF audit_log FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');
CREATE TABLE audit_log_2026_q2 PARTITION OF audit_log FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
CREATE TABLE audit_log_2026_q3 PARTITION OF audit_log FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');
CREATE TABLE audit_log_2026_q4 PARTITION OF audit_log FOR VALUES FROM ('2026-10-01') TO ('2027-01-01');

-- ═══════════════════════════════════════════════════════════════
-- IMMUTABLE AUDIT LOG — Prevent UPDATE and DELETE
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log records are immutable. UPDATE and DELETE are prohibited.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

CREATE TRIGGER trg_audit_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

-- ═══════════════════════════════════════════════════════════════
-- AUTO-UPDATE updated_at TRIGGER
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_departments_updated_at
    BEFORE UPDATE ON departments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
