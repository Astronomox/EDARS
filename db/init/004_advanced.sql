-- ═══════════════════════════════════════════════════════════════
-- EDARS — Materialized Views, Stored Procedures, Advanced Indexes
-- Performance & Intelligence Layer
-- ═══════════════════════════════════════════════════════════════

-- ─── GIN Index on JSONB columns for fast metadata queries ────
CREATE INDEX idx_reports_params_gin      ON reports      USING GIN (parameters);
CREATE INDEX idx_reports_result_gin      ON reports      USING GIN (result_data);
CREATE INDEX idx_transactions_meta_gin   ON transactions USING GIN (metadata);
CREATE INDEX idx_audit_metadata_gin      ON audit_log    USING GIN (metadata);

-- ─── Composite indexes for common query patterns ─────────────
CREATE INDEX idx_reports_dept_status      ON reports (department_id, status, created_at DESC);
CREATE INDEX idx_reports_type_status      ON reports (report_type, status);
CREATE INDEX idx_transactions_dept_date   ON transactions (department_id, transaction_date DESC);
CREATE INDEX idx_transactions_cat_date    ON transactions (category, transaction_date DESC);
CREATE INDEX idx_audit_user_action_date   ON audit_log (user_id, action, created_at DESC);
CREATE INDEX idx_users_active_role        ON users (is_active, role);
CREATE INDEX idx_users_dept_active        ON users (department_id, is_active);

-- ═══════════════════════════════════════════════════════════════
-- MATERIALIZED VIEW: Department Revenue Summary
-- Refreshed periodically; provides sub-millisecond dashboard reads
-- ═══════════════════════════════════════════════════════════════
CREATE MATERIALIZED VIEW mv_department_revenue AS
SELECT
    d.id AS department_id,
    d.name AS department_name,
    COUNT(t.id) AS transaction_count,
    COALESCE(SUM(t.amount), 0) AS total_revenue,
    COALESCE(AVG(t.amount), 0) AS avg_transaction,
    COALESCE(MIN(t.amount), 0) AS min_transaction,
    COALESCE(MAX(t.amount), 0) AS max_transaction,
    COALESCE(SUM(t.amount) FILTER (WHERE t.transaction_date >= DATE_TRUNC('month', NOW())), 0) AS current_month_revenue,
    COALESCE(SUM(t.amount) FILTER (WHERE t.transaction_date >= DATE_TRUNC('quarter', NOW())), 0) AS current_quarter_revenue,
    COUNT(t.id) FILTER (WHERE t.transaction_date >= DATE_TRUNC('month', NOW())) AS current_month_tx_count,
    NOW() AS last_refreshed
FROM departments d
LEFT JOIN transactions t ON t.department_id = d.id
GROUP BY d.id, d.name
ORDER BY total_revenue DESC;

CREATE UNIQUE INDEX idx_mv_dept_rev ON mv_department_revenue (department_id);

-- ═══════════════════════════════════════════════════════════════
-- MATERIALIZED VIEW: User Activity Summary
-- ═══════════════════════════════════════════════════════════════
CREATE MATERIALIZED VIEW mv_user_activity AS
SELECT
    u.id AS user_id,
    u.full_name,
    u.email,
    u.role,
    d.name AS department,
    COUNT(al.id) AS total_actions,
    COUNT(al.id) FILTER (WHERE al.created_at >= NOW() - INTERVAL '7 days') AS actions_7d,
    COUNT(al.id) FILTER (WHERE al.created_at >= NOW() - INTERVAL '30 days') AS actions_30d,
    COUNT(DISTINCT DATE_TRUNC('day', al.created_at)) AS active_days,
    MAX(al.created_at) AS last_action_at,
    NOW() AS last_refreshed
FROM users u
LEFT JOIN audit_log al ON al.user_id = u.id
LEFT JOIN departments d ON d.id = u.department_id
GROUP BY u.id, u.full_name, u.email, u.role, d.name
ORDER BY total_actions DESC;

CREATE UNIQUE INDEX idx_mv_user_act ON mv_user_activity (user_id);

-- ═══════════════════════════════════════════════════════════════
-- MATERIALIZED VIEW: Category Spend Analysis
-- ═══════════════════════════════════════════════════════════════
CREATE MATERIALIZED VIEW mv_category_spend AS
SELECT
    COALESCE(t.category, 'uncategorised') AS category,
    COUNT(*) AS transaction_count,
    SUM(t.amount) AS total_amount,
    AVG(t.amount) AS avg_amount,
    COUNT(DISTINCT t.department_id) AS departments_using,
    MIN(t.transaction_date) AS earliest,
    MAX(t.transaction_date) AS latest,
    NOW() AS last_refreshed
FROM transactions t
GROUP BY t.category
ORDER BY total_amount DESC;

-- ═══════════════════════════════════════════════════════════════
-- STORED PROCEDURE: Refresh All Materialized Views
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION refresh_all_materialized_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_department_revenue;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_user_activity;
    REFRESH MATERIALIZED VIEW mv_category_spend;
    RAISE NOTICE 'All materialized views refreshed at %', NOW();
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- STORED PROCEDURE: Generate Partition for Next Quarter
-- Automatically creates the next quarter's partitions
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION create_next_quarter_partitions()
RETURNS void AS $$
DECLARE
    next_q_start DATE;
    next_q_end   DATE;
    q_label      TEXT;
    year_str     TEXT;
BEGIN
    -- Calculate next quarter start
    next_q_start := DATE_TRUNC('quarter', NOW()) + INTERVAL '3 months';
    next_q_end   := next_q_start + INTERVAL '3 months';
    year_str     := EXTRACT(YEAR FROM next_q_start)::TEXT;
    q_label      := year_str || '_q' || EXTRACT(QUARTER FROM next_q_start)::TEXT;

    -- Create partitions for each partitioned table
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS reports_%s PARTITION OF reports FOR VALUES FROM (%L) TO (%L)',
        q_label, next_q_start, next_q_end
    );
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS transactions_%s PARTITION OF transactions FOR VALUES FROM (%L) TO (%L)',
        q_label, next_q_start, next_q_end
    );
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
        q_label, next_q_start, next_q_end
    );

    RAISE NOTICE 'Created partitions for quarter: % (% to %)', q_label, next_q_start, next_q_end;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- STORED PROCEDURE: User Login Audit (atomic)
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION record_login(
    p_user_id INT,
    p_ip_address INET,
    p_user_agent TEXT
)
RETURNS void AS $$
BEGIN
    -- Update last login
    UPDATE users SET last_login_at = NOW() WHERE id = p_user_id;

    -- Write audit entry
    INSERT INTO audit_log (user_id, action, resource_type, ip_address, user_agent, metadata)
    VALUES (p_user_id, 'LOGIN', 'auth', p_ip_address, p_user_agent,
            jsonb_build_object('timestamp', NOW(), 'method', 'password'));
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- STORED PROCEDURE: Department Health Score
-- Composite metric combining activity, report completion, and revenue
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION calculate_department_health(p_department_id INT)
RETURNS TABLE (
    department_name TEXT,
    health_score    NUMERIC,
    headcount       BIGINT,
    active_ratio    NUMERIC,
    report_completion_rate NUMERIC,
    revenue_rank    BIGINT,
    activity_score  NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    WITH dept_metrics AS (
        SELECT
            d.name::TEXT AS dept_name,
            (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id) AS total_users,
            (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id AND u.is_active = TRUE) AS active_users,
            (SELECT COUNT(*) FROM reports r WHERE r.department_id = d.id) AS total_reports,
            (SELECT COUNT(*) FROM reports r WHERE r.department_id = d.id AND r.status = 'completed') AS completed_reports,
            (SELECT COALESCE(SUM(t.amount), 0) FROM transactions t WHERE t.department_id = d.id) AS revenue,
            (SELECT COUNT(*) FROM audit_log al JOIN users u ON u.id = al.user_id WHERE u.department_id = d.id AND al.created_at > NOW() - INTERVAL '30 days') AS recent_actions
        FROM departments d
        WHERE d.id = p_department_id
    )
    SELECT
        dm.dept_name,
        -- Health score: weighted composite (0–100)
        ROUND(
            (CASE WHEN dm.total_users > 0 THEN (dm.active_users::NUMERIC / dm.total_users) * 25 ELSE 0 END) +
            (CASE WHEN dm.total_reports > 0 THEN (dm.completed_reports::NUMERIC / dm.total_reports) * 35 ELSE 0 END) +
            (LEAST(dm.recent_actions::NUMERIC / GREATEST(dm.active_users, 1) / 10, 1.0) * 40),
            1
        ) AS health_score,
        dm.active_users,
        ROUND(CASE WHEN dm.total_users > 0 THEN dm.active_users::NUMERIC / dm.total_users * 100 ELSE 0 END, 1),
        ROUND(CASE WHEN dm.total_reports > 0 THEN dm.completed_reports::NUMERIC / dm.total_reports * 100 ELSE 0 END, 1),
        RANK() OVER (ORDER BY dm.revenue DESC),
        ROUND(LEAST(dm.recent_actions::NUMERIC / GREATEST(dm.active_users, 1) / 10, 1.0) * 100, 1)
    FROM dept_metrics dm;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- STORED PROCEDURE: Anomaly Detection — Spending Outliers
-- Identifies transactions > 2 standard deviations from the category mean
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION detect_spending_anomalies(p_lookback_days INT DEFAULT 90)
RETURNS TABLE (
    transaction_uuid UUID,
    department       TEXT,
    amount           NUMERIC,
    category         VARCHAR,
    category_avg     NUMERIC,
    category_stddev  NUMERIC,
    z_score          NUMERIC,
    transaction_date TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    WITH category_stats AS (
        SELECT
            t.category,
            AVG(t.amount) AS avg_amount,
            STDDEV(t.amount) AS stddev_amount
        FROM transactions t
        WHERE t.transaction_date > NOW() - (p_lookback_days || ' days')::INTERVAL
        GROUP BY t.category
        HAVING COUNT(*) > 2 AND STDDEV(t.amount) > 0
    )
    SELECT
        t.uuid,
        d.name::TEXT,
        t.amount,
        t.category,
        ROUND(cs.avg_amount, 2),
        ROUND(cs.stddev_amount, 2),
        ROUND((t.amount - cs.avg_amount) / cs.stddev_amount, 2) AS z_score,
        t.transaction_date
    FROM transactions t
    JOIN departments d ON d.id = t.department_id
    JOIN category_stats cs ON cs.category = t.category
    WHERE ABS((t.amount - cs.avg_amount) / cs.stddev_amount) > 2
    ORDER BY z_score DESC;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- SCHEDULED TASK HELPER: Cleanup old sessions from Redis
-- (called externally by cron / pg_cron if available)
-- ═══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION get_inactive_users(p_days INT DEFAULT 90)
RETURNS TABLE (
    user_uuid  UUID,
    email      VARCHAR,
    full_name  VARCHAR,
    role       user_role,
    last_login TIMESTAMPTZ,
    days_inactive INT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.uuid,
        u.email,
        u.full_name,
        u.role,
        u.last_login_at,
        EXTRACT(DAY FROM NOW() - COALESCE(u.last_login_at, u.created_at))::INT
    FROM users u
    WHERE u.is_active = TRUE
      AND COALESCE(u.last_login_at, u.created_at) < NOW() - (p_days || ' days')::INTERVAL
    ORDER BY u.last_login_at ASC NULLS FIRST;
END;
$$ LANGUAGE plpgsql;
