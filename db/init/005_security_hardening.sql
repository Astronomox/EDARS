-- ═══════════════════════════════════════════════════════════════
-- EDARS — Security Hardening Layer
-- ═══════════════════════════════════════════════════════════════
-- Column-level encryption, PII masking, session management,
-- audit chain integrity, failed login tracking, IP blocking
-- ═══════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════════════════════════════
-- 1. ENCRYPTION KEY MANAGEMENT
-- ═══════════════════════════════════════════════════════════════
-- Uses pgcrypto for AES-256 symmetric encryption of sensitive fields.
-- The encryption key is passed via session variable, never stored in DB.

CREATE OR REPLACE FUNCTION encrypt_pii(plaintext TEXT, encryption_key TEXT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(plaintext, encryption_key, 'cipher-algo=aes256');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION decrypt_pii(ciphertext BYTEA, encryption_key TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(ciphertext, encryption_key);
EXCEPTION
    WHEN OTHERS THEN
        RETURN '[ENCRYPTED]';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- ═══════════════════════════════════════════════════════════════
-- 2. PII DATA MASKING VIEWS
-- ═══════════════════════════════════════════════════════════════
-- Partial masking for non-admin users. Admins see full data.

CREATE OR REPLACE FUNCTION mask_email(email VARCHAR)
RETURNS TEXT AS $$
DECLARE
    at_pos INT;
    local_part TEXT;
    domain TEXT;
BEGIN
    at_pos := POSITION('@' IN email);
    IF at_pos <= 0 THEN RETURN '***@***'; END IF;

    local_part := LEFT(email, at_pos - 1);
    domain := SUBSTRING(email FROM at_pos);

    IF LENGTH(local_part) <= 2 THEN
        RETURN '*' || domain;
    END IF;

    RETURN LEFT(local_part, 2) || REPEAT('*', LENGTH(local_part) - 2) || domain;
END;
$$ LANGUAGE plpgsql IMMUTABLE;


CREATE OR REPLACE FUNCTION mask_name(full_name VARCHAR)
RETURNS TEXT AS $$
DECLARE
    parts TEXT[];
BEGIN
    parts := string_to_array(full_name, ' ');
    IF array_length(parts, 1) IS NULL THEN RETURN '***'; END IF;

    RETURN LEFT(parts[1], 1) || '. ' ||
           CASE WHEN array_length(parts, 1) > 1
                THEN LEFT(parts[array_length(parts, 1)], 1) || '.'
                ELSE ''
           END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- PII-masked user view (non-admin sees masked data)
CREATE OR REPLACE VIEW v_users_masked AS
SELECT
    u.id,
    u.uuid,
    CASE
        WHEN current_setting('app.current_user_role', true) = 'admin'
            THEN u.email
        ELSE mask_email(u.email)
    END AS email,
    CASE
        WHEN current_setting('app.current_user_role', true) = 'admin'
            THEN u.full_name
        ELSE mask_name(u.full_name)
    END AS full_name,
    u.role,
    u.department_id,
    u.is_active,
    u.last_login_at,
    u.created_at
FROM users u;


-- ═══════════════════════════════════════════════════════════════
-- 3. SESSION MANAGEMENT (Device Fingerprinting)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS user_sessions (
    id              SERIAL PRIMARY KEY,
    uuid            UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
    user_id         INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash    VARCHAR(128) NOT NULL,
    device_fingerprint VARCHAR(64),
    ip_address      INET NOT NULL,
    user_agent      TEXT,
    geo_country     VARCHAR(3),
    geo_city        VARCHAR(128),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '8 hours'),
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(64)
);

CREATE INDEX idx_sessions_user ON user_sessions (user_id, is_active);
CREATE INDEX idx_sessions_hash ON user_sessions (session_hash);
CREATE INDEX idx_sessions_expires ON user_sessions (expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_device ON user_sessions (device_fingerprint);

-- Auto-expire sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INT AS $$
DECLARE
    expired_count INT;
BEGIN
    UPDATE user_sessions
    SET is_active = FALSE,
        revoked_at = NOW(),
        revoked_reason = 'expired'
    WHERE is_active = TRUE
      AND expires_at < NOW();

    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;


-- Concurrent session limit (max 5 active sessions per user)
CREATE OR REPLACE FUNCTION enforce_session_limit()
RETURNS TRIGGER AS $$
DECLARE
    active_count INT;
    oldest_session_id INT;
BEGIN
    SELECT COUNT(*) INTO active_count
    FROM user_sessions
    WHERE user_id = NEW.user_id AND is_active = TRUE;

    -- If over limit, revoke the oldest session
    IF active_count >= 5 THEN
        SELECT id INTO oldest_session_id
        FROM user_sessions
        WHERE user_id = NEW.user_id AND is_active = TRUE
        ORDER BY created_at ASC
        LIMIT 1;

        UPDATE user_sessions
        SET is_active = FALSE,
            revoked_at = NOW(),
            revoked_reason = 'session_limit'
        WHERE id = oldest_session_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_session_limit
    AFTER INSERT ON user_sessions
    FOR EACH ROW EXECUTE FUNCTION enforce_session_limit();


-- ═══════════════════════════════════════════════════════════════
-- 4. FAILED LOGIN TRACKING & AUTO IP BLOCKING
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS failed_logins (
    id              SERIAL PRIMARY KEY,
    ip_address      INET NOT NULL,
    email_attempted VARCHAR(255),
    user_agent      TEXT,
    failure_reason  VARCHAR(64) NOT NULL DEFAULT 'invalid_credentials',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_failed_logins_ip ON failed_logins (ip_address, created_at DESC);
CREATE INDEX idx_failed_logins_email ON failed_logins (email_attempted, created_at DESC);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id              SERIAL PRIMARY KEY,
    ip_address      INET NOT NULL UNIQUE,
    reason          TEXT NOT NULL,
    blocked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    is_permanent    BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts INT DEFAULT 0,
    metadata        JSONB DEFAULT '{}'
);

CREATE INDEX idx_blocked_ips ON blocked_ips (ip_address);
CREATE INDEX idx_blocked_ips_expires ON blocked_ips (expires_at) WHERE NOT is_permanent;


-- Auto-block IPs with excessive failures (>20 in 1 hour)
CREATE OR REPLACE FUNCTION auto_block_ip()
RETURNS TRIGGER AS $$
DECLARE
    recent_failures INT;
BEGIN
    SELECT COUNT(*) INTO recent_failures
    FROM failed_logins
    WHERE ip_address = NEW.ip_address
      AND created_at > NOW() - INTERVAL '1 hour';

    IF recent_failures >= 20 THEN
        INSERT INTO blocked_ips (ip_address, reason, expires_at, failed_attempts)
        VALUES (NEW.ip_address, 'auto_blocked: excessive login failures', NOW() + INTERVAL '24 hours', recent_failures)
        ON CONFLICT (ip_address) DO UPDATE SET
            expires_at = NOW() + INTERVAL '24 hours',
            failed_attempts = blocked_ips.failed_attempts + 1,
            -- Escalate to permanent after 3 auto-blocks
            is_permanent = CASE WHEN blocked_ips.failed_attempts >= 3 THEN TRUE ELSE FALSE END;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auto_block_ip
    AFTER INSERT ON failed_logins
    FOR EACH ROW EXECUTE FUNCTION auto_block_ip();


-- Check if IP is blocked
CREATE OR REPLACE FUNCTION is_ip_blocked(check_ip INET)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM blocked_ips
        WHERE ip_address = check_ip
          AND (is_permanent = TRUE OR expires_at > NOW())
    );
END;
$$ LANGUAGE plpgsql;


-- ═══════════════════════════════════════════════════════════════
-- 5. AUDIT LOG INTEGRITY — CRYPTOGRAPHIC HASH CHAIN
-- ═══════════════════════════════════════════════════════════════
-- Each audit entry includes a hash of the previous entry,
-- creating a tamper-evident blockchain-style chain.

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS integrity_hash VARCHAR(128);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(128);

CREATE OR REPLACE FUNCTION compute_audit_chain_hash()
RETURNS TRIGGER AS $$
DECLARE
    last_hash VARCHAR(128);
    hash_input TEXT;
BEGIN
    -- Get previous entry's hash
    SELECT integrity_hash INTO last_hash
    FROM audit_log
    ORDER BY created_at DESC, id DESC
    LIMIT 1;

    IF last_hash IS NULL THEN
        last_hash := 'GENESIS';
    END IF;

    NEW.prev_hash := last_hash;

    -- Compute hash of current entry + previous hash
    hash_input := COALESCE(NEW.user_id::TEXT, 'null') || '|' ||
                  NEW.action || '|' ||
                  NEW.resource_type || '|' ||
                  COALESCE(NEW.resource_id, 'null') || '|' ||
                  COALESCE(host(NEW.ip_address), 'null') || '|' ||
                  NEW.created_at::TEXT || '|' ||
                  last_hash;

    NEW.integrity_hash := encode(digest(hash_input, 'sha256'), 'hex');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_chain_hash
    BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION compute_audit_chain_hash();


-- Verify audit chain integrity
CREATE OR REPLACE FUNCTION verify_audit_chain(p_limit INT DEFAULT 1000)
RETURNS TABLE (
    entry_id INT,
    entry_action VARCHAR,
    expected_prev_hash VARCHAR,
    actual_prev_hash VARCHAR,
    chain_valid BOOLEAN
) AS $$
DECLARE
    rec RECORD;
    prev_hash VARCHAR := 'GENESIS';
BEGIN
    FOR rec IN
        SELECT a.id, a.action, a.prev_hash, a.integrity_hash
        FROM audit_log a
        ORDER BY a.created_at ASC, a.id ASC
        LIMIT p_limit
    LOOP
        entry_id := rec.id;
        entry_action := rec.action;
        expected_prev_hash := prev_hash;
        actual_prev_hash := rec.prev_hash;
        chain_valid := (rec.prev_hash = prev_hash);
        prev_hash := rec.integrity_hash;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;


-- ═══════════════════════════════════════════════════════════════
-- 6. SECURITY REPORTING FUNCTIONS
-- ═══════════════════════════════════════════════════════════════

-- Security dashboard: failed logins per hour over last 24h
CREATE OR REPLACE FUNCTION security_failed_login_timeline(p_hours INT DEFAULT 24)
RETURNS TABLE (
    hour TIMESTAMPTZ,
    failure_count BIGINT,
    unique_ips BIGINT,
    unique_emails BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        DATE_TRUNC('hour', fl.created_at) AS hour,
        COUNT(*) AS failure_count,
        COUNT(DISTINCT fl.ip_address) AS unique_ips,
        COUNT(DISTINCT fl.email_attempted) AS unique_emails
    FROM failed_logins fl
    WHERE fl.created_at > NOW() - (p_hours || ' hours')::INTERVAL
    GROUP BY DATE_TRUNC('hour', fl.created_at)
    ORDER BY hour DESC;
END;
$$ LANGUAGE plpgsql;


-- Top targeted accounts
CREATE OR REPLACE FUNCTION security_targeted_accounts(p_hours INT DEFAULT 24, p_limit INT DEFAULT 20)
RETURNS TABLE (
    email VARCHAR,
    attempt_count BIGINT,
    distinct_ips BIGINT,
    first_attempt TIMESTAMPTZ,
    last_attempt TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        fl.email_attempted,
        COUNT(*) AS attempt_count,
        COUNT(DISTINCT fl.ip_address) AS distinct_ips,
        MIN(fl.created_at) AS first_attempt,
        MAX(fl.created_at) AS last_attempt
    FROM failed_logins fl
    WHERE fl.created_at > NOW() - (p_hours || ' hours')::INTERVAL
    GROUP BY fl.email_attempted
    ORDER BY attempt_count DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;


-- Active sessions summary
CREATE OR REPLACE FUNCTION security_active_sessions_summary()
RETURNS TABLE (
    total_active BIGINT,
    unique_users BIGINT,
    unique_ips BIGINT,
    avg_session_age_hours NUMERIC,
    sessions_expiring_soon BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*),
        COUNT(DISTINCT user_id),
        COUNT(DISTINCT ip_address),
        ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600)::NUMERIC, 1),
        COUNT(*) FILTER (WHERE expires_at < NOW() + INTERVAL '1 hour')
    FROM user_sessions
    WHERE is_active = TRUE;
END;
$$ LANGUAGE plpgsql;


-- ═══════════════════════════════════════════════════════════════
-- 7. GRANT PERMISSIONS
-- ═══════════════════════════════════════════════════════════════
GRANT SELECT, INSERT ON user_sessions TO edars_app;
GRANT SELECT, INSERT ON failed_logins TO edars_app;
GRANT SELECT ON blocked_ips TO edars_app;
GRANT SELECT ON v_users_masked TO edars_app;
GRANT USAGE ON SEQUENCE user_sessions_id_seq TO edars_app;
GRANT USAGE ON SEQUENCE failed_logins_id_seq TO edars_app;
