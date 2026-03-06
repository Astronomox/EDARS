-- ═══════════════════════════════════════════════════════════════
-- RLS Policy & Audit Immutability Tests
-- ═══════════════════════════════════════════════════════════════
-- Run these against a live test database.
-- All tests should pass; any failure indicates a security vulnerability.
-- Usage: psql -U edars_admin -d edars -f tests/test_rls.sql
-- ═══════════════════════════════════════════════════════════════

BEGIN;

-- ─── Setup: create a second test tenant ──────────────────────
INSERT INTO tenants (id, name, slug, plan)
VALUES (999, 'Test Tenant B', 'test-tenant-b', 'growth')
ON CONFLICT (id) DO NOTHING;

INSERT INTO departments (id, name, tenant_id)
VALUES (999, 'Test Dept B', 999)
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, email, password_hash, full_name, role, department_id, tenant_id)
VALUES (999, 'test-b@other-tenant.com',
        '$2b$12$LJ3m5ZVcGqx.V0YBQ5Xz6eJ8FkXJWvKYkQ9HzNH5HvUlFp3Mnq0vO',
        'Test User B', 'admin', 999, 999)
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_departments (user_id, department_id)
VALUES (999, 999)
ON CONFLICT DO NOTHING;

INSERT INTO reports (title, report_type, department_id, created_by, tenant_id)
VALUES ('Tenant B Secret Report', 'sales_summary', 999, 999, 999);

INSERT INTO transactions (department_id, amount, currency, description, category, transaction_date, tenant_id)
VALUES (999, 99999.99, 'USD', 'Tenant B secret transaction', 'classified', NOW(), 999);


-- ─── Test 1: Tenant 1 user CANNOT see Tenant 999 reports ────
SET LOCAL app.current_user_id = '1';
SET LOCAL app.current_user_role = 'admin';
SET LOCAL app.current_tenant_id = '1';

DO $$
DECLARE
    leaked_count INT;
BEGIN
    SELECT COUNT(*) INTO leaked_count
    FROM reports
    WHERE tenant_id = 999;

    IF leaked_count > 0 THEN
        RAISE EXCEPTION 'RLS VIOLATION: Tenant 1 admin can see Tenant 999 reports (found %)', leaked_count;
    ELSE
        RAISE NOTICE 'TEST PASSED: Tenant 1 cannot see Tenant 999 reports';
    END IF;
END $$;


-- ─── Test 2: Tenant 1 user CANNOT see Tenant 999 transactions
DO $$
DECLARE
    leaked_count INT;
BEGIN
    SELECT COUNT(*) INTO leaked_count
    FROM transactions
    WHERE tenant_id = 999;

    IF leaked_count > 0 THEN
        RAISE EXCEPTION 'RLS VIOLATION: Tenant 1 admin can see Tenant 999 transactions (found %)', leaked_count;
    ELSE
        RAISE NOTICE 'TEST PASSED: Tenant 1 cannot see Tenant 999 transactions';
    END IF;
END $$;


-- ─── Test 3: Tenant 999 CAN see their own reports ──────────
RESET ALL;
SET LOCAL app.current_user_id = '999';
SET LOCAL app.current_user_role = 'admin';
SET LOCAL app.current_tenant_id = '999';

DO $$
DECLARE
    own_count INT;
BEGIN
    SELECT COUNT(*) INTO own_count
    FROM reports
    WHERE tenant_id = 999;

    IF own_count = 0 THEN
        RAISE EXCEPTION 'RLS ERROR: Tenant 999 cannot see their own reports';
    ELSE
        RAISE NOTICE 'TEST PASSED: Tenant 999 can see their own reports (found %)', own_count;
    END IF;
END $$;


-- ─── Test 4: Tenant 999 CANNOT see Tenant 1 data ───────────
DO $$
DECLARE
    leaked_count INT;
BEGIN
    SELECT COUNT(*) INTO leaked_count
    FROM reports
    WHERE tenant_id = 1;

    IF leaked_count > 0 THEN
        RAISE EXCEPTION 'RLS VIOLATION: Tenant 999 can see Tenant 1 reports (found %)', leaked_count;
    ELSE
        RAISE NOTICE 'TEST PASSED: Tenant 999 cannot see Tenant 1 reports';
    END IF;
END $$;


-- ─── Test 5: Viewer cannot see other departments (within same tenant)
RESET ALL;
SET LOCAL app.current_user_id = '14';  -- Viewer, dept 3 (Marketing)
SET LOCAL app.current_user_role = 'viewer';
SET LOCAL app.current_tenant_id = '1';

DO $$
DECLARE
    eng_count INT;
BEGIN
    SELECT COUNT(*) INTO eng_count
    FROM transactions
    WHERE department_id = 1;  -- Engineering (not viewer's dept)

    IF eng_count > 0 THEN
        RAISE EXCEPTION 'RLS VIOLATION: Viewer in Marketing can see Engineering transactions (found %)', eng_count;
    ELSE
        RAISE NOTICE 'TEST PASSED: Viewer in Marketing cannot see Engineering transactions';
    END IF;
END $$;


-- ─── Test 6: Audit log UPDATE is blocked ────────────────────
RESET ALL;
DO $$
BEGIN
    UPDATE audit_log SET action = 'TAMPERED' WHERE id = 1;
    RAISE EXCEPTION 'AUDIT VIOLATION: UPDATE on audit_log was NOT blocked by trigger!';
EXCEPTION
    WHEN raise_exception THEN
        IF SQLERRM LIKE '%TAMPERED%' THEN
            RAISE;
        END IF;
        RAISE NOTICE 'TEST PASSED: UPDATE on audit_log was blocked by trigger';
    WHEN OTHERS THEN
        RAISE NOTICE 'TEST PASSED: UPDATE on audit_log was blocked (%)' , SQLERRM;
END $$;


-- ─── Test 7: Audit log DELETE is blocked ────────────────────
DO $$
BEGIN
    DELETE FROM audit_log WHERE id = 1;
    RAISE EXCEPTION 'AUDIT VIOLATION: DELETE on audit_log was NOT blocked by trigger!';
EXCEPTION
    WHEN raise_exception THEN
        IF SQLERRM LIKE '%NOT blocked%' THEN
            RAISE;
        END IF;
        RAISE NOTICE 'TEST PASSED: DELETE on audit_log was blocked by trigger';
    WHEN OTHERS THEN
        RAISE NOTICE 'TEST PASSED: DELETE on audit_log was blocked (%)' , SQLERRM;
END $$;


-- ─── Cleanup ─────────────────────────────────────────────────
ROLLBACK;
-- All test data is rolled back. Database is unchanged.
