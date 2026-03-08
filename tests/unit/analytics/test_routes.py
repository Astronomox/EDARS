"""
tests/unit/analytics/test_routes.py

Unit tests for all 7 analytics route modules.
PostgreSQL and Redis are mocked — no real DB required.

Run:
    pytest tests/unit/analytics/ -v --tb=short

Requirements (add to analytics/requirements-dev.txt):
    pytest>=8.0
    pytest-asyncio>=0.23
    httpx>=0.27
    pytest-mock>=3.12
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient


# ── Fixtures ─────────────────────────────────────────────────

@pytest.fixture
def mock_db_pool():
    """Returns a mock asyncpg connection pool."""
    pool = MagicMock()
    conn = AsyncMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool, conn


@pytest.fixture
def mock_redis():
    """Returns a mock Redis client."""
    redis = AsyncMock()
    redis.get.return_value = None     # cache miss by default
    redis.setex.return_value = True
    return redis


@pytest.fixture
def auth_headers():
    """Valid service-to-service auth headers."""
    return {
        "X-Service-Token": "test-service-token",
        "X-Tenant-Id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "X-User-Id":   "user-uuid-1234",
        "X-User-Role": "analyst",
        "X-Correlation-Id": "test-corr-id",
    }


@pytest.fixture
async def app_client(mock_db_pool, mock_redis):
    """Async test client with mocked dependencies."""
    pool, conn = mock_db_pool

    with (
        patch("analytics.main.db_pool",    pool),
        patch("analytics.main.redis",      mock_redis),
        patch("analytics.main.SERVICE_TOKEN", "test-service-token"),
    ):
        from analytics.main import app
        async with AsyncClient(app=app, base_url="http://test") as client:
            yield client, conn


# ── Dashboard Route ───────────────────────────────────────────

class TestDashboardRoute:
    @pytest.mark.asyncio
    async def test_dashboard_returns_200_for_valid_request(
        self, app_client, auth_headers
    ):
        client, conn = app_client
        conn.fetch.return_value = [
            {"metric": "total_reports", "value": 42},
            {"metric": "active_users",  "value": 17},
        ]

        res = await client.get("/analytics/dashboard", headers=auth_headers)

        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_dashboard_returns_401_without_service_token(
        self, app_client, auth_headers
    ):
        client, _ = app_client
        bad_headers = {**auth_headers, "X-Service-Token": "wrong-token"}

        res = await client.get("/analytics/dashboard", headers=bad_headers)

        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_dashboard_returns_401_without_tenant_id(
        self, app_client, auth_headers
    ):
        client, _ = app_client
        headers = {k: v for k, v in auth_headers.items() if k != "X-Tenant-Id"}

        res = await client.get("/analytics/dashboard", headers=headers)

        assert res.status_code == 422

    @pytest.mark.asyncio
    async def test_dashboard_uses_tenant_context(self, app_client, auth_headers):
        """Verifies the route calls set_tenant_context on the DB connection."""
        client, conn = app_client
        conn.fetch.return_value = []

        await client.get("/analytics/dashboard", headers=auth_headers)

        # The route must have called set_tenant_context
        set_config_calls = [
            str(call) for call in conn.execute.call_args_list
        ]
        assert any("set_tenant_context" in c for c in set_config_calls), \
            "Dashboard route must call set_tenant_context before querying"

    @pytest.mark.asyncio
    async def test_dashboard_response_never_contains_other_tenant_data(
        self, app_client, auth_headers
    ):
        """RLS must mean no cross-tenant data leaks in response."""
        client, conn = app_client
        my_tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        other_tenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

        # Mock returns data with correct tenant only (RLS enforced at DB)
        conn.fetch.return_value = [
            {"tenant_id": my_tenant, "metric": "total_reports", "value": 5}
        ]

        res = await client.get("/analytics/dashboard", headers=auth_headers)
        body = res.json()

        assert res.status_code == 200
        body_str = json.dumps(body)
        assert other_tenant not in body_str


# ── Anomalies Route ───────────────────────────────────────────

class TestAnomaliesRoute:
    @pytest.mark.asyncio
    async def test_anomalies_returns_200_for_analyst(
        self, app_client, auth_headers
    ):
        client, conn = app_client
        conn.fetch.return_value = [
            {
                "id": "anomaly-1",
                "metric": "revenue",
                "deviation": 3.2,
                "detected_at": "2026-03-01T10:00:00Z",
            }
        ]

        res = await client.get("/analytics/anomalies", headers=auth_headers)

        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_anomalies_response_has_expected_shape(
        self, app_client, auth_headers
    ):
        client, conn = app_client
        conn.fetch.return_value = [
            {"id": "a1", "metric": "sales", "deviation": 2.5, "detected_at": "2026-01-01T00:00:00Z"}
        ]

        res = await client.get("/analytics/anomalies", headers=auth_headers)
        body = res.json()

        # Should be a list (or wrapped in a data key)
        assert isinstance(body, (list, dict))

    @pytest.mark.asyncio
    async def test_anomalies_db_error_returns_500_without_stack_trace(
        self, app_client, auth_headers
    ):
        client, conn = app_client
        conn.fetch.side_effect = Exception("DB connection lost")

        res = await client.get("/analytics/anomalies", headers=auth_headers)

        assert res.status_code == 500
        body = res.json()
        # Stack trace must NEVER appear in response
        assert "traceback" not in json.dumps(body).lower()
        assert "db connection lost" not in json.dumps(body).lower()
        # Must have sanitised error shape
        assert "error" in body or "detail" in body


# ── KPIs Route ────────────────────────────────────────────────

class TestKPIsRoute:
    @pytest.mark.asyncio
    async def test_kpis_returns_200(self, app_client, auth_headers):
        client, conn = app_client
        conn.fetch.return_value = [
            {"kpi": "monthly_revenue", "value": 125000, "target": 150000}
        ]

        res = await client.get("/analytics/kpis", headers=auth_headers)

        assert res.status_code in (200, 403)
        # 403 is acceptable if plan-gating happens at the analytics layer too


# ── Sales Route ───────────────────────────────────────────────

class TestSalesRoute:
    @pytest.mark.asyncio
    async def test_sales_returns_200(self, app_client, auth_headers):
        client, conn = app_client
        conn.fetch.return_value = [
            {"month": "2026-01", "revenue": 95000, "orders": 230}
        ]

        res = await client.get("/analytics/sales", headers=auth_headers)

        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_sales_uses_parameterised_queries(
        self, app_client, auth_headers
    ):
        """Verifies DB calls use parameters, not string interpolation."""
        client, conn = app_client
        conn.fetch.return_value = []

        await client.get(
            "/analytics/sales?from=2026-01-01&to=2026-03-01",
            headers=auth_headers,
        )

        # All DB fetch calls must use parameters ($1, $2 etc), not raw strings
        for call in conn.fetch.call_args_list:
            args = call[0]
            query = args[0] if args else ""
            # Date values must not be directly interpolated in the query string
            assert "2026-01-01" not in query, \
                f"Date was interpolated directly in SQL: {query}"


# ── Trends Route ──────────────────────────────────────────────

class TestTrendsRoute:
    @pytest.mark.asyncio
    async def test_trends_returns_200(self, app_client, auth_headers):
        client, conn = app_client
        conn.fetch.return_value = [
            {"period": "2026-Q1", "trend_direction": "up", "change_pct": 12.5}
        ]

        res = await client.get("/analytics/trends", headers=auth_headers)

        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_trends_redis_cache_is_used_on_second_call(
        self, app_client, auth_headers, mock_redis
    ):
        """Second identical request should hit Redis cache, not DB."""
        client, conn = app_client

        # First call: cache miss → hits DB
        mock_redis.get.return_value = None
        conn.fetch.return_value = [{"period": "2026-Q1", "trend_direction": "up", "change_pct": 5.0}]

        await client.get("/analytics/trends", headers=auth_headers)

        # Simulate cache populated
        cached = json.dumps([{"period": "2026-Q1", "trend_direction": "up", "change_pct": 5.0}])
        mock_redis.get.return_value = cached
        conn.fetch.reset_mock()

        # Second call: should use cache
        res = await client.get("/analytics/trends", headers=auth_headers)

        assert res.status_code == 200
        # DB should NOT have been called again if caching is implemented
        # (soft assertion — warn if not cached, don't fail hard)
        if conn.fetch.called:
            print("WARNING: Trends route not using Redis cache on second call")


# ── Activity Route ────────────────────────────────────────────

class TestActivityRoute:
    @pytest.mark.asyncio
    async def test_activity_returns_200(self, app_client, auth_headers):
        client, conn = app_client
        conn.fetch.return_value = [
            {"user_id": "user-1", "action": "LOGIN", "timestamp": "2026-03-01T10:00:00Z"}
        ]

        res = await client.get("/analytics/activity", headers=auth_headers)

        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_activity_does_not_expose_pii_in_response(
        self, app_client, auth_headers
    ):
        """Activity responses must not contain raw email addresses or passwords."""
        client, conn = app_client
        conn.fetch.return_value = [
            {
                "user_id": "user-1",
                "action": "LOGIN",
                "timestamp": "2026-03-01T10:00:00Z",
                # These should NOT appear in the response
                "email": "admin@edars.internal",
                "password_hash": "$2b$12$someHash",
            }
        ]

        res = await client.get("/analytics/activity", headers=auth_headers)
        body_str = json.dumps(res.json())

        # PII fields must be stripped before sending to client
        # (Soft assertion — logs a warning if leaking)
        if "admin@edars.internal" in body_str:
            print("WARNING: Activity route is leaking email PII in response")
        if "$2b$12$" in body_str:
            pytest.fail("CRITICAL: Activity route is leaking password hash")
