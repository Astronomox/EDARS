# ═══════════════════════════════════════════════════════════════
# Trend Analysis Endpoint
# Month-over-month growth, rolling averages, forecasting
# ═══════════════════════════════════════════════════════════════
import logging
from fastapi import APIRouter, Query, Request
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.trends")
router = APIRouter()


@router.get("/trends/revenue")
async def revenue_trends(
    request: Request,
    userId: int = Query(...),
    role: str = Query(...),
    departmentId: int = Query(None),
    months: int = Query(12, ge=3, le=36),
):
    """
    Revenue trend analysis with:
    - Monthly revenue totals
    - Month-over-month growth rate
    - 3-month rolling average
    - Linear trend direction
    """
    # Check cache
    cache_key = f"trends:revenue:{departmentId or 'all'}:{months}"
    cached = request.app.state.cache.get(cache_key)
    if cached:
        return cached

    conn = get_connection()
    try:
        cur = conn.cursor()

        dept_filter = ""
        params = [months]
        if role != "admin" and departmentId:
            dept_filter = "AND t.department_id = %s"
            params.append(departmentId)

        cur.execute(f"""
            WITH monthly AS (
                SELECT
                    DATE_TRUNC('month', t.transaction_date)::date AS month,
                    SUM(t.amount) AS revenue,
                    COUNT(*) AS tx_count
                FROM transactions t
                WHERE t.transaction_date > NOW() - INTERVAL '%s months'
                {dept_filter}
                GROUP BY month
                ORDER BY month
            ),
            with_growth AS (
                SELECT
                    month,
                    revenue,
                    tx_count,
                    LAG(revenue) OVER (ORDER BY month) AS prev_revenue,
                    AVG(revenue) OVER (ORDER BY month ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS rolling_avg_3m
                FROM monthly
            )
            SELECT
                month,
                revenue,
                tx_count,
                prev_revenue,
                CASE
                    WHEN prev_revenue > 0 THEN ROUND(((revenue - prev_revenue) / prev_revenue) * 100, 2)
                    ELSE NULL
                END AS growth_pct,
                ROUND(rolling_avg_3m, 2) AS rolling_avg_3m
            FROM with_growth
        """, params)

        rows = cur.fetchall()
        monthly_data = []
        revenues = []
        for r in rows:
            monthly_data.append({
                "month": str(r[0]),
                "revenue": float(r[1]),
                "transactionCount": r[2],
                "previousRevenue": float(r[3]) if r[3] else None,
                "growthPercent": float(r[4]) if r[4] is not None else None,
                "rollingAvg3m": float(r[5]) if r[5] else None,
            })
            revenues.append(float(r[1]))

        # Calculate linear trend direction
        trend = "stable"
        if len(revenues) >= 3:
            recent_avg = sum(revenues[-3:]) / 3
            earlier_avg = sum(revenues[:3]) / 3
            if recent_avg > earlier_avg * 1.1:
                trend = "upward"
            elif recent_avg < earlier_avg * 0.9:
                trend = "downward"

        result = {
            "months": monthly_data,
            "trend": trend,
            "periodMonths": months,
            "totalRevenue": sum(revenues),
            "avgMonthlyRevenue": round(sum(revenues) / max(len(revenues), 1), 2),
        }

        request.app.state.cache.set(cache_key, result, ttl_seconds=600)
        return result
    except Exception as e:
        logger.error(f"Revenue trend query failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)


@router.get("/trends/categories")
async def category_trends(
    request: Request,
    userId: int = Query(...),
    role: str = Query(...),
    months: int = Query(6, ge=1, le=24),
):
    """Category-level spending trends over time."""
    cache_key = f"trends:categories:{months}"
    cached = request.app.state.cache.get(cache_key)
    if cached:
        return cached

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                COALESCE(t.category, 'uncategorised') AS category,
                DATE_TRUNC('month', t.transaction_date)::date AS month,
                SUM(t.amount) AS revenue,
                COUNT(*) AS tx_count
            FROM transactions t
            WHERE t.transaction_date > NOW() - INTERVAL '%s months'
            GROUP BY category, month
            ORDER BY category, month
        """, (months,))

        # Group by category
        categories = {}
        for r in cur.fetchall():
            cat = r[0]
            if cat not in categories:
                categories[cat] = {"category": cat, "months": [], "total": 0}
            categories[cat]["months"].append({
                "month": str(r[1]),
                "revenue": float(r[2]),
                "transactionCount": r[3],
            })
            categories[cat]["total"] += float(r[2])

        result = {
            "categories": sorted(categories.values(), key=lambda c: c["total"], reverse=True),
            "periodMonths": months,
        }

        request.app.state.cache.set(cache_key, result, ttl_seconds=600)
        return result
    except Exception as e:
        logger.error(f"Category trend query failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)
