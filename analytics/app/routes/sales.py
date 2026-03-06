# ═══════════════════════════════════════════════════════════════
# Sales Summary Report
# ═══════════════════════════════════════════════════════════════
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Query
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.sales")
router = APIRouter()


@router.get("/sales-summary")
async def sales_summary(
    userId: int = Query(...),
    role: str = Query(...),
    departmentId: int = Query(None),
    startDate: str = Query(None),
    endDate: str = Query(None),
):
    """
    Revenue aggregation and department-level breakdown over a configurable date range.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # Default date range: last 90 days
        end = datetime.fromisoformat(endDate) if endDate else datetime.now()
        start = datetime.fromisoformat(startDate) if startDate else (end - timedelta(days=90))

        base_where = "WHERE t.transaction_date BETWEEN %s AND %s"
        params = [start, end]

        if role != "admin" and departmentId:
            base_where += " AND t.department_id = %s"
            params.append(departmentId)

        # ── Total revenue in range ──
        cur.execute(f"""
            SELECT COALESCE(SUM(amount), 0),
                   COUNT(*),
                   COALESCE(AVG(amount), 0)
            FROM transactions t
            {base_where}
        """, params)
        row = cur.fetchone()
        summary = {
            "totalRevenue": float(row[0]),
            "transactionCount": row[1],
            "averageTransaction": round(float(row[2]), 2),
        }

        # ── Breakdown by department ──
        cur.execute(f"""
            SELECT d.name,
                   COALESCE(SUM(t.amount), 0) as revenue,
                   COUNT(*) as tx_count
            FROM transactions t
            JOIN departments d ON d.id = t.department_id
            {base_where}
            GROUP BY d.name
            ORDER BY revenue DESC
        """, params)
        dept_breakdown = [
            {"department": row[0], "revenue": float(row[1]), "transactionCount": row[2]}
            for row in cur.fetchall()
        ]

        # ── Breakdown by category ──
        cur.execute(f"""
            SELECT COALESCE(t.category, 'uncategorised') as category,
                   COALESCE(SUM(t.amount), 0) as revenue,
                   COUNT(*) as tx_count
            FROM transactions t
            {base_where}
            GROUP BY t.category
            ORDER BY revenue DESC
        """, params)
        category_breakdown = [
            {"category": row[0], "revenue": float(row[1]), "transactionCount": row[2]}
            for row in cur.fetchall()
        ]

        # ── Monthly trend ──
        cur.execute(f"""
            SELECT DATE_TRUNC('month', t.transaction_date) as month,
                   COALESCE(SUM(t.amount), 0) as revenue
            FROM transactions t
            {base_where}
            GROUP BY month
            ORDER BY month
        """, params)
        monthly_trend = [
            {"month": str(row[0].date()), "revenue": float(row[1])}
            for row in cur.fetchall()
        ]

        return {
            "dateRange": {"start": str(start.date()), "end": str(end.date())},
            "summary": summary,
            "byDepartment": dept_breakdown,
            "byCategory": category_breakdown,
            "monthlyTrend": monthly_trend,
        }
    except Exception as e:
        logger.error(f"Sales summary query failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)
