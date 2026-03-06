# ═══════════════════════════════════════════════════════════════
# Dashboard Metrics Endpoint
# ═══════════════════════════════════════════════════════════════
import logging
from fastapi import APIRouter, Query
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.dashboard")
router = APIRouter()


@router.get("/dashboard")
async def get_dashboard(
    userId: int = Query(...),
    departmentId: int = Query(...),
    role: str = Query(...),
):
    """
    Returns aggregated dashboard metrics:
    - Total reports by status
    - Total revenue (transactions)
    - Active users count
    - Recent activity
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # ── Report counts by status ──
        if role == "admin":
            cur.execute("""
                SELECT status, COUNT(*) as count
                FROM reports
                GROUP BY status
            """)
        else:
            cur.execute("""
                SELECT status, COUNT(*) as count
                FROM reports
                WHERE department_id = %s
                GROUP BY status
            """, (departmentId,))
        report_counts = {row[0]: row[1] for row in cur.fetchall()}

        # ── Total revenue ──
        if role == "admin":
            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions")
        else:
            cur.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE department_id = %s",
                (departmentId,)
            )
        total_revenue = float(cur.fetchone()[0])

        # ── Active users (logged in within 30 days) ──
        cur.execute("""
            SELECT COUNT(*) FROM users
            WHERE is_active = TRUE
              AND last_login_at > NOW() - INTERVAL '30 days'
        """)
        active_users = cur.fetchone()[0]

        # ── Department count ──
        cur.execute("SELECT COUNT(*) FROM departments")
        department_count = cur.fetchone()[0]

        # ── Recent transactions (last 10) ──
        if role == "admin":
            cur.execute("""
                SELECT t.uuid, t.amount, t.currency, t.description,
                       t.category, t.transaction_date, d.name as department
                FROM transactions t
                JOIN departments d ON d.id = t.department_id
                ORDER BY t.transaction_date DESC
                LIMIT 10
            """)
        else:
            cur.execute("""
                SELECT t.uuid, t.amount, t.currency, t.description,
                       t.category, t.transaction_date, d.name as department
                FROM transactions t
                JOIN departments d ON d.id = t.department_id
                WHERE t.department_id = %s
                ORDER BY t.transaction_date DESC
                LIMIT 10
            """, (departmentId,))

        columns = [desc[0] for desc in cur.description]
        recent_transactions = [dict(zip(columns, row)) for row in cur.fetchall()]

        # Convert Decimal/datetime objects for JSON serialisation
        for tx in recent_transactions:
            tx["amount"] = float(tx["amount"])
            tx["transaction_date"] = str(tx["transaction_date"])
            tx["uuid"] = str(tx["uuid"])

        return {
            "reportCounts": report_counts,
            "totalRevenue": total_revenue,
            "activeUsers": active_users,
            "departmentCount": department_count,
            "recentTransactions": recent_transactions,
        }
    except Exception as e:
        logger.error(f"Dashboard query failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)
