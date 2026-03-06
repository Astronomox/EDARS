# ═══════════════════════════════════════════════════════════════
# Department KPIs Report
# ═══════════════════════════════════════════════════════════════
import logging
from fastapi import APIRouter, Query
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.kpis")
router = APIRouter()


@router.get("/department-kpis")
async def department_kpis(
    userId: int = Query(...),
    role: str = Query(...),
    departmentId: int = Query(None),
):
    """
    Per-department KPIs: headcount, report volume, processing metrics, revenue.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        dept_filter = ""
        params = []
        if departmentId and role != "admin":
            dept_filter = "WHERE d.id = %s"
            params = [departmentId]

        cur.execute(f"""
            SELECT
                d.id,
                d.name,
                -- Headcount
                (SELECT COUNT(*) FROM users u WHERE u.department_id = d.id AND u.is_active = TRUE) as headcount,
                -- Total reports
                (SELECT COUNT(*) FROM reports r WHERE r.department_id = d.id) as total_reports,
                -- Completed reports
                (SELECT COUNT(*) FROM reports r WHERE r.department_id = d.id AND r.status = 'completed') as completed_reports,
                -- Pending reports
                (SELECT COUNT(*) FROM reports r WHERE r.department_id = d.id AND r.status = 'pending') as pending_reports,
                -- Total revenue
                (SELECT COALESCE(SUM(t.amount), 0) FROM transactions t WHERE t.department_id = d.id) as total_revenue,
                -- Avg transaction
                (SELECT COALESCE(AVG(t.amount), 0) FROM transactions t WHERE t.department_id = d.id) as avg_transaction,
                -- Transaction count
                (SELECT COUNT(*) FROM transactions t WHERE t.department_id = d.id) as transaction_count,
                -- Audit actions (last 30 days)
                (SELECT COUNT(*) FROM audit_log al
                 JOIN users u ON u.id = al.user_id
                 WHERE u.department_id = d.id
                   AND al.created_at > NOW() - INTERVAL '30 days') as recent_actions
            FROM departments d
            {dept_filter}
            ORDER BY d.name
        """, params)

        columns = [desc[0] for desc in cur.description]
        departments = []
        for row in cur.fetchall():
            dept = dict(zip(columns, row))
            # Convert Decimal types
            dept["total_revenue"] = float(dept["total_revenue"])
            dept["avg_transaction"] = round(float(dept["avg_transaction"]), 2)
            # Compute completion rate
            total = dept["total_reports"]
            dept["completion_rate"] = (
                round((dept["completed_reports"] / total) * 100, 1) if total > 0 else 0
            )
            departments.append(dept)

        # ── Summary aggregates ──
        totals = {
            "totalHeadcount": sum(d["headcount"] for d in departments),
            "totalReports": sum(d["total_reports"] for d in departments),
            "totalRevenue": sum(d["total_revenue"] for d in departments),
            "departmentCount": len(departments),
        }

        return {
            "departments": departments,
            "totals": totals,
        }
    except Exception as e:
        logger.error(f"Department KPIs query failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)
