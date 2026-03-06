# ═══════════════════════════════════════════════════════════════
# Report Generation Endpoint (async trigger)
# ═══════════════════════════════════════════════════════════════
import logging
import json
from pydantic import BaseModel
from typing import Optional
from fastapi import APIRouter
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.generate")
router = APIRouter()


class GenerateRequest(BaseModel):
    reportUuid: str
    reportType: str
    parameters: dict = {}
    departmentId: int


@router.post("/generate")
async def generate_report(req: GenerateRequest):
    """
    Generates report data and writes the result back to the reports table.
    Called internally by the API gateway when a user creates a new report.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # Mark report as processing
        cur.execute(
            "UPDATE reports SET status = 'processing' WHERE uuid = %s",
            (req.reportUuid,)
        )
        conn.commit()

        result_data = {}

        if req.reportType == "sales_summary":
            result_data = _generate_sales_summary(cur, req.departmentId, req.parameters)
        elif req.reportType == "user_activity":
            result_data = _generate_user_activity(cur, req.parameters)
        elif req.reportType == "department_kpis":
            result_data = _generate_department_kpis(cur, req.departmentId, req.parameters)
        else:
            raise ValueError(f"Unknown report type: {req.reportType}")

        # Write result and mark completed
        cur.execute(
            """UPDATE reports
               SET status = 'completed',
                   result_data = %s,
                   completed_at = NOW()
               WHERE uuid = %s""",
            (json.dumps(result_data, default=str), req.reportUuid)
        )
        conn.commit()

        logger.info(f"Report {req.reportUuid} generated successfully")

        return {"status": "completed", "reportUuid": req.reportUuid}

    except Exception as e:
        conn.rollback()
        # Mark as failed
        try:
            cur.execute(
                "UPDATE reports SET status = 'failed' WHERE uuid = %s",
                (req.reportUuid,)
            )
            conn.commit()
        except Exception:
            pass
        logger.error(f"Report generation failed for {req.reportUuid}: {e}")
        return {"status": "failed", "error": str(e)}
    finally:
        cur.close()
        return_connection(conn)


def _generate_sales_summary(cur, department_id, params):
    cur.execute("""
        SELECT d.name,
               COALESCE(SUM(t.amount), 0) as revenue,
               COUNT(*) as tx_count,
               COALESCE(AVG(t.amount), 0) as avg_amount
        FROM transactions t
        JOIN departments d ON d.id = t.department_id
        WHERE t.department_id = %s
        GROUP BY d.name
    """, (department_id,))
    rows = cur.fetchall()
    return {
        "departments": [
            {
                "name": r[0],
                "revenue": float(r[1]),
                "transactionCount": r[2],
                "averageAmount": round(float(r[3]), 2),
            }
            for r in rows
        ]
    }


def _generate_user_activity(cur, params):
    days = params.get("days", 30)
    cur.execute("""
        SELECT DATE_TRUNC('day', al.created_at)::date as day,
               COUNT(DISTINCT al.user_id) as dau,
               COUNT(*) as actions
        FROM audit_log al
        WHERE al.created_at > NOW() - INTERVAL '%s days'
        GROUP BY day
        ORDER BY day
    """, (days,))
    return {
        "dailyActivity": [
            {"date": str(r[0]), "dau": r[1], "actions": r[2]}
            for r in cur.fetchall()
        ]
    }


def _generate_department_kpis(cur, department_id, params):
    cur.execute("""
        SELECT
            (SELECT COUNT(*) FROM users WHERE department_id = %s AND is_active = TRUE) as headcount,
            (SELECT COUNT(*) FROM reports WHERE department_id = %s) as total_reports,
            (SELECT COUNT(*) FROM reports WHERE department_id = %s AND status = 'completed') as completed,
            (SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE department_id = %s) as revenue
    """, (department_id, department_id, department_id, department_id))
    row = cur.fetchone()
    return {
        "headcount": row[0],
        "totalReports": row[1],
        "completedReports": row[2],
        "revenue": float(row[3]),
        "completionRate": round((row[2] / row[1]) * 100, 1) if row[1] > 0 else 0,
    }
