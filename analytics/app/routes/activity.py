# ═══════════════════════════════════════════════════════════════
# User Activity Report
# ═══════════════════════════════════════════════════════════════
import logging
from fastapi import APIRouter, Query
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.activity")
router = APIRouter()


@router.get("/user-activity")
async def user_activity(
    userId: int = Query(...),
    role: str = Query(...),
    days: int = Query(30, ge=1, le=365),
):
    """
    Daily active users, action counts, and peak usage analysis.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # ── Daily active users (DAU) ──
        cur.execute("""
            SELECT DATE_TRUNC('day', al.created_at)::date as day,
                   COUNT(DISTINCT al.user_id) as active_users,
                   COUNT(*) as total_actions
            FROM audit_log al
            WHERE al.created_at > NOW() - INTERVAL '%s days'
            GROUP BY day
            ORDER BY day
        """, (days,))
        daily_activity = [
            {"date": str(row[0]), "activeUsers": row[1], "totalActions": row[2]}
            for row in cur.fetchall()
        ]

        # ── Top actions ──
        cur.execute("""
            SELECT al.action, COUNT(*) as count
            FROM audit_log al
            WHERE al.created_at > NOW() - INTERVAL '%s days'
            GROUP BY al.action
            ORDER BY count DESC
            LIMIT 20
        """, (days,))
        top_actions = [
            {"action": row[0], "count": row[1]}
            for row in cur.fetchall()
        ]

        # ── Peak usage hours ──
        cur.execute("""
            SELECT EXTRACT(HOUR FROM al.created_at)::int as hour,
                   COUNT(*) as action_count
            FROM audit_log al
            WHERE al.created_at > NOW() - INTERVAL '%s days'
            GROUP BY hour
            ORDER BY hour
        """, (days,))
        hourly_distribution = [
            {"hour": row[0], "actions": row[1]}
            for row in cur.fetchall()
        ]

        # ── Most active users ──
        cur.execute("""
            SELECT u.full_name, u.email, COUNT(*) as action_count
            FROM audit_log al
            JOIN users u ON u.id = al.user_id
            WHERE al.created_at > NOW() - INTERVAL '%s days'
            GROUP BY u.full_name, u.email
            ORDER BY action_count DESC
            LIMIT 10
        """, (days,))
        most_active = [
            {"name": row[0], "email": row[1], "actionCount": row[2]}
            for row in cur.fetchall()
        ]

        return {
            "period": f"Last {days} days",
            "dailyActivity": daily_activity,
            "topActions": top_actions,
            "hourlyDistribution": hourly_distribution,
            "mostActiveUsers": most_active,
        }
    except Exception as e:
        logger.error(f"User activity query failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)
