# ═══════════════════════════════════════════════════════════════
# Anomaly Detection Endpoint
# Statistical outlier detection across transactions
# ═══════════════════════════════════════════════════════════════
import logging
import math
from fastapi import APIRouter, Query, Request
from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.anomalies")
router = APIRouter()


@router.get("/anomalies/spending")
async def spending_anomalies(
    request: Request,
    userId: int = Query(...),
    role: str = Query(...),
    lookbackDays: int = Query(90, ge=7, le=365),
    zThreshold: float = Query(2.0, ge=1.0, le=5.0),
):
    """
    Identifies spending outliers using z-score analysis.
    Transactions with z-score > threshold are flagged.
    """
    cache_key = f"anomalies:spending:{lookbackDays}:{zThreshold}"
    cached = request.app.state.cache.get(cache_key)
    if cached:
        return cached

    conn = get_connection()
    try:
        cur = conn.cursor()

        cur.execute("""
            WITH category_stats AS (
                SELECT
                    category,
                    AVG(amount) AS avg_amount,
                    STDDEV(amount) AS stddev_amount,
                    COUNT(*) as sample_size
                FROM transactions
                WHERE transaction_date > NOW() - INTERVAL '%s days'
                GROUP BY category
                HAVING COUNT(*) > 2 AND STDDEV(amount) > 0
            )
            SELECT
                t.uuid,
                d.name AS department,
                t.amount,
                t.currency,
                t.description,
                t.category,
                t.transaction_date,
                cs.avg_amount,
                cs.stddev_amount,
                cs.sample_size,
                (t.amount - cs.avg_amount) / cs.stddev_amount AS z_score
            FROM transactions t
            JOIN departments d ON d.id = t.department_id
            JOIN category_stats cs ON cs.category = t.category
            WHERE t.transaction_date > NOW() - INTERVAL '%s days'
              AND ABS((t.amount - cs.avg_amount) / cs.stddev_amount) > %s
            ORDER BY ABS((t.amount - cs.avg_amount) / cs.stddev_amount) DESC
            LIMIT 50
        """, (lookbackDays, lookbackDays, zThreshold))

        anomalies = []
        for r in cur.fetchall():
            z = float(r[10])
            anomalies.append({
                "uuid": str(r[0]),
                "department": r[1],
                "amount": float(r[2]),
                "currency": r[3],
                "description": r[4],
                "category": r[5],
                "transactionDate": str(r[6]),
                "categoryAvg": round(float(r[7]), 2),
                "categoryStdDev": round(float(r[8]), 2),
                "sampleSize": r[9],
                "zScore": round(z, 2),
                "severity": "critical" if abs(z) > 3 else "warning",
                "direction": "above" if z > 0 else "below",
            })

        # Summary statistics
        total_flagged = len(anomalies)
        critical_count = sum(1 for a in anomalies if a["severity"] == "critical")

        result = {
            "anomalies": anomalies,
            "summary": {
                "totalFlagged": total_flagged,
                "critical": critical_count,
                "warnings": total_flagged - critical_count,
                "lookbackDays": lookbackDays,
                "zThreshold": zThreshold,
            },
        }

        request.app.state.cache.set(cache_key, result, ttl_seconds=300)
        return result
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)


@router.get("/anomalies/activity")
async def activity_anomalies(
    request: Request,
    userId: int = Query(...),
    role: str = Query(...),
    lookbackDays: int = Query(30, ge=7, le=180),
):
    """
    Detects unusual user activity patterns.
    Flags users with activity significantly above/below normal.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        cur.execute("""
            WITH user_daily AS (
                SELECT
                    al.user_id,
                    DATE_TRUNC('day', al.created_at)::date AS day,
                    COUNT(*) AS actions
                FROM audit_log al
                WHERE al.created_at > NOW() - INTERVAL '%s days'
                  AND al.user_id IS NOT NULL
                GROUP BY al.user_id, day
            ),
            user_stats AS (
                SELECT
                    user_id,
                    AVG(actions) AS avg_daily,
                    STDDEV(actions) AS stddev_daily,
                    MAX(actions) AS max_daily,
                    COUNT(*) AS active_days
                FROM user_daily
                GROUP BY user_id
                HAVING COUNT(*) >= 3
            )
            SELECT
                u.full_name,
                u.email,
                u.role,
                d.name AS department,
                us.avg_daily,
                us.stddev_daily,
                us.max_daily,
                us.active_days,
                CASE
                    WHEN us.stddev_daily > 0 AND us.max_daily > us.avg_daily + 2 * us.stddev_daily
                    THEN 'spike_detected'
                    WHEN us.active_days < %s * 0.3
                    THEN 'low_activity'
                    ELSE 'normal'
                END AS pattern
            FROM user_stats us
            JOIN users u ON u.id = us.user_id
            JOIN departments d ON d.id = u.department_id
            WHERE (us.stddev_daily > 0 AND us.max_daily > us.avg_daily + 2 * us.stddev_daily)
               OR us.active_days < %s * 0.3
            ORDER BY us.max_daily DESC
        """, (lookbackDays, lookbackDays, lookbackDays))

        columns = [desc[0] for desc in cur.description]
        flagged_users = []
        for row in cur.fetchall():
            user = dict(zip(columns, row))
            user["avg_daily"] = round(float(user["avg_daily"]), 1)
            user["stddev_daily"] = round(float(user["stddev_daily"]), 1) if user["stddev_daily"] else 0
            flagged_users.append(user)

        return {
            "flaggedUsers": flagged_users,
            "totalFlagged": len(flagged_users),
            "lookbackDays": lookbackDays,
        }
    except Exception as e:
        logger.error(f"Activity anomaly detection failed: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)
