# ═══════════════════════════════════════════════════════════════
# Predictive Analytics & Forecasting Engine
# ═══════════════════════════════════════════════════════════════
# Time-series forecasting, anomaly severity scoring, revenue
# prediction, seasonal decomposition — all with pure Python
# (no heavy ML libs required, runs lean in containers)
# ═══════════════════════════════════════════════════════════════
import math
import logging
from datetime import datetime, timedelta
from typing import Optional
from decimal import Decimal

from fastapi import APIRouter, Request, Query, HTTPException
from pydantic import BaseModel

from app.database import get_connection, return_connection
from app.cache import RedisCache

logger = logging.getLogger("edars.analytics.forecasting")
router = APIRouter(prefix="/forecasting", tags=["Forecasting"])


# ─── Response Models ──────────────────────────────────────────
class ForecastPoint(BaseModel):
    date: str
    predicted_value: float
    lower_bound: float
    upper_bound: float
    confidence: float


class ForecastResponse(BaseModel):
    department_id: int
    department_name: str
    metric: str
    horizon_days: int
    data_points_used: int
    forecast: list[ForecastPoint]
    trend: str          # "rising", "falling", "stable"
    trend_strength: float
    seasonality_detected: bool
    model_accuracy: float


class AnomalySeverity(BaseModel):
    transaction_uuid: str
    department: str
    amount: float
    z_score: float
    severity: str       # "low", "medium", "high", "critical"
    confidence: float
    context: str        # Human-readable explanation


# ─── Core Forecasting Engine ─────────────────────────────────

def linear_regression(x_vals: list[float], y_vals: list[float]):
    """Simple OLS linear regression. Returns (slope, intercept, r_squared)."""
    n = len(x_vals)
    if n < 2:
        return 0.0, 0.0, 0.0

    sum_x = sum(x_vals)
    sum_y = sum(y_vals)
    sum_xy = sum(x * y for x, y in zip(x_vals, y_vals))
    sum_x2 = sum(x * x for x in x_vals)
    sum_y2 = sum(y * y for y in y_vals)

    denom = n * sum_x2 - sum_x * sum_x
    if abs(denom) < 1e-10:
        return 0.0, sum_y / n, 0.0

    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n

    # R-squared
    ss_tot = sum_y2 - (sum_y ** 2) / n
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(x_vals, y_vals))
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

    return slope, intercept, max(0.0, min(1.0, r_squared))


def detect_seasonality(values: list[float], period: int = 7) -> tuple[bool, list[float]]:
    """
    Detect weekly seasonality using autocorrelation.
    Returns (is_seasonal, seasonal_factors).
    """
    if len(values) < period * 2:
        return False, [1.0] * period

    # Compute mean for each day-of-period position
    seasonal_factors = []
    overall_mean = sum(values) / len(values) if values else 1.0

    for i in range(period):
        period_values = [values[j] for j in range(i, len(values), period)]
        period_mean = sum(period_values) / len(period_values) if period_values else overall_mean
        factor = period_mean / overall_mean if overall_mean > 0 else 1.0
        seasonal_factors.append(factor)

    # Check if seasonality is significant (variance of factors > threshold)
    factor_variance = sum((f - 1.0) ** 2 for f in seasonal_factors) / period
    is_seasonal = factor_variance > 0.01  # 1% variance threshold

    return is_seasonal, seasonal_factors


def forecast_series(
    dates: list[datetime],
    values: list[float],
    horizon_days: int = 30,
) -> dict:
    """
    Generate time-series forecast using linear trend + seasonal decomposition.
    """
    if len(values) < 3:
        raise ValueError("Need at least 3 data points for forecasting")

    # Normalise x-axis to day indices
    base_date = min(dates)
    x_vals = [(d - base_date).days for d in dates]
    y_vals = [float(v) for v in values]

    # Fit linear trend
    slope, intercept, r_squared = linear_regression(
        [float(x) for x in x_vals], y_vals
    )

    # Detect seasonality
    is_seasonal, seasonal_factors = detect_seasonality(y_vals)

    # Compute residuals for confidence interval
    residuals = []
    for x, y in zip(x_vals, y_vals):
        predicted = slope * x + intercept
        if is_seasonal:
            predicted *= seasonal_factors[x % len(seasonal_factors)]
        residuals.append(y - predicted)

    residual_std = math.sqrt(
        sum(r ** 2 for r in residuals) / len(residuals)
    ) if residuals else 0.0

    # Generate forecast points
    last_x = max(x_vals)
    forecast_points = []

    for day in range(1, horizon_days + 1):
        future_x = last_x + day
        predicted = slope * future_x + intercept

        if is_seasonal:
            predicted *= seasonal_factors[future_x % len(seasonal_factors)]

        # Confidence widens with distance
        uncertainty = residual_std * math.sqrt(1 + day / len(values))
        confidence = max(0.5, min(0.99, r_squared * (1 - day / (horizon_days * 3))))

        future_date = base_date + timedelta(days=future_x)
        forecast_points.append({
            "date": future_date.strftime("%Y-%m-%d"),
            "predicted_value": round(max(0, predicted), 2),
            "lower_bound": round(max(0, predicted - 1.96 * uncertainty), 2),
            "upper_bound": round(predicted + 1.96 * uncertainty, 2),
            "confidence": round(confidence, 3),
        })

    # Determine trend
    if abs(slope) < 0.01 * (sum(y_vals) / len(y_vals)):
        trend = "stable"
    elif slope > 0:
        trend = "rising"
    else:
        trend = "falling"

    return {
        "forecast": forecast_points,
        "trend": trend,
        "trend_strength": round(abs(slope), 4),
        "seasonality_detected": is_seasonal,
        "model_accuracy": round(r_squared, 4),
        "data_points_used": len(values),
    }


# ─── Anomaly Severity Scoring ────────────────────────────────

def score_anomaly_severity(z_score: float, amount: float, category_avg: float) -> dict:
    """
    Multi-factor anomaly severity scoring.
    Combines statistical deviation, absolute magnitude, and relative impact.
    """
    abs_z = abs(z_score)

    # Statistical severity
    if abs_z >= 4.0:
        stat_severity = "critical"
        stat_score = 1.0
    elif abs_z >= 3.0:
        stat_severity = "high"
        stat_score = 0.75
    elif abs_z >= 2.5:
        stat_severity = "medium"
        stat_score = 0.5
    else:
        stat_severity = "low"
        stat_score = 0.25

    # Magnitude factor (how large is the absolute amount?)
    magnitude_factor = min(amount / max(category_avg, 1.0), 10.0) / 10.0

    # Combined confidence
    confidence = min(0.99, stat_score * 0.7 + magnitude_factor * 0.3)

    # Human-readable context
    direction = "above" if z_score > 0 else "below"
    multiple = abs(amount / category_avg) if category_avg > 0 else 0

    if multiple > 1:
        context = f"Transaction is {multiple:.1f}x the category average ({direction} mean by {abs_z:.1f} standard deviations)"
    else:
        context = f"Transaction is {abs_z:.1f} standard deviations {direction} the category average"

    return {
        "severity": stat_severity,
        "confidence": round(confidence, 3),
        "context": context,
    }


# ─── API Routes ──────────────────────────────────────────────

@router.get("/revenue-forecast/{department_id}")
async def revenue_forecast(
    request: Request,
    department_id: int,
    horizon: int = Query(30, ge=7, le=180, description="Forecast horizon in days"),
    lookback: int = Query(90, ge=30, le=365, description="Historical data lookback in days"),
):
    """
    Forecast department revenue using trend analysis + seasonal decomposition.
    """
    cache: RedisCache = request.app.state.cache
    cache_key = f"forecast:revenue:{department_id}:{horizon}:{lookback}"

    cached = cache.get(cache_key)
    if cached:
        return cached

    conn = get_connection()
    try:
        cur = conn.cursor()

        # Get department name
        cur.execute("SELECT name FROM departments WHERE id = %s", (department_id,))
        dept = cur.fetchone()
        if not dept:
            raise HTTPException(status_code=404, detail="Department not found")

        # Fetch daily revenue aggregates
        cur.execute("""
            SELECT DATE_TRUNC('day', transaction_date)::date AS day,
                   COALESCE(SUM(amount), 0) AS daily_revenue
            FROM transactions
            WHERE department_id = %s
              AND transaction_date >= NOW() - INTERVAL '%s days'
            GROUP BY day
            ORDER BY day ASC
        """, (department_id, lookback))

        rows = cur.fetchall()
        cur.close()

        if len(rows) < 7:
            raise HTTPException(
                status_code=422,
                detail=f"Insufficient data: need at least 7 data points, found {len(rows)}",
            )

        dates = [row[0] for row in rows]
        values = [float(row[1]) for row in rows]

        result = forecast_series(dates, values, horizon)
        result["department_id"] = department_id
        result["department_name"] = dept[0]
        result["metric"] = "daily_revenue"
        result["horizon_days"] = horizon

        cache.set(cache_key, result, ttl_seconds=1800)  # 30-min cache
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Revenue forecast failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Forecast computation failed")
    finally:
        return_connection(conn)


@router.get("/spending-anomalies")
async def scored_anomalies(
    request: Request,
    lookback_days: int = Query(90, ge=7, le=365),
    min_severity: str = Query("low", regex="^(low|medium|high|critical)$"),
):
    """
    Enhanced anomaly detection with severity scoring and human-readable context.
    """
    cache: RedisCache = request.app.state.cache
    cache_key = f"anomalies:scored:{lookback_days}:{min_severity}"

    cached = cache.get(cache_key)
    if cached:
        return cached

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            WITH category_stats AS (
                SELECT category,
                       AVG(amount) AS avg_amount,
                       STDDEV(amount) AS stddev_amount
                FROM transactions
                WHERE transaction_date > NOW() - INTERVAL '%s days'
                GROUP BY category
                HAVING COUNT(*) > 2 AND STDDEV(amount) > 0
            )
            SELECT t.uuid, d.name, t.amount, t.category,
                   cs.avg_amount, cs.stddev_amount,
                   (t.amount - cs.avg_amount) / cs.stddev_amount AS z_score,
                   t.transaction_date
            FROM transactions t
            JOIN departments d ON d.id = t.department_id
            JOIN category_stats cs ON cs.category = t.category
            WHERE ABS((t.amount - cs.avg_amount) / cs.stddev_amount) > 2
            ORDER BY ABS((t.amount - cs.avg_amount) / cs.stddev_amount) DESC
            LIMIT 100
        """, (lookback_days,))

        rows = cur.fetchall()
        cur.close()

        anomalies = []
        for row in rows:
            scoring = score_anomaly_severity(
                z_score=float(row[6]),
                amount=float(row[2]),
                category_avg=float(row[4]),
            )

            if severity_rank.get(scoring["severity"], 0) >= severity_rank.get(min_severity, 0):
                anomalies.append({
                    "transaction_uuid": str(row[0]),
                    "department": row[1],
                    "amount": float(row[2]),
                    "category": row[3],
                    "category_avg": round(float(row[4]), 2),
                    "z_score": round(float(row[6]), 2),
                    "severity": scoring["severity"],
                    "confidence": scoring["confidence"],
                    "context": scoring["context"],
                    "transaction_date": row[7].isoformat() if row[7] else None,
                })

        result = {
            "anomalies": anomalies,
            "total_count": len(anomalies),
            "lookback_days": lookback_days,
            "min_severity": min_severity,
            "severity_breakdown": {
                s: sum(1 for a in anomalies if a["severity"] == s)
                for s in ["low", "medium", "high", "critical"]
            },
        }

        cache.set(cache_key, result, ttl_seconds=900)  # 15-min cache
        return result

    except Exception as e:
        logger.error(f"Anomaly scoring failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Anomaly analysis failed")
    finally:
        return_connection(conn)


@router.get("/trend-analysis")
async def trend_analysis(
    request: Request,
    metric: str = Query("revenue", regex="^(revenue|transactions|users)$"),
    granularity: str = Query("daily", regex="^(daily|weekly|monthly)$"),
    lookback_days: int = Query(90, ge=14, le=365),
):
    """
    General trend analysis with slope, R², and direction detection.
    """
    cache: RedisCache = request.app.state.cache
    cache_key = f"trends:{metric}:{granularity}:{lookback_days}"

    cached = cache.get(cache_key)
    if cached:
        return cached

    trunc_map = {"daily": "day", "weekly": "week", "monthly": "month"}
    trunc = trunc_map[granularity]

    conn = get_connection()
    try:
        cur = conn.cursor()

        if metric == "revenue":
            cur.execute("""
                SELECT DATE_TRUNC(%s, transaction_date)::date AS period,
                       SUM(amount) AS value
                FROM transactions
                WHERE transaction_date >= NOW() - INTERVAL '%s days'
                GROUP BY period ORDER BY period
            """, (trunc, lookback_days))
        elif metric == "transactions":
            cur.execute("""
                SELECT DATE_TRUNC(%s, transaction_date)::date AS period,
                       COUNT(*) AS value
                FROM transactions
                WHERE transaction_date >= NOW() - INTERVAL '%s days'
                GROUP BY period ORDER BY period
            """, (trunc, lookback_days))
        elif metric == "users":
            cur.execute("""
                SELECT DATE_TRUNC(%s, created_at)::date AS period,
                       COUNT(*) AS value
                FROM audit_log
                WHERE action = 'LOGIN'
                  AND created_at >= NOW() - INTERVAL '%s days'
                GROUP BY period ORDER BY period
            """, (trunc, lookback_days))

        rows = cur.fetchall()
        cur.close()

        if len(rows) < 3:
            return {
                "metric": metric,
                "granularity": granularity,
                "data_points": len(rows),
                "trend": "insufficient_data",
                "message": "Need at least 3 data points for trend analysis",
            }

        dates = [row[0] for row in rows]
        values = [float(row[1]) for row in rows]
        base = min(dates)
        x_vals = [(d - base).days for d in dates]

        slope, intercept, r_squared = linear_regression(
            [float(x) for x in x_vals], values
        )

        mean_val = sum(values) / len(values)
        pct_change = (slope * len(x_vals)) / mean_val * 100 if mean_val > 0 else 0

        if abs(pct_change) < 2:
            trend = "stable"
        elif pct_change > 0:
            trend = "rising"
        else:
            trend = "falling"

        result = {
            "metric": metric,
            "granularity": granularity,
            "lookback_days": lookback_days,
            "data_points": len(rows),
            "trend": trend,
            "slope": round(slope, 4),
            "r_squared": round(r_squared, 4),
            "period_change_pct": round(pct_change, 2),
            "current_value": values[-1],
            "period_average": round(mean_val, 2),
            "period_min": min(values),
            "period_max": max(values),
            "time_series": [
                {"date": d.isoformat(), "value": round(v, 2)}
                for d, v in zip(dates, values)
            ],
        }

        cache.set(cache_key, result, ttl_seconds=1800)
        return result

    except Exception as e:
        logger.error(f"Trend analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Trend analysis failed")
    finally:
        return_connection(conn)
