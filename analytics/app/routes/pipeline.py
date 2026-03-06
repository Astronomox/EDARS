# ═══════════════════════════════════════════════════════════════
# ETL Data Pipeline Engine
# ═══════════════════════════════════════════════════════════════
# Scheduled data processing framework with:
#   • Pipeline stage orchestration
#   • Checkpoint-based incremental processing
#   • Watermark tracking (only process new data)
#   • Dead-letter queue for failed records
#   • Aggregation job runner
# ═══════════════════════════════════════════════════════════════
import logging
import time
import json
import traceback
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Request, Query, HTTPException
from pydantic import BaseModel

from app.database import get_connection, return_connection

logger = logging.getLogger("edars.analytics.pipeline")
router = APIRouter(prefix="/pipeline", tags=["Pipeline"])


# ─── Pipeline Models ─────────────────────────────────────────

class PipelineStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class PipelineStage(BaseModel):
    name: str
    status: str
    records_processed: int
    records_failed: int
    duration_ms: float
    error: Optional[str] = None


class PipelineResult(BaseModel):
    pipeline_name: str
    status: str
    started_at: str
    completed_at: Optional[str]
    stages: list[PipelineStage]
    total_processed: int
    total_failed: int
    watermark: Optional[str]
    next_run_hint: Optional[str]


# ─── Pipeline Registry ───────────────────────────────────────

_pipelines = {}
_pipeline_history = []  # Last 50 runs


def register_pipeline(name: str, stages: list):
    """Register a named pipeline with its processing stages."""
    _pipelines[name] = {
        "name": name,
        "stages": stages,
        "last_run": None,
        "last_status": PipelineStatus.IDLE,
        "run_count": 0,
    }


# ─── Watermark Tracking ──────────────────────────────────────

def get_watermark(conn, pipeline_name: str) -> Optional[datetime]:
    """Get the last processed timestamp for incremental pipelines."""
    cur = conn.cursor()
    cur.execute("""
        SELECT metadata->>'watermark'
        FROM audit_log
        WHERE action = 'PIPELINE_CHECKPOINT'
          AND resource_type = 'pipeline'
          AND resource_id = %s
        ORDER BY created_at DESC
        LIMIT 1
    """, (pipeline_name,))
    row = cur.fetchone()
    cur.close()
    if row and row[0]:
        return datetime.fromisoformat(row[0])
    return None


def set_watermark(conn, pipeline_name: str, watermark: datetime):
    """Persist watermark for incremental processing."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log (action, resource_type, resource_id, metadata)
        VALUES ('PIPELINE_CHECKPOINT', 'pipeline', %s, %s)
    """, (pipeline_name, json.dumps({
        "watermark": watermark.isoformat(),
        "checkpoint_at": datetime.utcnow().isoformat(),
    })))
    conn.commit()
    cur.close()


# ─── Built-in Pipeline Stages ────────────────────────────────

def stage_refresh_materialized_views(conn, context: dict) -> dict:
    """Refresh all materialized views for fresh dashboard data."""
    cur = conn.cursor()
    cur.execute("SELECT refresh_all_materialized_views()")
    conn.commit()
    cur.close()
    return {"records_processed": 3, "records_failed": 0}  # 3 mat views


def stage_aggregate_daily_revenue(conn, context: dict) -> dict:
    """Aggregate daily revenue per department since last watermark."""
    watermark = context.get("watermark")
    where_clause = ""
    params = []

    if watermark:
        where_clause = "WHERE transaction_date > %s"
        params = [watermark]

    cur = conn.cursor()

    # Count new records to process
    cur.execute(f"""
        SELECT COUNT(*), MAX(transaction_date)
        FROM transactions
        {where_clause}
    """, params)
    count_row = cur.fetchone()
    total_records = count_row[0] or 0
    new_watermark = count_row[1]

    if total_records == 0:
        cur.close()
        return {"records_processed": 0, "records_failed": 0, "watermark": None}

    # Run aggregation
    cur.execute(f"""
        SELECT d.name, DATE_TRUNC('day', t.transaction_date)::date,
               SUM(t.amount), COUNT(*)
        FROM transactions t
        JOIN departments d ON d.id = t.department_id
        {where_clause}
        GROUP BY d.name, DATE_TRUNC('day', t.transaction_date)::date
        ORDER BY DATE_TRUNC('day', t.transaction_date)::date DESC
    """, params)

    aggregated = cur.fetchall()
    cur.close()

    context["new_watermark"] = new_watermark.isoformat() if new_watermark else None

    return {
        "records_processed": total_records,
        "records_failed": 0,
        "aggregation_rows": len(aggregated),
        "watermark": context["new_watermark"],
    }


def stage_detect_anomalies(conn, context: dict) -> dict:
    """Run anomaly detection on recent transactions."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM detect_spending_anomalies(90)")
    result = cur.fetchone()
    cur.close()
    return {
        "records_processed": result[0] if result else 0,
        "records_failed": 0,
    }


def stage_cleanup_old_sessions(conn, context: dict) -> dict:
    """Identify and log inactive user sessions."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM get_inactive_users(90)")
    result = cur.fetchone()
    cur.close()
    return {
        "records_processed": result[0] if result else 0,
        "records_failed": 0,
    }


def stage_partition_maintenance(conn, context: dict) -> dict:
    """Create next quarter's partitions if approaching quarter boundary."""
    now = datetime.utcnow()
    quarter_end_month = ((now.month - 1) // 3 + 1) * 3
    quarter_end = datetime(now.year, quarter_end_month, 1) + timedelta(days=32)
    quarter_end = quarter_end.replace(day=1)
    days_until_end = (quarter_end - now).days

    if days_until_end <= 30:
        cur = conn.cursor()
        cur.execute("SELECT create_next_quarter_partitions()")
        conn.commit()
        cur.close()
        return {"records_processed": 1, "records_failed": 0, "action": "partitions_created"}

    return {"records_processed": 0, "records_failed": 0, "action": "no_action_needed"}


# ─── Register Default Pipelines ──────────────────────────────

register_pipeline("daily_aggregation", [
    ("aggregate_daily_revenue", stage_aggregate_daily_revenue),
    ("refresh_views", stage_refresh_materialized_views),
    ("detect_anomalies", stage_detect_anomalies),
])

register_pipeline("maintenance", [
    ("cleanup_sessions", stage_cleanup_old_sessions),
    ("partition_maintenance", stage_partition_maintenance),
    ("refresh_views", stage_refresh_materialized_views),
])

register_pipeline("full_reprocess", [
    ("aggregate_daily_revenue", stage_aggregate_daily_revenue),
    ("refresh_views", stage_refresh_materialized_views),
    ("detect_anomalies", stage_detect_anomalies),
    ("cleanup_sessions", stage_cleanup_old_sessions),
    ("partition_maintenance", stage_partition_maintenance),
])


# ─── Pipeline Runner ─────────────────────────────────────────

def run_pipeline(pipeline_name: str, force_full: bool = False) -> dict:
    """Execute a registered pipeline with stage orchestration."""
    if pipeline_name not in _pipelines:
        raise ValueError(f"Unknown pipeline: {pipeline_name}")

    pipeline = _pipelines[pipeline_name]
    pipeline["run_count"] += 1

    conn = get_connection()
    started_at = datetime.utcnow()

    result = {
        "pipeline_name": pipeline_name,
        "status": PipelineStatus.RUNNING,
        "started_at": started_at.isoformat(),
        "completed_at": None,
        "stages": [],
        "total_processed": 0,
        "total_failed": 0,
        "watermark": None,
        "next_run_hint": None,
    }

    context = {}

    # Get watermark for incremental processing
    if not force_full:
        watermark = get_watermark(conn, pipeline_name)
        context["watermark"] = watermark
        result["watermark"] = watermark.isoformat() if watermark else None

    overall_status = PipelineStatus.COMPLETED
    dead_letter = []

    try:
        for stage_name, stage_fn in pipeline["stages"]:
            stage_start = time.perf_counter()
            stage_result = {
                "name": stage_name,
                "status": "running",
                "records_processed": 0,
                "records_failed": 0,
                "duration_ms": 0,
                "error": None,
            }

            try:
                outcome = stage_fn(conn, context)
                stage_result["records_processed"] = outcome.get("records_processed", 0)
                stage_result["records_failed"] = outcome.get("records_failed", 0)
                stage_result["status"] = "completed"

                result["total_processed"] += stage_result["records_processed"]
                result["total_failed"] += stage_result["records_failed"]

                # Update watermark if stage produced one
                if "watermark" in outcome and outcome["watermark"]:
                    context["new_watermark"] = outcome["watermark"]

            except Exception as e:
                stage_result["status"] = "failed"
                stage_result["error"] = str(e)
                overall_status = PipelineStatus.PARTIAL
                logger.error(f"Pipeline stage failed: {pipeline_name}/{stage_name}", exc_info=True)

                dead_letter.append({
                    "stage": stage_name,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.utcnow().isoformat(),
                })

            stage_result["duration_ms"] = round(
                (time.perf_counter() - stage_start) * 1000, 2
            )
            result["stages"].append(stage_result)

        # Persist new watermark
        if context.get("new_watermark"):
            set_watermark(conn, pipeline_name, datetime.fromisoformat(context["new_watermark"]))
            result["watermark"] = context["new_watermark"]

    except Exception as e:
        overall_status = PipelineStatus.FAILED
        logger.error(f"Pipeline execution failed: {pipeline_name}", exc_info=True)

    finally:
        return_connection(conn)

    completed_at = datetime.utcnow()
    result["status"] = overall_status
    result["completed_at"] = completed_at.isoformat()
    total_duration = (completed_at - started_at).total_seconds()
    result["total_duration_seconds"] = round(total_duration, 2)

    if dead_letter:
        result["dead_letter_count"] = len(dead_letter)

    # Update pipeline state
    pipeline["last_run"] = completed_at.isoformat()
    pipeline["last_status"] = overall_status

    # Store in history
    _pipeline_history.insert(0, result)
    if len(_pipeline_history) > 50:
        _pipeline_history.pop()

    return result


# ─── API Routes ──────────────────────────────────────────────

@router.post("/run/{pipeline_name}")
async def trigger_pipeline(
    request: Request,
    pipeline_name: str,
    force_full: bool = Query(False, description="Ignore watermark and reprocess all data"),
):
    """Trigger a registered pipeline. Returns execution results."""
    if pipeline_name not in _pipelines:
        raise HTTPException(
            status_code=404,
            detail=f"Pipeline '{pipeline_name}' not found. Available: {list(_pipelines.keys())}",
        )

    try:
        result = run_pipeline(pipeline_name, force_full=force_full)
        return result
    except Exception as e:
        logger.error(f"Pipeline trigger failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pipeline execution failed: {str(e)}")


@router.get("/status")
async def pipeline_status(request: Request):
    """Get status of all registered pipelines."""
    statuses = {}
    for name, pipeline in _pipelines.items():
        statuses[name] = {
            "name": name,
            "stage_count": len(pipeline["stages"]),
            "stages": [s[0] for s in pipeline["stages"]],
            "last_run": pipeline["last_run"],
            "last_status": pipeline["last_status"],
            "run_count": pipeline["run_count"],
        }

    return {
        "pipelines": statuses,
        "total_registered": len(_pipelines),
    }


@router.get("/history")
async def pipeline_history(
    request: Request,
    limit: int = Query(10, ge=1, le=50),
    pipeline_name: Optional[str] = None,
):
    """Get recent pipeline execution history."""
    history = _pipeline_history

    if pipeline_name:
        history = [h for h in history if h["pipeline_name"] == pipeline_name]

    return {
        "runs": history[:limit],
        "total_available": len(history),
    }
