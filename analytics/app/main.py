# ═══════════════════════════════════════════════════════════════
# EDARS Analytics Engine — FastAPI Main Application  (ENHANCED v3.0)
# Caching, trend analysis, anomaly detection, data health,
# predictive forecasting, ETL pipeline engine
# ═══════════════════════════════════════════════════════════════
import os
import logging
import time
import json
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import FastAPI, Depends, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.database import get_db_pool, close_db_pool
from app.cache import RedisCache
from app.routes import dashboard, sales, activity, kpis, generate, trends, anomalies
from app.routes import forecasting, pipeline

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("edars.analytics")

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "CHANGE_ME")


# ─── Service Token Validation ────────────────────────────────
async def verify_service_token(x_service_token: str = Header(...)):
    if x_service_token != SERVICE_TOKEN:
        logger.warning("Invalid service token received")
        raise HTTPException(status_code=403, detail="Invalid service token")
    return True


# ─── Request Timing Middleware ────────────────────────────────
class TimingMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                elapsed = (time.perf_counter() - start) * 1000
                headers = list(message.get("headers", []))
                headers.append([b"x-response-time", f"{elapsed:.2f}ms".encode()])
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ─── Lifespan ─────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Analytics Engine v3.0 starting — initialising pools")
    app.state.db_pool = get_db_pool()
    app.state.cache = RedisCache()
    yield
    logger.info("Analytics Engine shutting down")
    close_db_pool(app.state.db_pool)
    app.state.cache.close()


# ─── App ──────────────────────────────────────────────────────
app = FastAPI(
    title="EDARS Analytics Engine",
    description="Internal analytics, reporting, trend analysis, anomaly detection, forecasting, and data pipelines",
    version="3.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# Timing middleware
app.add_middleware(TimingMiddleware)


# ─── Health Check ─────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "analytics-engine",
        "version": "3.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/health/ready")
async def readiness(request: Request):
    """Deep readiness check with DB pool status."""
    from app.database import get_connection, return_connection
    checks = {}
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return_connection(conn)
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {e}"

    try:
        request.app.state.cache.ping()
        checks["cache"] = "healthy"
    except Exception:
        checks["cache"] = "unavailable (non-critical)"

    return {"status": "ready", "checks": checks}


# ─── Routes ──────────────────────────────────────────────────
# Original routes
for r in [dashboard, sales, activity, kpis, generate, trends, anomalies]:
    app.include_router(
        r.router,
        prefix="/api/v1",
        dependencies=[Depends(verify_service_token)],
    )

# Enhanced routes (v3.0)
app.include_router(
    forecasting.router,
    prefix="/api/v1",
    dependencies=[Depends(verify_service_token)],
    tags=["Forecasting"],
)

app.include_router(
    pipeline.router,
    prefix="/api/v1",
    dependencies=[Depends(verify_service_token)],
    tags=["Pipeline"],
)
