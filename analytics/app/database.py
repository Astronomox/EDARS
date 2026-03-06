# ═══════════════════════════════════════════════════════════════
# Database Connection Pool
# ═══════════════════════════════════════════════════════════════
import os
import logging
from psycopg2 import pool as pg_pool

logger = logging.getLogger("edars.analytics.db")

_pool = None


def get_db_pool():
    global _pool
    if _pool is None:
        _pool = pg_pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            dbname=os.getenv("DB_NAME", "edars"),
            user=os.getenv("DB_USER", "edars_admin"),
            password=os.getenv("DB_PASSWORD", ""),
        )
        logger.info("Database connection pool created")
    return _pool


def close_db_pool(pool=None):
    global _pool
    target = pool or _pool
    if target:
        target.closeall()
        _pool = None
        logger.info("Database connection pool closed")


def get_connection():
    """Get a connection from the pool. Caller must return it."""
    p = get_db_pool()
    return p.getconn()


def return_connection(conn):
    """Return a connection to the pool."""
    p = get_db_pool()
    p.putconn(conn)
