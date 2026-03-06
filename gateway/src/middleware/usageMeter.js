// ═══════════════════════════════════════════════════════════════
// Usage Metering Middleware
// ═══════════════════════════════════════════════════════════════
// Logs { tenant_id, user_id, event_type, timestamp } to the
// usage_events table for billing/analytics.  Fire-and-forget to
// avoid adding latency to user requests.
// ═══════════════════════════════════════════════════════════════
const logger = require('../utils/logger');

/**
 * Maps HTTP method + route prefix to a usage event type.
 * Only routes that should be metered appear here.
 */
const ROUTE_EVENT_MAP = {
    'POST /api/v1/reports': 'report_generated',
    'GET /api/v1/exports': 'export_requested',
    'POST /api/v1/auth/login': 'login',
    'POST /api/v1/pipeline/run': 'data_pipeline_run',
};

/**
 * Determines the usage event type for a given request.
 * Falls back to 'api_call' for all authenticated requests.
 *
 * @param {string} method - HTTP method
 * @param {string} path - request path
 * @returns {string} usage event type
 */
function resolveEventType(method, path) {
    for (const [pattern, eventType] of Object.entries(ROUTE_EVENT_MAP)) {
        const [m, p] = pattern.split(' ');
        if (method === m && (path === p || path.startsWith(p + '/'))) {
            return eventType;
        }
    }
    return 'api_call';
}

/**
 * Middleware factory: creates usage metering middleware.
 * Must be mounted AFTER authenticate (needs req.user).
 *
 * @param {import('pg').Pool} pool - database connection pool
 * @returns {import('express').RequestHandler}
 */
function createUsageMeter(pool) {
    return (req, res, next) => {
        // Only meter authenticated requests
        if (!req.user) {
            return next();
        }

        // Meter after response completes (fire-and-forget)
        res.on('finish', () => {
            // Only meter successful requests (2xx, 3xx)
            if (res.statusCode >= 400) return;

            const eventType = resolveEventType(req.method, req.path);
            const tenantId = req.user.tenantId || 1;
            const userId = req.user.id;

            pool.query(
                `INSERT INTO usage_events (tenant_id, user_id, event_type, metadata)
                 VALUES ($1, $2, $3::usage_event_type, $4)`,
                [
                    tenantId,
                    userId,
                    eventType,
                    JSON.stringify({
                        path: req.path,
                        method: req.method,
                        status: res.statusCode,
                        correlationId: req.requestId,
                    }),
                ]
            ).catch(err => {
                // Usage metering failure must not break the application
                logger.error('Usage metering write failed', {
                    error: err.message,
                    tenantId,
                    userId,
                    eventType,
                });
            });
        });

        next();
    };
}

module.exports = { createUsageMeter, resolveEventType };
