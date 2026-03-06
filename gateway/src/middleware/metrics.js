// ═══════════════════════════════════════════════════════════════
// Prometheus-Compatible Metrics Middleware
// ═══════════════════════════════════════════════════════════════
// Exposes /metrics endpoint in Prometheus text format.
// Tracks: request latency, error rates, active connections,
//         circuit breaker state, memory, event loop lag.
// ═══════════════════════════════════════════════════════════════
const logger = require('../utils/logger');
const { getBreakerStates } = require('./circuitBreaker');

// ─── Metric Storage ──────────────────────────────────────────
const metrics = {
    // Counters
    requestsTotal: {},          // { "GET /api/v1/reports 200": count }
    errorsTotal: {},            // { "GET /api/v1/reports 500": count }
    threatBlocksTotal: 0,

    // Histograms (bucket-based)
    requestDuration: {
        buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
        observations: {},       // { route: { bucket: count, sum: total, count: n }}
    },

    // Gauges
    activeConnections: 0,
    dbPoolActive: 0,
    dbPoolIdle: 0,
    dbPoolWaiting: 0,

    // System
    startTime: Date.now(),
    eventLoopLag: 0,
};

// ─── Event Loop Lag Monitoring ───────────────────────────────
let lastCheck = process.hrtime.bigint();
setInterval(() => {
    const now = process.hrtime.bigint();
    const expected = 1000n * 1000000n; // 1000ms in nanoseconds
    const actual = now - lastCheck;
    metrics.eventLoopLag = Number(actual - expected) / 1e6; // ms
    lastCheck = now;
}, 1000);

// ─── Middleware: Track Request Metrics ───────────────────────
function metricsCollector(req, res, next) {
    metrics.activeConnections++;
    const start = process.hrtime.bigint();

    res.on('finish', () => {
        metrics.activeConnections--;
        const durationMs = Number(process.hrtime.bigint() - start) / 1e6;

        // Route label (normalise UUIDs and numeric IDs)
        const route = normaliseRoute(req.method, req.route?.path || req.path);
        const statusClass = `${Math.floor(res.statusCode / 100)}xx`;
        const key = `${route} ${res.statusCode}`;

        // Increment request counter
        metrics.requestsTotal[key] = (metrics.requestsTotal[key] || 0) + 1;

        // Increment error counter
        if (res.statusCode >= 400) {
            metrics.errorsTotal[key] = (metrics.errorsTotal[key] || 0) + 1;
        }

        // Track threat blocks
        if (res.statusCode === 403 && req.threatScore > 0) {
            metrics.threatBlocksTotal++;
        }

        // Histogram observation
        recordDuration(route, durationMs);
    });

    next();
}

function recordDuration(route, durationMs) {
    if (!metrics.requestDuration.observations[route]) {
        metrics.requestDuration.observations[route] = {
            buckets: {},
            sum: 0,
            count: 0,
        };
    }

    const obs = metrics.requestDuration.observations[route];
    obs.sum += durationMs;
    obs.count++;

    for (const bucket of metrics.requestDuration.buckets) {
        if (durationMs <= bucket) {
            obs.buckets[bucket] = (obs.buckets[bucket] || 0) + 1;
        }
    }
    // +Inf bucket always incremented
    obs.buckets['+Inf'] = (obs.buckets['+Inf'] || 0) + 1;
}

function normaliseRoute(method, path) {
    // Replace UUIDs and numeric IDs with placeholders
    const normalised = path
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, ':uuid')
        .replace(/\/\d+/g, '/:id');
    return `${method} ${normalised}`;
}

// ─── Route: /metrics ─────────────────────────────────────────
function metricsEndpoint(pool, redis) {
    return async (req, res) => {
        try {
            // Gather DB pool stats
            if (pool) {
                metrics.dbPoolActive = pool.totalCount - pool.idleCount;
                metrics.dbPoolIdle = pool.idleCount;
                metrics.dbPoolWaiting = pool.waitingCount;
            }

            const lines = [];
            const now = Date.now();

            // ── Process uptime ──────────────────────────────
            lines.push('# HELP edars_uptime_seconds Time since process start');
            lines.push('# TYPE edars_uptime_seconds gauge');
            lines.push(`edars_uptime_seconds ${((now - metrics.startTime) / 1000).toFixed(0)}`);

            // ── Request totals ──────────────────────────────
            lines.push('# HELP edars_http_requests_total Total HTTP requests');
            lines.push('# TYPE edars_http_requests_total counter');
            for (const [key, count] of Object.entries(metrics.requestsTotal)) {
                const parts = key.split(' ');
                const status = parts.pop();
                const route = parts.join(' ');
                lines.push(`edars_http_requests_total{route="${escapeLabel(route)}",status="${status}"} ${count}`);
            }

            // ── Error totals ────────────────────────────────
            lines.push('# HELP edars_http_errors_total Total HTTP errors (4xx, 5xx)');
            lines.push('# TYPE edars_http_errors_total counter');
            for (const [key, count] of Object.entries(metrics.errorsTotal)) {
                const parts = key.split(' ');
                const status = parts.pop();
                const route = parts.join(' ');
                lines.push(`edars_http_errors_total{route="${escapeLabel(route)}",status="${status}"} ${count}`);
            }

            // ── Request duration histogram ──────────────────
            lines.push('# HELP edars_http_request_duration_ms HTTP request latency in ms');
            lines.push('# TYPE edars_http_request_duration_ms histogram');
            for (const [route, obs] of Object.entries(metrics.requestDuration.observations)) {
                for (const bucket of [...metrics.requestDuration.buckets, '+Inf']) {
                    const val = obs.buckets[bucket] || 0;
                    lines.push(`edars_http_request_duration_ms_bucket{route="${escapeLabel(route)}",le="${bucket}"} ${val}`);
                }
                lines.push(`edars_http_request_duration_ms_sum{route="${escapeLabel(route)}"} ${obs.sum.toFixed(2)}`);
                lines.push(`edars_http_request_duration_ms_count{route="${escapeLabel(route)}"} ${obs.count}`);
            }

            // ── Active connections ──────────────────────────
            lines.push('# HELP edars_active_connections Current active HTTP connections');
            lines.push('# TYPE edars_active_connections gauge');
            lines.push(`edars_active_connections ${metrics.activeConnections}`);

            // ── Threat blocks ───────────────────────────────
            lines.push('# HELP edars_threat_blocks_total Requests blocked by threat intelligence');
            lines.push('# TYPE edars_threat_blocks_total counter');
            lines.push(`edars_threat_blocks_total ${metrics.threatBlocksTotal}`);

            // ── DB Pool ─────────────────────────────────────
            lines.push('# HELP edars_db_pool_active Active database connections');
            lines.push('# TYPE edars_db_pool_active gauge');
            lines.push(`edars_db_pool_active ${metrics.dbPoolActive}`);
            lines.push('# HELP edars_db_pool_idle Idle database connections');
            lines.push('# TYPE edars_db_pool_idle gauge');
            lines.push(`edars_db_pool_idle ${metrics.dbPoolIdle}`);
            lines.push('# HELP edars_db_pool_waiting Waiting database connection requests');
            lines.push('# TYPE edars_db_pool_waiting gauge');
            lines.push(`edars_db_pool_waiting ${metrics.dbPoolWaiting}`);

            // ── Event Loop Lag ──────────────────────────────
            lines.push('# HELP edars_event_loop_lag_ms Event loop lag in ms');
            lines.push('# TYPE edars_event_loop_lag_ms gauge');
            lines.push(`edars_event_loop_lag_ms ${metrics.eventLoopLag.toFixed(2)}`);

            // ── Memory ──────────────────────────────────────
            const mem = process.memoryUsage();
            lines.push('# HELP edars_memory_rss_bytes Resident set size');
            lines.push('# TYPE edars_memory_rss_bytes gauge');
            lines.push(`edars_memory_rss_bytes ${mem.rss}`);
            lines.push('# HELP edars_memory_heap_used_bytes Heap used');
            lines.push('# TYPE edars_memory_heap_used_bytes gauge');
            lines.push(`edars_memory_heap_used_bytes ${mem.heapUsed}`);

            // ── Circuit Breakers ────────────────────────────
            const breakers = getBreakerStates();
            lines.push('# HELP edars_circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)');
            lines.push('# TYPE edars_circuit_breaker_state gauge');
            for (const [name, state] of Object.entries(breakers)) {
                const stateVal = state.state === 'CLOSED' ? 0 : state.state === 'OPEN' ? 1 : 2;
                lines.push(`edars_circuit_breaker_state{service="${name}"} ${stateVal}`);
            }

            res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
            res.send(lines.join('\n') + '\n');
        } catch (err) {
            logger.error('Metrics generation failed', { error: err.message });
            res.status(500).send('# Error generating metrics\n');
        }
    };
}

function escapeLabel(str) {
    return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

module.exports = { metricsCollector, metricsEndpoint };
