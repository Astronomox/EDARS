// ═══════════════════════════════════════════════════════════════
// Health Check Routes — Deep System Diagnostics
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const os = require('os');
const { getBreakerStates } = require('../middleware/circuitBreaker');

/**
 * Factory: creates health router with injected dependencies.
 */
module.exports = function healthRoutes(pool, redis) {
    const router = express.Router();

    // ── Simple liveness probe ──────────────────────────────────
    router.get('/', async (req, res) => {
        res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // ── Deep readiness probe ───────────────────────────────────
    router.get('/ready', async (req, res) => {
        const checks = {};
        let healthy = true;

        // Database
        try {
            const start = Date.now();
            await pool.query('SELECT 1');
            checks.database = {
                status: 'healthy',
                latency: `${Date.now() - start}ms`,
                pool: {
                    total: pool.totalCount,
                    idle: pool.idleCount,
                    waiting: pool.waitingCount,
                },
            };
        } catch (err) {
            checks.database = { status: 'unhealthy', error: err.message };
            healthy = false;
        }

        // Redis
        try {
            const start = Date.now();
            await redis.ping();
            const info = await redis.info('memory');
            const usedMemory = info.match(/used_memory_human:(\S+)/)?.[1] || 'unknown';
            checks.redis = {
                status: 'healthy',
                latency: `${Date.now() - start}ms`,
                memory: usedMemory,
            };
        } catch (err) {
            checks.redis = { status: 'unhealthy', error: err.message };
            healthy = false;
        }

        // Circuit breakers
        checks.circuitBreakers = getBreakerStates();

        // Analytics service reachability
        try {
            const analyticsUrl = process.env.ANALYTICS_URL || 'http://analytics:8000';
            const fetch = (await import('node-fetch')).default;
            const start = Date.now();
            const analyticsRes = await fetch(`${analyticsUrl}/health`, { timeout: 5000 });
            const analyticsBody = await analyticsRes.json().catch(() => ({}));
            checks.analytics = {
                status: analyticsRes.ok ? 'healthy' : 'unhealthy',
                latency: `${Date.now() - start}ms`,
                version: analyticsBody.version || 'unknown',
            };
            if (!analyticsRes.ok) healthy = false;
        } catch (err) {
            checks.analytics = { status: 'unreachable', error: err.message };
            // Analytics being unreachable is degraded, not unhealthy
            // (circuit breaker will handle this)
        }

        // System
        checks.system = {
            uptime: `${Math.floor(process.uptime())}s`,
            memory: {
                rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
                heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
                heapMax: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
            },
            cpu: os.loadavg(),
            platform: `${os.platform()} ${os.arch()}`,
            nodeVersion: process.version,
        };

        const statusCode = healthy ? 200 : 503;
        res.status(statusCode).json({
            status: healthy ? 'ready' : 'degraded',
            timestamp: new Date().toISOString(),
            checks,
        });
    });

    // ── Metrics endpoint (Prometheus-compatible) ───────────────
    router.get('/metrics', async (req, res) => {
        const mem = process.memoryUsage();
        const breakers = getBreakerStates();

        let metrics = '';
        metrics += `# HELP edars_process_uptime_seconds Process uptime\n`;
        metrics += `# TYPE edars_process_uptime_seconds gauge\n`;
        metrics += `edars_process_uptime_seconds ${Math.floor(process.uptime())}\n\n`;

        metrics += `# HELP edars_memory_rss_bytes Resident set size\n`;
        metrics += `# TYPE edars_memory_rss_bytes gauge\n`;
        metrics += `edars_memory_rss_bytes ${mem.rss}\n\n`;

        metrics += `# HELP edars_memory_heap_used_bytes Heap used\n`;
        metrics += `# TYPE edars_memory_heap_used_bytes gauge\n`;
        metrics += `edars_memory_heap_used_bytes ${mem.heapUsed}\n\n`;

        metrics += `# HELP edars_db_pool_total Total pool connections\n`;
        metrics += `# TYPE edars_db_pool_total gauge\n`;
        metrics += `edars_db_pool_total ${pool.totalCount}\n\n`;

        metrics += `# HELP edars_db_pool_idle Idle pool connections\n`;
        metrics += `# TYPE edars_db_pool_idle gauge\n`;
        metrics += `edars_db_pool_idle ${pool.idleCount}\n\n`;

        metrics += `# HELP edars_db_pool_waiting Waiting pool requests\n`;
        metrics += `# TYPE edars_db_pool_waiting gauge\n`;
        metrics += `edars_db_pool_waiting ${pool.waitingCount}\n\n`;

        for (const [name, state] of Object.entries(breakers)) {
            metrics += `# HELP edars_circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)\n`;
            metrics += `# TYPE edars_circuit_breaker_state gauge\n`;
            const stateNum = state.state === 'CLOSED' ? 0 : state.state === 'OPEN' ? 1 : 2;
            metrics += `edars_circuit_breaker_state{service="${name}"} ${stateNum}\n`;
            metrics += `edars_circuit_breaker_failures{service="${name}"} ${state.totalFailures}\n`;
            metrics += `edars_circuit_breaker_requests{service="${name}"} ${state.totalRequests}\n\n`;
        }

        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(metrics);
    });

    return router;
};
