// ═══════════════════════════════════════════════════════════════
// Request Tracing Middleware — X-Request-ID
// ═══════════════════════════════════════════════════════════════
// Assigns a unique UUID to every request. Propagated through all
// internal service calls for end-to-end distributed tracing.
const { v4: uuidv4 } = require('uuid');

function requestTracer(req, res, next) {
    // Honour upstream trace ID if present (from Nginx or load balancer)
    const traceId = req.headers['x-request-id'] || uuidv4();

    req.requestId = traceId;
    res.setHeader('X-Request-ID', traceId);

    // Timing header for performance observability
    req._startTime = process.hrtime.bigint();
    res.on('finish', () => {
        const elapsed = Number(process.hrtime.bigint() - req._startTime) / 1e6;
        res.setHeader('X-Response-Time', `${elapsed.toFixed(2)}ms`);
    });

    next();
}

module.exports = { requestTracer };
