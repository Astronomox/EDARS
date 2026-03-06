// ═══════════════════════════════════════════════════════════════
// Circuit Breaker Middleware
// ═══════════════════════════════════════════════════════════════
// Protects the gateway from cascading failures when downstream
// services (e.g. analytics) become unresponsive.
//
// States: CLOSED → OPEN → HALF_OPEN → CLOSED
//   CLOSED:    Normal operation. Failures are counted.
//   OPEN:      Requests fail fast with 503. No downstream calls.
//   HALF_OPEN: A single probe request is allowed through to test recovery.

const logger = require('../utils/logger');

const breakers = {};

const DEFAULT_OPTIONS = {
    failureThreshold: 5,       // Failures before opening
    resetTimeoutMs: 30000,   // Time in OPEN state before trying HALF_OPEN
    monitorWindowMs: 60000,   // Rolling window for counting failures
};

function getBreaker(name) {
    if (!breakers[name]) {
        breakers[name] = {
            state: 'CLOSED',
            failures: 0,
            lastFailureAt: null,
            lastStateChange: Date.now(),
            successCount: 0,
            totalRequests: 0,
            totalFailures: 0,
        };
    }
    return breakers[name];
}

function circuitBreaker(serviceName, options = {}) {
    const opts = { ...DEFAULT_OPTIONS, ...options };

    return (req, res, next) => {
        const breaker = getBreaker(serviceName);
        breaker.totalRequests++;

        if (breaker.state === 'OPEN') {
            const elapsed = Date.now() - breaker.lastStateChange;

            if (elapsed >= opts.resetTimeoutMs) {
                // Transition to HALF_OPEN — allow one probe request
                breaker.state = 'HALF_OPEN';
                breaker.lastStateChange = Date.now();
                logger.info(`Circuit breaker [${serviceName}] → HALF_OPEN (probe request)`);
            } else {
                // Fail fast
                logger.warn(`Circuit breaker [${serviceName}] OPEN — rejecting request`, {
                    requestId: req.requestId,
                    retryIn: `${Math.ceil((opts.resetTimeoutMs - elapsed) / 1000)}s`,
                });
                return res.status(503).json({
                    error: `Service temporarily unavailable: ${serviceName}`,
                    retryAfter: Math.ceil((opts.resetTimeoutMs - elapsed) / 1000),
                    requestId: req.requestId,
                });
            }
        }

        // Intercept response to track success/failure
        const originalJson = res.json.bind(res);
        res.json = (body) => {
            if (res.statusCode >= 500 || res.statusCode === 502) {
                recordFailure(breaker, serviceName, opts);
            } else {
                recordSuccess(breaker, serviceName);
            }
            return originalJson(body);
        };

        next();
    };
}

function recordFailure(breaker, serviceName, opts) {
    breaker.failures++;
    breaker.totalFailures++;
    breaker.lastFailureAt = Date.now();

    if (breaker.state === 'HALF_OPEN') {
        // Probe failed — reopen
        breaker.state = 'OPEN';
        breaker.lastStateChange = Date.now();
        logger.error(`Circuit breaker [${serviceName}] → OPEN (probe failed)`);
    } else if (breaker.failures >= opts.failureThreshold) {
        breaker.state = 'OPEN';
        breaker.lastStateChange = Date.now();
        logger.error(`Circuit breaker [${serviceName}] → OPEN (threshold ${opts.failureThreshold} reached)`, {
            failures: breaker.failures,
            totalFailures: breaker.totalFailures,
        });
    }
}

function recordSuccess(breaker, serviceName) {
    if (breaker.state === 'HALF_OPEN') {
        // Probe succeeded — close the circuit
        breaker.state = 'CLOSED';
        breaker.failures = 0;
        breaker.lastStateChange = Date.now();
        breaker.successCount++;
        logger.info(`Circuit breaker [${serviceName}] → CLOSED (recovered)`);
    } else {
        breaker.successCount++;
        // Decay failure count on success
        if (breaker.failures > 0) breaker.failures--;
    }
}

/**
 * Returns the state of all circuit breakers (for /health endpoint).
 */
function getBreakerStates() {
    const states = {};
    for (const [name, breaker] of Object.entries(breakers)) {
        states[name] = {
            state: breaker.state,
            failures: breaker.failures,
            totalRequests: breaker.totalRequests,
            totalFailures: breaker.totalFailures,
            successCount: breaker.successCount,
            lastFailure: breaker.lastFailureAt ? new Date(breaker.lastFailureAt).toISOString() : null,
        };
    }
    return states;
}

module.exports = { circuitBreaker, getBreakerStates };
