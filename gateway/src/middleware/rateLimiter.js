// ═══════════════════════════════════════════════════════════════
// Rate Limiter — Redis-backed sliding window
// ═══════════════════════════════════════════════════════════════
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis').default;
const logger = require('../utils/logger');

/**
 * Creates a rate limiter backed by Redis.
 * 100 requests per 15-minute window per IP address.
 */
function createRateLimiter(redisClient) {
    return rateLimit({
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 min
        max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
        standardHeaders: true,
        legacyHeaders: false,
        store: new RedisStore({
            sendCommand: (...args) => redisClient.call(...args),
        }),
        handler: (req, res) => {
            logger.warn('Rate limit exceeded', {
                ip: req.ip,
                path: req.path,
            });
            res.status(429).json({
                error: 'Too many requests',
                retryAfter: res.getHeader('Retry-After'),
            });
        },
        skip: (req) => req.path === '/health',
    });
}

module.exports = { createRateLimiter };
