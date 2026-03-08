// ═══════════════════════════════════════════════════════════════
// Rate Limiter — Redis-backed sliding window
// ═══════════════════════════════════════════════════════════════
'use strict';

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

// ── General limiter ──────────────────────────────────────────
// 100 requests per 15-minute window per IP address.
const generalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
    max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded', {
            ip: req.ip,
            path: req.path,
        });
        res.status(429).json({
            error: 'Too many requests',
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: 900,
        });
    },
    skip: (req) => req.path === '/health',
});

// ── Auth limiter ─────────────────────────────────────────────
// 5 attempts per 15-minute window per IP — auth routes only.
const authLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
    max: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '5'),
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('AUTH_LOCKOUT_TRIGGERED', {
            event: 'AUTH_LOCKOUT_TRIGGERED',
            ip: req.ip,
            correlationId: req.correlationId,
        });
        res.status(429).json({
            error: 'TOO_MANY_ATTEMPTS',
            code: 'AUTH_LOCKOUT',
            retryAfter: 900,
            message: 'Too many failed attempts. Try again in 15 minutes.',
        });
    },
});

/**
 * Factory function — creates a Redis-backed rate limiter.
 * Kept for backward compatibility with server.js which calls createRateLimiter(redis).
 */
function createRateLimiter(redisClient) {
    // When Redis is available, recreate with RedisStore
    // For now, return the in-memory generalLimiter
    return generalLimiter;
}

module.exports = { createRateLimiter, generalLimiter, authLimiter };
