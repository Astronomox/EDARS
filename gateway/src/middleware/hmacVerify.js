// ═══════════════════════════════════════════════════════════════
// HMAC Request Signing & Verification Middleware
// ═══════════════════════════════════════════════════════════════
// Ensures every API request is cryptographically signed by the
// client application, preventing replay attacks and MITM.
//
// Headers required:
//   X-Signature:  HMAC-SHA256(signing_key, canonical_string)
//   X-Timestamp:  ISO 8601 timestamp (must be within 5 minutes)
//   X-Nonce:      Unique per-request UUID (prevents replay)
//
// Canonical string format:
//   METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH
// ═══════════════════════════════════════════════════════════════
const crypto = require('crypto');
const logger = require('../utils/logger');

const HMAC_SECRET = process.env.HMAC_SIGNING_KEY || process.env.JWT_SECRET;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000; // 5 minutes
const NONCE_TTL = 600; // 10 minutes — nonces expire from Redis after this
const HMAC_ENABLED = process.env.HMAC_ENABLED !== 'false';

/**
 * Middleware factory: HMAC signature verification.
 * @param {import('ioredis')} redis — for nonce deduplication
 * @param {object} options
 * @param {string[]} options.excludePaths — paths exempt from signing
 */
function createHmacVerifier(redis, options = {}) {
    const excludePaths = options.excludePaths || [
        '/health', '/api/v1/auth/login', '/api/v1/auth/password-policy',
    ];

    return async (req, res, next) => {
        // Skip if HMAC is disabled (dev mode)
        if (!HMAC_ENABLED) return next();

        // Skip excluded paths
        if (excludePaths.some(p => req.path === p || req.path.startsWith(p + '/'))) {
            return next();
        }

        const signature = req.headers['x-signature'];
        const timestamp = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];

        // ── Require all signing headers ─────────────────────
        if (!signature || !timestamp || !nonce) {
            logger.warn('Missing HMAC signing headers', {
                ip: req.ip, path: req.path, requestId: req.requestId,
                hasSignature: !!signature, hasTimestamp: !!timestamp, hasNonce: !!nonce,
            });
            return res.status(401).json({
                error: 'Request signature required',
                details: 'X-Signature, X-Timestamp, and X-Nonce headers are required',
                requestId: req.requestId,
            });
        }

        // ── Validate timestamp (prevent replay) ─────────────
        const requestTime = new Date(timestamp).getTime();
        if (isNaN(requestTime)) {
            return res.status(400).json({
                error: 'Invalid timestamp format',
                requestId: req.requestId,
            });
        }

        const drift = Math.abs(Date.now() - requestTime);
        if (drift > MAX_CLOCK_SKEW_MS) {
            logger.warn('Request timestamp outside acceptable window', {
                ip: req.ip, drift: `${drift}ms`, maxAllowed: `${MAX_CLOCK_SKEW_MS}ms`,
                requestId: req.requestId,
            });
            return res.status(401).json({
                error: 'Request timestamp expired or invalid',
                serverTime: new Date().toISOString(),
                requestId: req.requestId,
            });
        }

        // ── Check nonce uniqueness (prevent replay) ─────────
        try {
            const nonceKey = `hmac:nonce:${nonce}`;
            const exists = await redis.get(nonceKey);
            if (exists) {
                logger.warn('Duplicate nonce detected (replay attempt)', {
                    ip: req.ip, nonce, requestId: req.requestId,
                });
                return res.status(401).json({
                    error: 'Duplicate request (nonce already used)',
                    requestId: req.requestId,
                });
            }
            await redis.setex(nonceKey, NONCE_TTL, '1');
        } catch (err) {
            logger.error('Nonce check failed (Redis error)', { error: err.message });
            // Fail open: allow the request but log the failure
        }

        // ── Compute expected signature ──────────────────────
        const bodyHash = crypto
            .createHash('sha256')
            .update(JSON.stringify(req.body || {}))
            .digest('hex');

        const canonicalString = [
            req.method.toUpperCase(),
            req.originalUrl || req.path,
            timestamp,
            nonce,
            bodyHash,
        ].join('\n');

        const expectedSignature = crypto
            .createHmac('sha256', HMAC_SECRET)
            .update(canonicalString)
            .digest('hex');

        // ── Constant-time comparison ────────────────────────
        const sigBuffer = Buffer.from(signature, 'hex');
        const expectedBuffer = Buffer.from(expectedSignature, 'hex');

        if (sigBuffer.length !== expectedBuffer.length ||
            !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
            logger.warn('HMAC signature mismatch', {
                ip: req.ip,
                path: req.path,
                method: req.method,
                requestId: req.requestId,
            });
            return res.status(401).json({
                error: 'Invalid request signature',
                requestId: req.requestId,
            });
        }

        // ── Signature valid — attach metadata ───────────────
        req.signatureVerified = true;
        req.signatureTimestamp = timestamp;

        next();
    };
}

/**
 * Utility: Generate HMAC signature for a request.
 * Used by internal services and provided for client SDK reference.
 */
function signRequest(method, path, body, signingKey) {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();

    const bodyHash = crypto
        .createHash('sha256')
        .update(JSON.stringify(body || {}))
        .digest('hex');

    const canonicalString = [
        method.toUpperCase(),
        path,
        timestamp,
        nonce,
        bodyHash,
    ].join('\n');

    const signature = crypto
        .createHmac('sha256', signingKey)
        .update(canonicalString)
        .digest('hex');

    return {
        'X-Signature': signature,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
    };
}

module.exports = { createHmacVerifier, signRequest };
