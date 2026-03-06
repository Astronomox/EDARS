// ═══════════════════════════════════════════════════════════════
// JWT Authentication Middleware
// ═══════════════════════════════════════════════════════════════
// - Token blacklist checking via Redis
// - Zero-downtime JWT_SECRET rotation (legacy key fallback)
// - Tenant context extraction and validation
// - Role-based access control (RBAC)
// ═══════════════════════════════════════════════════════════════
'use strict';

const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates JWT from Authorization header.
 * Checks token blacklist in Redis (for logged-out tokens).
 * Supports zero-downtime secret rotation via JWT_SECRET_LEGACY.
 * Attaches decoded user payload to req.user on success.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
async function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'AUTHENTICATION_REQUIRED',
            code: 'MISSING_TOKEN',
            correlationId: req.requestId,
        });
    }

    const token = authHeader.slice(7);

    try {
        // Check token blacklist in Redis
        if (req.redis) {
            const blacklisted = await req.redis.get(`blacklist:${token}`);
            if (blacklisted) {
                logger.warn('Blacklisted token used', {
                    ip: req.ip,
                    requestId: req.requestId,
                });
                return res.status(401).json({
                    error: 'TOKEN_REVOKED',
                    code: 'BLACKLISTED',
                    correlationId: req.requestId,
                });
            }
        }

        // ─── JWT Verification with Secret Rotation Support ───
        // Try primary secret first. If it fails and a legacy
        // secret exists, try that — supports zero-downtime rotation.
        // Old tokens (up to 8h old) still work during the rotation window.
        let decoded;

        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET, {
                algorithms: ['HS256'],
            });
        } catch (primaryErr) {
            if (process.env.JWT_SECRET_LEGACY) {
                try {
                    decoded = jwt.verify(token, process.env.JWT_SECRET_LEGACY, {
                        algorithms: ['HS256'],
                    });
                } catch (legacyErr) {
                    return res.status(401).json({
                        error: 'INVALID_TOKEN',
                        code: 'TOKEN_EXPIRED_OR_INVALID',
                        correlationId: req.requestId,
                    });
                }
            } else {
                if (primaryErr.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        error: 'TOKEN_EXPIRED',
                        code: 'TOKEN_EXPIRED_OR_INVALID',
                        correlationId: req.requestId,
                    });
                }
                return res.status(401).json({
                    error: 'INVALID_TOKEN',
                    code: 'TOKEN_EXPIRED_OR_INVALID',
                    correlationId: req.requestId,
                });
            }
        }

        // Reject refresh tokens used as access tokens
        if (decoded.type === 'refresh') {
            return res.status(401).json({
                error: 'INVALID_TOKEN',
                code: 'REFRESH_AS_ACCESS',
                correlationId: req.requestId,
            });
        }

        // ─── Extract user context ────────────────────────────
        req.user = {
            userId: decoded.userId,
            email: decoded.email,
            role: decoded.role,
            tenantId: decoded.tenantId,
            plan: decoded.plan,
            slug: decoded.slug,
            departmentId: decoded.departmentId,
            fullName: decoded.fullName,
            // Backward compat: some routes use req.user.id
            id: decoded.userId,
        };

        // ─── Hard block: never allow a request without valid tenantId
        if (!req.user.tenantId || !UUID_REGEX.test(req.user.tenantId)) {
            logger.warn('Token missing valid tenantId', {
                ip: req.ip,
                requestId: req.requestId,
            });
            return res.status(401).json({
                error: 'INVALID_TOKEN',
                code: 'MISSING_TENANT',
                correlationId: req.requestId,
            });
        }

        next();
    } catch (err) {
        logger.warn('JWT verification failed', {
            error: err.message,
            ip: req.ip,
            requestId: req.requestId,
        });

        return res.status(401).json({
            error: 'INVALID_TOKEN',
            code: 'TOKEN_EXPIRED_OR_INVALID',
            correlationId: req.requestId,
        });
    }
}

/**
 * Role-Based Access Control middleware factory.
 * Returns 403 if the authenticated user's role is not
 * in the allowed list.
 *
 * @param  {...string} allowedRoles — roles permitted to access the route
 * @returns {import('express').RequestHandler}
 */
function authorize(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'AUTHENTICATION_REQUIRED',
                code: 'MISSING_USER',
                correlationId: req.requestId,
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            logger.warn('Unauthorized access attempt', {
                userId: req.user.userId,
                role: req.user.role,
                requiredRoles: allowedRoles,
                path: req.path,
                requestId: req.requestId,
            });
            return res.status(403).json({
                error: 'INSUFFICIENT_PERMISSIONS',
                code: 'ROLE_DENIED',
                correlationId: req.requestId,
            });
        }

        next();
    };
}

module.exports = { authenticate, authorize };
