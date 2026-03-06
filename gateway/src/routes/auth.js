// ═══════════════════════════════════════════════════════════════
// Auth Routes — Login, Register, Token Refresh, Password Change
// ═══════════════════════════════════════════════════════════════
// Security constraints:
//   - Never log passwords in any form
//   - Never log plain-text emails — SHA-256 hash them first
//   - Timing-safe login: always ~300ms delay on failure
//   - Login rate limiter: 5 attempts / 15 min per IP
//   - Registration requires explicit ToS + Privacy consent
// ═══════════════════════════════════════════════════════════════
'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '8h';
const REFRESH_EXPIRY = '7d';
const BCRYPT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// ─── Helper: Hash email for safe logging ────────────────────
function hashEmail(email) {
    if (!email) return 'unknown';
    return crypto.createHash('sha256')
        .update(email.toLowerCase().trim())
        .digest('hex')
        .slice(0, 16);  // First 16 hex chars is enough for log correlation
}

// ─── Helper: Timing-safe delay ──────────────────────────────
// Always wait ~300ms before responding to failed login,
// regardless of failure reason. Prevents timing attacks that
// reveal whether an email exists.
function timingSafeDelay() {
    return new Promise(r => setTimeout(r, 300));
}

// ─── Password Strength Validator ─────────────────────────────
function validatePasswordStrength(password) {
    const issues = [];
    if (password.length < 12) issues.push('Minimum 12 characters required');
    if (password.length > 128) issues.push('Maximum 128 characters');
    if (!/[A-Z]/.test(password)) issues.push('At least one uppercase letter required');
    if (!/[a-z]/.test(password)) issues.push('At least one lowercase letter required');
    if (!/[0-9]/.test(password)) issues.push('At least one digit required');
    if (!/[^A-Za-z0-9]/.test(password)) issues.push('At least one special character required');
    if (/(.)\\1{3,}/.test(password)) issues.push('No more than 3 repeated characters in a row');
    if (/^(password|123456|qwerty|admin)/i.test(password)) issues.push('Common password patterns are not allowed');

    return {
        valid: issues.length === 0,
        issues,
        strength: issues.length === 0 ? 'strong' : issues.length <= 2 ? 'moderate' : 'weak',
    };
}

// ─── Account Lockout (Redis-backed) ──────────────────────────
async function checkLockout(redis, email) {
    const key = `lockout:${email}`;
    const data = await redis.get(key);
    if (!data) return { locked: false, attempts: 0 };

    const { attempts, lockedUntil } = JSON.parse(data);
    if (lockedUntil && Date.now() < lockedUntil) {
        return { locked: true, attempts, retryAfter: Math.ceil((lockedUntil - Date.now()) / 1000) };
    }
    return { locked: false, attempts };
}

async function recordFailedAttempt(redis, email) {
    const key = `lockout:${email}`;
    const data = await redis.get(key);
    let attempts = data ? JSON.parse(data).attempts + 1 : 1;

    const lockoutData = { attempts };
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
        lockoutData.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
        logger.warn('Account locked due to failed attempts', {
            emailHash: hashEmail(email),
            attempts,
        });
    }

    await redis.setex(key, 1800, JSON.stringify(lockoutData)); // TTL 30min
    return attempts;
}

async function clearLockout(redis, email) {
    await redis.del(`lockout:${email}`);
}


// ─── Login Rate Limiter (per-IP) ─────────────────────────────
// 5 attempts per 15 minutes per IP. Only counts failures.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const emailHash = hashEmail(req.body?.email);

        logger.warn('AUTH_LOCKOUT_TRIGGERED', {
            event: 'AUTH_LOCKOUT_TRIGGERED',
            emailHash,
            ip: req.ip,
            correlationId: req.requestId,
        });

        return res.status(429).json({
            error: 'TOO_MANY_ATTEMPTS',
            code: 'AUTH_LOCKOUT',
            retryAfter: 900,
            message: 'Too many failed attempts. Try again in 15 minutes.',
            correlationId: req.requestId,
        });
    },
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/auth/login
// ═══════════════════════════════════════════════════════════════
router.post('/login', loginLimiter, async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            await timingSafeDelay();
            return res.status(400).json({
                error: 'VALIDATION_ERROR',
                code: 'MISSING_CREDENTIALS',
                correlationId: req.requestId,
            });
        }

        const normEmail = email.toLowerCase().trim();

        // Check account lockout
        const lockout = await checkLockout(req.redis, normEmail);
        if (lockout.locked) {
            logger.warn('Login attempt on locked account', {
                emailHash: hashEmail(normEmail),
                ip: req.ip,
                requestId: req.requestId,
            });
            await timingSafeDelay();
            return res.status(429).json({
                error: 'TOO_MANY_ATTEMPTS',
                code: 'ACCOUNT_LOCKED',
                retryAfter: lockout.retryAfter,
                correlationId: req.requestId,
            });
        }

        // Fetch user (unscoped query — login runs before tenant context is set)
        const result = await req.db.query(
            `SELECT u.id, u.uuid, u.email, u.password_hash, u.full_name, u.role,
                    u.department_id, u.is_active
             FROM users u
             WHERE u.email = $1`,
            [normEmail]
        );

        if (result.rows.length === 0) {
            // Constant-time: always run bcrypt even if user not found
            await bcrypt.hash('dummy-password-for-timing', BCRYPT_ROUNDS);
            await recordFailedAttempt(req.redis, normEmail);
            await timingSafeDelay();
            return res.status(401).json({
                error: 'INVALID_CREDENTIALS',
                code: 'AUTH_FAILED',
                correlationId: req.requestId,
            });
        }

        const user = result.rows[0];

        if (!user.is_active) {
            await timingSafeDelay();
            return res.status(403).json({
                error: 'ACCOUNT_DEACTIVATED',
                code: 'ACCOUNT_INACTIVE',
                message: 'Account is deactivated. Contact your administrator.',
                correlationId: req.requestId,
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            await recordFailedAttempt(req.redis, normEmail);
            await timingSafeDelay();
            return res.status(401).json({
                error: 'INVALID_CREDENTIALS',
                code: 'AUTH_FAILED',
                correlationId: req.requestId,
            });
        }

        // ─── Fetch tenant for this user ─────────────────────
        const tenantResult = await req.db.query(
            `SELECT t.id, t.plan, t.slug, t.is_active
             FROM tenants t
             JOIN users u ON u.tenant_id = t.id
             WHERE u.id = $1`,
            [user.id]
        );

        const tenant = tenantResult.rows[0];

        if (!tenant || !tenant.is_active) {
            await timingSafeDelay();
            return res.status(403).json({
                error: 'TENANT_INACTIVE',
                code: 'ORG_SUSPENDED',
                message: 'Your organisation account is suspended. Contact support.',
                correlationId: req.requestId,
            });
        }

        // Clear lockout on successful login
        await clearLockout(req.redis, normEmail);

        // ─── Issue JWT with tenant context ──────────────────
        const accessToken = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role,
                tenantId: tenant.id,
                plan: tenant.plan,
                slug: tenant.slug,
                departmentId: user.department_id,
                fullName: user.full_name,
                type: 'access',
            },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: JWT_EXPIRY }
        );

        // Refresh token (longer expiry, minimal claims)
        const refreshToken = jwt.sign(
            { userId: user.id, uuid: user.uuid, type: 'refresh' },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: REFRESH_EXPIRY }
        );

        // Store refresh token in Redis
        await req.redis.setex(`refresh:${user.id}`, 7 * 24 * 3600, refreshToken);

        // Update last login
        await req.db.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

        // Audit log (unscoped — uses superuser connection at login time)
        await req.db.query(
            `INSERT INTO audit_log
                (tenant_id, user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
             VALUES ($1, $2, 'LOGIN', 'auth', $3, $4, $5, $6)`,
            [
                tenant.id, user.id, user.uuid,
                req.ip, req.get('User-Agent') || 'unknown',
                JSON.stringify({
                    timestamp: new Date().toISOString(),
                    method: 'password',
                }),
            ]
        );

        logger.info('Successful login', {
            userId: user.id,
            emailHash: hashEmail(user.email),
            tenantSlug: tenant.slug,
            ip: req.ip,
            requestId: req.requestId,
        });

        res.json({
            accessToken,
            refreshToken,
            expiresIn: JWT_EXPIRY,
            user: {
                uuid: user.uuid,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
            },
        });
    } catch (err) {
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/auth/refresh
// ═══════════════════════════════════════════════════════════════
router.post('/refresh', async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(400).json({
                error: 'VALIDATION_ERROR',
                code: 'MISSING_REFRESH_TOKEN',
                correlationId: req.requestId,
            });
        }

        // Verify refresh token (supports secret rotation)
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, JWT_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            if (process.env.JWT_SECRET_LEGACY) {
                try {
                    decoded = jwt.verify(refreshToken, process.env.JWT_SECRET_LEGACY, { algorithms: ['HS256'] });
                } catch (_) {
                    return res.status(401).json({
                        error: 'INVALID_TOKEN',
                        code: 'REFRESH_EXPIRED',
                        correlationId: req.requestId,
                    });
                }
            } else {
                return res.status(401).json({
                    error: 'INVALID_TOKEN',
                    code: 'REFRESH_EXPIRED',
                    correlationId: req.requestId,
                });
            }
        }

        if (decoded.type !== 'refresh') {
            return res.status(401).json({
                error: 'INVALID_TOKEN',
                code: 'WRONG_TOKEN_TYPE',
                correlationId: req.requestId,
            });
        }

        const userId = decoded.userId || decoded.id;

        // Verify token still in Redis
        const storedToken = await req.redis.get(`refresh:${userId}`);
        if (!storedToken || storedToken !== refreshToken) {
            return res.status(401).json({
                error: 'TOKEN_REVOKED',
                code: 'REFRESH_REVOKED',
                correlationId: req.requestId,
            });
        }

        // Fetch fresh user + tenant data
        const result = await req.db.query(
            `SELECT u.id, u.uuid, u.email, u.full_name, u.role,
                    u.department_id, u.is_active, u.tenant_id,
                    t.slug AS tenant_slug, t.plan AS tenant_plan, t.is_active AS tenant_active
             FROM users u
             JOIN tenants t ON t.id = u.tenant_id
             WHERE u.id = $1`,
            [userId]
        );

        if (result.rows.length === 0 || !result.rows[0].is_active) {
            await req.redis.del(`refresh:${userId}`);
            return res.status(401).json({
                error: 'ACCOUNT_DEACTIVATED',
                code: 'USER_INACTIVE',
                correlationId: req.requestId,
            });
        }

        const user = result.rows[0];

        if (!user.tenant_active) {
            return res.status(403).json({
                error: 'TENANT_INACTIVE',
                code: 'ORG_SUSPENDED',
                correlationId: req.requestId,
            });
        }

        // Issue new access token with tenant context
        const newAccessToken = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role,
                tenantId: user.tenant_id,
                plan: user.tenant_plan,
                slug: user.tenant_slug,
                departmentId: user.department_id,
                fullName: user.full_name,
                type: 'access',
            },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: JWT_EXPIRY }
        );

        // Rotate refresh token
        const newRefreshToken = jwt.sign(
            { userId: user.id, uuid: user.uuid, type: 'refresh' },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: REFRESH_EXPIRY }
        );
        await req.redis.setex(`refresh:${user.id}`, 7 * 24 * 3600, newRefreshToken);

        res.json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
            expiresIn: JWT_EXPIRY,
        });
    } catch (err) {
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/auth/logout
// ═══════════════════════════════════════════════════════════════
router.post('/logout', authenticate, async (req, res, next) => {
    try {
        // Revoke refresh token
        await req.redis.del(`refresh:${req.user.userId}`);

        // Blacklist the current access token until expiry
        const token = req.headers.authorization?.slice(7);
        if (token) {
            const decoded = jwt.decode(token);
            const ttl = decoded?.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 0;
            if (ttl > 0) {
                await req.redis.setex(`blacklist:${token}`, ttl, '1');
            }
        }

        // Audit
        await req.db.query(
            `INSERT INTO audit_log
                (tenant_id, user_id, action, resource_type, ip_address, user_agent, metadata)
             VALUES ($1, $2, 'LOGOUT', 'auth', $3, $4, $5)`,
            [
                req.user.tenantId, req.user.userId,
                req.ip, req.get('User-Agent') || 'unknown',
                JSON.stringify({ timestamp: new Date().toISOString() }),
            ]
        );

        res.json({
            message: 'Logged out successfully',
            correlationId: req.requestId,
        });
    } catch (err) {
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/auth/change-password
// ═══════════════════════════════════════════════════════════════
router.post('/change-password', authenticate, async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                error: 'VALIDATION_ERROR',
                code: 'MISSING_PASSWORDS',
                correlationId: req.requestId,
            });
        }

        const strength = validatePasswordStrength(newPassword);
        if (!strength.valid) {
            return res.status(400).json({
                error: 'WEAK_PASSWORD',
                code: 'PASSWORD_POLICY_VIOLATION',
                issues: strength.issues,
                correlationId: req.requestId,
            });
        }

        // Verify current password
        const result = await req.db.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.userId]
        );
        const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
        if (!valid) {
            await timingSafeDelay();
            return res.status(401).json({
                error: 'INVALID_CREDENTIALS',
                code: 'WRONG_PASSWORD',
                correlationId: req.requestId,
            });
        }

        // Ensure new password is different
        const sameAsOld = await bcrypt.compare(newPassword, result.rows[0].password_hash);
        if (sameAsOld) {
            return res.status(400).json({
                error: 'VALIDATION_ERROR',
                code: 'SAME_PASSWORD',
                correlationId: req.requestId,
            });
        }

        // Hash and update
        const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await req.db.query(
            'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
            [newHash, req.user.userId]
        );

        // Revoke all tokens (force re-login)
        await req.redis.del(`refresh:${req.user.userId}`);

        // Audit
        await req.db.query(
            `INSERT INTO audit_log
                (tenant_id, user_id, action, resource_type, ip_address, user_agent, metadata)
             VALUES ($1, $2, 'PASSWORD_CHANGE', 'auth', $3, $4, $5)`,
            [
                req.user.tenantId, req.user.userId,
                req.ip, req.get('User-Agent') || 'unknown',
                JSON.stringify({ timestamp: new Date().toISOString() }),
            ]
        );

        logger.info('Password changed', {
            userId: req.user.userId,
            requestId: req.requestId,
        });

        res.json({
            message: 'Password changed successfully. Please log in again.',
            correlationId: req.requestId,
        });
    } catch (err) {
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/auth/register
// ═══════════════════════════════════════════════════════════════
// Admin-only. Requires explicit ToS + Privacy Policy consent.
router.post('/register', authenticate, async (req, res, next) => {
    try {
        // Admin-only
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                error: 'INSUFFICIENT_PERMISSIONS',
                code: 'ADMIN_REQUIRED',
                correlationId: req.requestId,
            });
        }

        const {
            email,
            password,
            fullName,
            role,
            departmentId,
            tosAccepted,
            privacyAccepted,
        } = req.body;

        // ─── Legal consent validation (GDPR / NDPA) ─────────
        if (tosAccepted !== true || privacyAccepted !== true) {
            return res.status(422).json({
                error: 'CONSENT_REQUIRED',
                code: 'MISSING_LEGAL_CONSENT',
                message: 'You must accept the Terms of Service '
                    + 'and Privacy Policy to create an account.',
                correlationId: req.requestId,
            });
        }

        if (!email || !password || !fullName || !departmentId) {
            return res.status(400).json({
                error: 'VALIDATION_ERROR',
                code: 'MISSING_FIELDS',
                message: 'email, password, fullName, and departmentId are required',
                correlationId: req.requestId,
            });
        }

        // Validate password strength
        const strength = validatePasswordStrength(password);
        if (!strength.valid) {
            return res.status(400).json({
                error: 'WEAK_PASSWORD',
                code: 'PASSWORD_POLICY_VIOLATION',
                issues: strength.issues,
                correlationId: req.requestId,
            });
        }

        const validRoles = ['viewer', 'analyst', 'manager', 'admin'];
        const userRole = validRoles.includes(role) ? role : 'viewer';

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const TOS_VERSION = process.env.CURRENT_TOS_VERSION || '2026-03';
        const PRIVACY_VERSION = process.env.CURRENT_PRIVACY_VERSION || '2026-03';

        // New user inherits the admin's tenant
        const tenantId = req.user.tenantId;

        const result = await req.db.query(
            `INSERT INTO users
                (email, password_hash, full_name, role, department_id, tenant_id,
                 tos_accepted_at, tos_version,
                 privacy_policy_accepted_at, privacy_policy_version)
             VALUES ($1, $2, $3, $4, $5, $6,
                     NOW(), $7,
                     NOW(), $8)
             RETURNING id, uuid, email, full_name, role`,
            [
                email.toLowerCase().trim(),
                passwordHash,
                fullName,
                userRole,
                departmentId,
                tenantId,
                TOS_VERSION,
                PRIVACY_VERSION,
            ]
        );

        const newUser = result.rows[0];

        // Insert user_departments junction row
        await req.db.query(
            'INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)',
            [newUser.id, departmentId]
        );

        // ─── Audit: consent recorded ────────────────────────
        await req.db.query(
            `INSERT INTO audit_log
                (tenant_id, user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
             VALUES ($1, $2, 'USER_CONSENT_RECORDED', 'users', $3, $4, $5, $6)`,
            [
                tenantId,
                newUser.id,
                newUser.uuid,
                req.ip,
                req.get('User-Agent') || 'unknown',
                JSON.stringify({
                    timestamp: new Date().toISOString(),
                    tosVersion: TOS_VERSION,
                    privacyVersion: PRIVACY_VERSION,
                    registeredBy: req.user.userId,
                }),
            ]
        );

        logger.info('User registered with consent', {
            newUserId: newUser.id,
            emailHash: hashEmail(newUser.email),
            role: newUser.role,
            registeredBy: req.user.userId,
            requestId: req.requestId,
        });

        res.status(201).json({
            message: 'User created successfully',
            user: {
                uuid: newUser.uuid,
                email: newUser.email,
                fullName: newUser.full_name,
                role: newUser.role,
            },
            correlationId: req.requestId,
        });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({
                error: 'DUPLICATE_EMAIL',
                code: 'EMAIL_EXISTS',
                correlationId: req.requestId,
            });
        }
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// GET /api/v1/auth/password-policy
// ═══════════════════════════════════════════════════════════════
router.get('/password-policy', (req, res) => {
    res.json({
        policy: {
            minLength: 12,
            maxLength: 128,
            requireUppercase: true,
            requireLowercase: true,
            requireDigit: true,
            requireSpecialChar: true,
            maxRepeatedChars: 3,
            blockedPatterns: ['password', '123456', 'qwerty', 'admin'],
        },
    });
});

module.exports = router;
