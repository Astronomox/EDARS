// ═══════════════════════════════════════════════════════════════
// Auth Routes — Login, Register, Token Refresh, Account Lockout
//               Password Strength Validation  (BUFFED)
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '8h';
const REFRESH_EXPIRY = '7d';
const BCRYPT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

// ─── Password Strength Validator ─────────────────────────────
function validatePasswordStrength(password) {
    const issues = [];
    if (password.length < 12) issues.push('Minimum 12 characters required');
    if (password.length > 128) issues.push('Maximum 128 characters');
    if (!/[A-Z]/.test(password)) issues.push('At least one uppercase letter required');
    if (!/[a-z]/.test(password)) issues.push('At least one lowercase letter required');
    if (!/[0-9]/.test(password)) issues.push('At least one digit required');
    if (!/[^A-Za-z0-9]/.test(password)) issues.push('At least one special character required');
    if (/(.)\1{3,}/.test(password)) issues.push('No more than 3 repeated characters in a row');
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
        logger.warn('Account locked due to failed attempts', { email, attempts });
    }

    await redis.setex(key, 1800, JSON.stringify(lockoutData)); // TTL 30min
    return attempts;
}

async function clearLockout(redis, email) {
    await redis.del(`lockout:${email}`);
}

// ─── POST /api/v1/auth/login ─────────────────────────────────
router.post('/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const normEmail = email.toLowerCase().trim();

        // Check account lockout
        const lockout = await checkLockout(req.redis, normEmail);
        if (lockout.locked) {
            logger.warn('Login attempt on locked account', { email: normEmail, ip: req.ip });
            return res.status(429).json({
                error: 'Account temporarily locked due to too many failed attempts',
                retryAfter: lockout.retryAfter,
            });
        }

        // Fetch user with tenant context
        const result = await req.db.query(
            `SELECT u.id, u.uuid, u.email, u.password_hash, u.full_name, u.role,
              u.department_id, u.is_active, u.tenant_id,
              d.name AS department_name,
              t.slug AS tenant_slug, t.plan AS tenant_plan, t.is_active AS tenant_active
       FROM users u
       JOIN departments d ON d.id = u.department_id
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.email = $1`,
            [normEmail]
        );

        if (result.rows.length === 0) {
            await bcrypt.hash('dummy', BCRYPT_ROUNDS); // Constant-time
            await recordFailedAttempt(req.redis, normEmail);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        if (!user.tenant_active) {
            return res.status(403).json({ error: 'Tenant account is suspended. Contact support.' });
        }

        if (!user.is_active) {
            return res.status(403).json({ error: 'Account is deactivated. Contact your administrator.' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            const attempts = await recordFailedAttempt(req.redis, normEmail);
            const remaining = MAX_LOGIN_ATTEMPTS - attempts;
            return res.status(401).json({
                error: 'Invalid credentials',
                ...(remaining <= 2 && remaining > 0 && { warning: `${remaining} attempt(s) remaining before lockout` }),
            });
        }

        // Clear lockout on successful login
        await clearLockout(req.redis, normEmail);

        // Generate access token (includes tenant context)
        const tokenPayload = {
            id: user.id,
            uuid: user.uuid,
            email: user.email,
            role: user.role,
            departmentId: user.department_id,
            fullName: user.full_name,
            tenantId: user.tenant_id,
            tenantSlug: user.tenant_slug,
            plan: user.tenant_plan,
            type: 'access',
        };
        const accessToken = jwt.sign(tokenPayload, JWT_SECRET, { algorithm: 'HS256', expiresIn: JWT_EXPIRY });

        // Generate refresh token (longer expiry, minimal claims)
        const refreshToken = jwt.sign(
            { id: user.id, uuid: user.uuid, type: 'refresh' },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: REFRESH_EXPIRY }
        );

        // Store refresh token hash in Redis
        const refreshKey = `refresh:${user.id}`;
        await req.redis.setex(refreshKey, 7 * 24 * 3600, refreshToken);

        // Update last login
        await req.db.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

        // Audit log (tenant-scoped)
        await req.db.query(
            `INSERT INTO audit_log (tenant_id, user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
       VALUES ($1, $2, 'LOGIN', 'auth', $3, $4, $5, $6)`,
            [user.tenant_id, user.id, user.uuid, req.ip, req.get('User-Agent') || 'unknown',
            JSON.stringify({ timestamp: new Date().toISOString(), method: 'password' })]
        );

        logger.info('Successful login', { userId: user.id, email: user.email, ip: req.ip });

        res.json({
            accessToken,
            refreshToken,
            expiresIn: JWT_EXPIRY,
            user: {
                uuid: user.uuid,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                department: user.department_name,
            },
        });
    } catch (err) {
        next(err);
    }
});

// ─── POST /api/v1/auth/refresh ───────────────────────────────
router.post('/refresh', async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token is required' });
        }

        // Verify refresh token
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, JWT_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            return res.status(401).json({ error: 'Invalid or expired refresh token' });
        }

        if (decoded.type !== 'refresh') {
            return res.status(401).json({ error: 'Invalid token type' });
        }

        // Verify token is still in Redis (not revoked)
        const storedToken = await req.redis.get(`refresh:${decoded.id}`);
        if (!storedToken || storedToken !== refreshToken) {
            logger.warn('Refresh token not found or revoked', { userId: decoded.id });
            return res.status(401).json({ error: 'Refresh token revoked or expired' });
        }

        // Fetch fresh user data with tenant context
        const result = await req.db.query(
            `SELECT u.id, u.uuid, u.email, u.full_name, u.role,
              u.department_id, u.is_active, u.tenant_id,
              t.slug AS tenant_slug, t.plan AS tenant_plan
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.id = $1`,
            [decoded.id]
        );

        if (result.rows.length === 0 || !result.rows[0].is_active) {
            await req.redis.del(`refresh:${decoded.id}`);
            return res.status(401).json({ error: 'User not found or deactivated' });
        }

        const user = result.rows[0];

        // Issue new access token with tenant context
        const newAccessToken = jwt.sign(
            {
                id: user.id, uuid: user.uuid, email: user.email,
                role: user.role, departmentId: user.department_id,
                fullName: user.full_name,
                tenantId: user.tenant_id, tenantSlug: user.tenant_slug,
                plan: user.tenant_plan,
                type: 'access',
            },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: JWT_EXPIRY }
        );

        // Rotate refresh token
        const newRefreshToken = jwt.sign(
            { id: user.id, uuid: user.uuid, type: 'refresh' },
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

// ─── POST /api/v1/auth/logout ────────────────────────────────
router.post('/logout', authenticate, async (req, res) => {
    try {
        // Revoke refresh token
        await req.redis.del(`refresh:${req.user.id}`);

        // Blacklist the current access token until expiry
        const token = req.headers.authorization?.slice(7);
        if (token) {
            const decoded = jwt.decode(token);
            const ttl = decoded.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 0;
            if (ttl > 0) {
                await req.redis.setex(`blacklist:${token}`, ttl, '1');
            }
        }

        // Audit (tenant-scoped)
        await req.db.query(
            `INSERT INTO audit_log (tenant_id, user_id, action, resource_type, ip_address, user_agent, metadata)
       VALUES ($1, $2, 'LOGOUT', 'auth', $3, $4, $5)`,
            [req.user.tenantId || 1, req.user.id, req.ip, req.get('User-Agent') || 'unknown',
            JSON.stringify({ timestamp: new Date().toISOString() })]
        );

        res.json({ message: 'Logged out successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

// ─── POST /api/v1/auth/change-password ───────────────────────
router.post('/change-password', authenticate, async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Both current and new password are required' });
        }

        // Validate new password strength
        const strength = validatePasswordStrength(newPassword);
        if (!strength.valid) {
            return res.status(400).json({
                error: 'Password does not meet strength requirements',
                issues: strength.issues,
                strength: strength.strength,
            });
        }

        // Verify current password
        const result = await req.db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
        const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Ensure new password is different
        const sameAsOld = await bcrypt.compare(newPassword, result.rows[0].password_hash);
        if (sameAsOld) {
            return res.status(400).json({ error: 'New password must be different from current password' });
        }

        // Hash and update
        const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await req.db.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, req.user.id]);

        // Revoke all tokens (force re-login)
        await req.redis.del(`refresh:${req.user.id}`);

        // Audit (tenant-scoped)
        await req.db.query(
            `INSERT INTO audit_log (tenant_id, user_id, action, resource_type, ip_address, user_agent, metadata)
       VALUES ($1, $2, 'PASSWORD_CHANGE', 'auth', $3, $4, $5)`,
            [req.user.tenantId || 1, req.user.id, req.ip, req.get('User-Agent') || 'unknown',
            JSON.stringify({ timestamp: new Date().toISOString() })]
        );

        logger.info('Password changed', { userId: req.user.id });
        res.json({ message: 'Password changed successfully. Please log in again.' });
    } catch (err) {
        next(err);
    }
});

// ─── POST /api/v1/auth/register ──────────────────────────────
router.post('/register', authenticate, async (req, res, next) => {
    try {
        // Admin-only
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only admins can register new users' });
        }

        const { email, password, fullName, role, departmentId } = req.body;

        if (!email || !password || !fullName || !departmentId) {
            return res.status(400).json({ error: 'email, password, fullName, and departmentId are required' });
        }

        // Validate password strength
        const strength = validatePasswordStrength(password);
        if (!strength.valid) {
            return res.status(400).json({
                error: 'Password does not meet strength requirements',
                issues: strength.issues,
            });
        }

        const validRoles = ['viewer', 'analyst', 'manager', 'admin'];
        const userRole = validRoles.includes(role) ? role : 'viewer';

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const tenantId = req.user.tenantId || 1;
        const result = await req.db.query(
            `INSERT INTO users (email, password_hash, full_name, role, department_id, tenant_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING uuid, email, full_name, role`,
            [email.toLowerCase().trim(), passwordHash, fullName, userRole, departmentId, tenantId]
        );

        const newUser = result.rows[0];
        const userIdResult = await req.db.query('SELECT id FROM users WHERE uuid = $1', [newUser.uuid]);
        await req.db.query(
            'INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)',
            [userIdResult.rows[0].id, departmentId]
        );

        logger.info('User registered', { email: newUser.email, role: newUser.role, by: req.user.email });

        res.status(201).json({ message: 'User created successfully', user: newUser });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
        next(err);
    }
});

// ─── GET /api/v1/auth/password-policy ────────────────────────
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
