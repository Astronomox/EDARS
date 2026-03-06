// ═══════════════════════════════════════════════════════════════
// Gateway Middleware Unit Tests
// ═══════════════════════════════════════════════════════════════
const jwt = require('jsonwebtoken');

// ─── Mock dependencies ───────────────────────────────────────
const JWT_SECRET = 'test-secret-key-for-jest';
process.env.JWT_SECRET = JWT_SECRET;
process.env.ADMIN_IP_WHITELIST = '127.0.0.1,::1,10.0.0.0/8';

// ─── Helpers ─────────────────────────────────────────────────
function createMockReq(overrides = {}) {
    return {
        headers: {},
        ip: '127.0.0.1',
        path: '/test',
        method: 'GET',
        originalUrl: '/test',
        get: jest.fn((h) => overrides.headerValues?.[h] || ''),
        connection: { remoteAddress: '127.0.0.1' },
        requestId: 'test-req-id',
        redis: {
            get: jest.fn().mockResolvedValue(null),
            set: jest.fn().mockResolvedValue('OK'),
            setex: jest.fn().mockResolvedValue('OK'),
            del: jest.fn().mockResolvedValue(1),
            incr: jest.fn().mockResolvedValue(1),
        },
        db: {
            query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
        },
        user: null,
        ...overrides,
    };
}

function createMockRes() {
    const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
        setHeader: jest.fn(),
        set: jest.fn(),
        send: jest.fn(),
        on: jest.fn(),
        statusCode: 200,
    };
    return res;
}

function generateTestToken(payload = {}, options = {}) {
    const defaults = {
        id: 1, uuid: 'test-uuid', email: 'test@edars.internal',
        role: 'admin', departmentId: 1, fullName: 'Test User',
        tenantId: 1, tenantSlug: 'test-org', plan: 'enterprise',
        type: 'access',
    };
    return jwt.sign({ ...defaults, ...payload }, JWT_SECRET, {
        algorithm: 'HS256', expiresIn: '8h', ...options,
    });
}

// ═══════════════════════════════════════════════════════════════
// 1. AUTH MIDDLEWARE TESTS
// ═══════════════════════════════════════════════════════════════
describe('Auth Middleware', () => {
    const { authenticate, authorize } = require('../src/middleware/auth');

    describe('authenticate', () => {
        test('rejects request without Authorization header', async () => {
            const req = createMockReq();
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Authentication required' }));
            expect(next).not.toHaveBeenCalled();
        });

        test('rejects request with malformed Authorization header', async () => {
            const req = createMockReq({ headers: { authorization: 'Basic abc123' } });
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });

        test('rejects expired JWT', async () => {
            const token = jwt.sign(
                { id: 1, type: 'access' }, JWT_SECRET,
                { algorithm: 'HS256', expiresIn: '-1s' }
            );
            const req = createMockReq({ headers: { authorization: `Bearer ${token}` } });
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: expect.stringContaining('expired') }));
        });

        test('rejects blacklisted token', async () => {
            const token = generateTestToken();
            const redis = { get: jest.fn().mockResolvedValue('1') };
            const req = createMockReq({
                headers: { authorization: `Bearer ${token}` },
                redis,
            });
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Token has been revoked' }));
        });

        test('rejects refresh token used as access token', async () => {
            const token = generateTestToken({ type: 'refresh' });
            const req = createMockReq({ headers: { authorization: `Bearer ${token}` } });
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: expect.stringContaining('refresh') }));
        });

        test('accepts valid token and attaches user with tenant fields', async () => {
            const token = generateTestToken({
                tenantId: 42, tenantSlug: 'acme', plan: 'growth',
            });
            const req = createMockReq({ headers: { authorization: `Bearer ${token}` } });
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(next).toHaveBeenCalled();
            expect(req.user).toBeDefined();
            expect(req.user.id).toBe(1);
            expect(req.user.tenantId).toBe(42);
            expect(req.user.tenantSlug).toBe('acme');
            expect(req.user.plan).toBe('growth');
        });

        test('rejects token with wrong algorithm', async () => {
            // Create token with none algorithm (should be rejected)
            const token = jwt.sign({ id: 1, type: 'access' }, '', { algorithm: 'none' });
            const req = createMockReq({ headers: { authorization: `Bearer ${token}` } });
            const res = createMockRes();
            const next = jest.fn();

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });
    });

    describe('authorize', () => {
        test('allows user with correct role', () => {
            const middleware = authorize('admin', 'manager');
            const req = createMockReq({ user: { id: 1, role: 'admin' } });
            const res = createMockRes();
            const next = jest.fn();

            middleware(req, res, next);

            expect(next).toHaveBeenCalled();
        });

        test('rejects user without required role', () => {
            const middleware = authorize('admin');
            const req = createMockReq({ user: { id: 1, role: 'viewer' } });
            const res = createMockRes();
            const next = jest.fn();

            middleware(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(next).not.toHaveBeenCalled();
        });

        test('rejects unauthenticated request', () => {
            const middleware = authorize('admin');
            const req = createMockReq({ user: null });
            const res = createMockRes();
            const next = jest.fn();

            middleware(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
        });
    });
});

// ═══════════════════════════════════════════════════════════════
// 2. SANITISE MIDDLEWARE TESTS
// ═══════════════════════════════════════════════════════════════
describe('Sanitise Middleware', () => {
    const { sanitise } = require('../src/middleware/sanitise');

    test('strips HTML tags from string fields in body', () => {
        const req = createMockReq({
            body: { name: '<script>alert("xss")</script>Hello' },
            query: {},
            params: {},
        });
        const res = createMockRes();
        const next = jest.fn();

        sanitise(req, res, next);

        expect(req.body.name).not.toContain('<script>');
        expect(next).toHaveBeenCalled();
    });

    test('strips HTML tags from query parameters', () => {
        const req = createMockReq({
            body: {},
            query: { search: '<img src=x onerror=alert(1)>' },
            params: {},
        });
        const res = createMockRes();
        const next = jest.fn();

        sanitise(req, res, next);

        expect(req.query.search).not.toContain('<img');
        expect(next).toHaveBeenCalled();
    });

    test('preserves non-string values', () => {
        const req = createMockReq({
            body: { count: 42, active: true },
            query: {},
            params: {},
        });
        const res = createMockRes();
        const next = jest.fn();

        sanitise(req, res, next);

        expect(req.body.count).toBe(42);
        expect(req.body.active).toBe(true);
        expect(next).toHaveBeenCalled();
    });
});

// ═══════════════════════════════════════════════════════════════
// 3. RATE LIMITER TESTS
// ═══════════════════════════════════════════════════════════════
describe('Rate Limiter Middleware', () => {
    const { createRateLimiter } = require('../src/middleware/rateLimiter');

    test('allows request under limit', async () => {
        const redis = {
            multi: jest.fn().mockReturnValue({
                incr: jest.fn().mockReturnThis(),
                pexpire: jest.fn().mockReturnThis(),
                exec: jest.fn().mockResolvedValue([[null, 1], [null, 1]]),
            }),
        };
        const middleware = createRateLimiter(redis);
        const req = createMockReq({ ip: '192.168.1.1' });
        const res = createMockRes();
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalled();
    });
});

// ═══════════════════════════════════════════════════════════════
// 4. IP WHITELIST TESTS
// ═══════════════════════════════════════════════════════════════
describe('IP Whitelist Middleware', () => {
    const { ipWhitelist } = require('../src/middleware/ipWhitelist');

    test('allows whitelisted IP', () => {
        const req = createMockReq({ ip: '127.0.0.1' });
        const res = createMockRes();
        const next = jest.fn();

        ipWhitelist(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('allows IP in whitelisted CIDR range', () => {
        const req = createMockReq({ ip: '10.5.3.1' });
        const res = createMockRes();
        const next = jest.fn();

        ipWhitelist(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('rejects non-whitelisted IP', () => {
        const req = createMockReq({ ip: '203.0.113.50' });
        const res = createMockRes();
        const next = jest.fn();

        ipWhitelist(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(next).not.toHaveBeenCalled();
    });
});

// ═══════════════════════════════════════════════════════════════
// 5. TRACER MIDDLEWARE TESTS
// ═══════════════════════════════════════════════════════════════
describe('Request Tracer Middleware', () => {
    const { requestTracer } = require('../src/middleware/tracer');

    test('generates a request ID if none provided', () => {
        const req = createMockReq({ headers: {} });
        const res = createMockRes();
        const next = jest.fn();

        requestTracer(req, res, next);

        expect(req.requestId).toBeDefined();
        expect(typeof req.requestId).toBe('string');
        expect(req.requestId.length).toBeGreaterThan(0);
        expect(res.setHeader).toHaveBeenCalledWith('X-Request-ID', req.requestId);
        expect(next).toHaveBeenCalled();
    });

    test('preserves existing X-Request-ID', () => {
        const existingId = 'my-trace-id-123';
        const req = createMockReq({ headers: { 'x-request-id': existingId } });
        const res = createMockRes();
        const next = jest.fn();

        requestTracer(req, res, next);

        expect(req.requestId).toBe(existingId);
        expect(next).toHaveBeenCalled();
    });
});

// ═══════════════════════════════════════════════════════════════
// 6. PLAN GATE MIDDLEWARE TESTS
// ═══════════════════════════════════════════════════════════════
describe('Plan Gate Middleware', () => {
    const { planGate, hasAccess } = require('../src/middleware/planGate');

    test('allows free plan on free-tier routes', () => {
        const req = createMockReq({
            user: { plan: 'free', tenantId: 1 },
            path: '/api/v1/analytics/dashboard',
        });
        const res = createMockRes();
        const next = jest.fn();

        planGate(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('blocks free plan from growth-tier routes', () => {
        const req = createMockReq({
            user: { plan: 'free', tenantId: 1 },
            path: '/api/v1/exports/transactions',
        });
        const res = createMockRes();
        const next = jest.fn();

        planGate(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            error: 'PLAN_UPGRADE_REQUIRED',
            requiredPlan: 'growth',
        }));
    });

    test('blocks growth plan from enterprise-tier routes', () => {
        const req = createMockReq({
            user: { plan: 'growth', tenantId: 1 },
            path: '/api/v1/admin/refresh-views',
        });
        const res = createMockRes();
        const next = jest.fn();

        planGate(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            error: 'PLAN_UPGRADE_REQUIRED',
            requiredPlan: 'enterprise',
        }));
    });

    test('allows enterprise plan on all routes', () => {
        const req = createMockReq({
            user: { plan: 'enterprise', tenantId: 1 },
            path: '/api/v1/admin/refresh-views',
        });
        const res = createMockRes();
        const next = jest.fn();

        planGate(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('hasAccess returns correct boolean', () => {
        expect(hasAccess('free', 'free')).toBe(true);
        expect(hasAccess('free', 'growth')).toBe(false);
        expect(hasAccess('growth', 'growth')).toBe(true);
        expect(hasAccess('growth', 'enterprise')).toBe(false);
        expect(hasAccess('enterprise', 'enterprise')).toBe(true);
        expect(hasAccess('enterprise', 'free')).toBe(true);
    });
});

// ═══════════════════════════════════════════════════════════════
// 7. AUDIT MIDDLEWARE TESTS
// ═══════════════════════════════════════════════════════════════
describe('Audit Middleware', () => {
    const { auditLog } = require('../src/middleware/audit');

    test('logs audit entry and calls next', async () => {
        const db = {
            query: jest.fn().mockResolvedValue({ rows: [], rowCount: 1 }),
        };
        const req = createMockReq({
            user: { id: 1, tenantId: 1 },
            method: 'GET',
            originalUrl: '/api/v1/reports',
            db,
        });
        const res = createMockRes();
        const next = jest.fn();

        await auditLog(req, res, next);

        expect(next).toHaveBeenCalled();
    });
});

// ═══════════════════════════════════════════════════════════════
// 8. USAGE METER MIDDLEWARE TESTS
// ═══════════════════════════════════════════════════════════════
describe('Usage Meter Middleware', () => {
    const { createUsageMeter, resolveEventType } = require('../src/middleware/usageMeter');

    test('resolves correct event type for report creation', () => {
        expect(resolveEventType('POST', '/api/v1/reports')).toBe('report_generated');
    });

    test('resolves api_call for generic GET', () => {
        expect(resolveEventType('GET', '/api/v1/analytics/dashboard')).toBe('api_call');
    });

    test('resolves login event', () => {
        expect(resolveEventType('POST', '/api/v1/auth/login')).toBe('login');
    });

    test('skips metering for unauthenticated requests', () => {
        const pool = { query: jest.fn() };
        const middleware = createUsageMeter(pool);
        const req = createMockReq({ user: null });
        const res = createMockRes();
        const next = jest.fn();

        middleware(req, res, next);

        expect(next).toHaveBeenCalled();
        // No finish handler should write, since user is null
    });
});

// ═══════════════════════════════════════════════════════════════
// 9. CIRCUIT BREAKER TESTS
// ═══════════════════════════════════════════════════════════════
describe('Circuit Breaker', () => {
    const { circuitBreaker, getBreakerStates } = require('../src/middleware/circuitBreaker');

    test('returns a middleware function', () => {
        const middleware = circuitBreaker('analytics');
        expect(typeof middleware).toBe('function');
    });

    test('getBreakerStates returns an object', () => {
        const states = getBreakerStates();
        expect(typeof states).toBe('object');
    });

    test('allows request when circuit is closed', async () => {
        const middleware = circuitBreaker('test-service');
        const req = createMockReq();
        const res = createMockRes();
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalled();
    });
});
