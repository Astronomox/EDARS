'use strict';

/**
 * tests/unit/gateway/auth.test.js
 *
 * Unit tests for gateway/src/middleware/auth.js
 * Covers: valid JWT, expired JWT, missing token, tampered payload,
 *         missing tenantId, legacy secret fallback, malformed token
 */

const jwt = require('jsonwebtoken');

// ── Mock environment before requiring the module ──────────────
process.env.JWT_SECRET = 'test-primary-secret';
process.env.JWT_SECRET_LEGACY = '';

// We mock the logger so tests don't produce noise
jest.mock('../../../gateway/src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

const { authenticate } = require('../../../gateway/src/middleware/auth');

// ── Helpers ───────────────────────────────────────────────────

/**
 * Build a minimal valid JWT payload for testing.
 * @param {object} overrides - Fields to override in payload
 * @param {object} signOpts  - Options passed to jwt.sign
 */
function makeToken(overrides = {}, signOpts = {}) {
  const payload = {
    userId: 'user-uuid-1234',
    email: 'test@edars.internal',
    role: 'analyst',
    tenantId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    plan: 'growth',
    slug: 'edars-dev',
    ...overrides,
  };
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '8h',
    ...signOpts,
  });
}

/**
 * Build mock Express req/res/next objects.
 * @param {string|null} token - Bearer token or null for no header
 */
function buildMocks(token) {
  const req = {
    headers: token ? { authorization: `Bearer ${token}` } : {},
    correlationId: 'test-corr-id',
    ip: '127.0.0.1',
  };
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  const next = jest.fn();
  return { req, res, next };
}

// ── Tests ─────────────────────────────────────────────────────

describe('authenticate middleware', () => {
  afterEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET_LEGACY = '';
  });

  // ── Happy Path ──────────────────────────────────────────────

  test('calls next() and sets req.user when JWT is valid', () => {
    const token = makeToken();
    const { req, res, next } = buildMocks(token);

    authenticate(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith(); // no error argument
    expect(req.user).toBeDefined();
    expect(req.user.userId).toBe('user-uuid-1234');
    expect(req.user.tenantId).toBe('f47ac10b-58cc-4372-a567-0e02b2c3d479');
    expect(req.user.role).toBe('analyst');
    expect(req.user.plan).toBe('growth');
  });

  test('sets all required user fields on req.user', () => {
    const token = makeToken();
    const { req, res, next } = buildMocks(token);

    authenticate(req, res, next);

    const required = ['userId', 'email', 'role', 'tenantId', 'plan', 'slug'];
    required.forEach((field) => {
      expect(req.user[field]).toBeDefined();
    });
  });

  // ── Missing / Malformed Token ────────────────────────────────

  test('returns 401 when Authorization header is absent', () => {
    const { req, res, next } = buildMocks(null);

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.any(String) })
    );
  });

  test('returns 401 when token is malformed (not a JWT)', () => {
    const { req, res, next } = buildMocks('this.is.not.valid');

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('returns 401 when token is signed with wrong secret', () => {
    const badToken = jwt.sign(
      { userId: 'x', tenantId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479', role: 'viewer', plan: 'free', slug: 'x', email: 'x@x.com' },
      'completely-wrong-secret',
      { expiresIn: '8h' }
    );
    const { req, res, next } = buildMocks(badToken);

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  // ── Expired Token ────────────────────────────────────────────

  test('returns 401 when JWT is expired', () => {
    const expiredToken = makeToken({}, { expiresIn: 0 });
    const { req, res, next } = buildMocks(expiredToken);

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  // ── Security: Missing tenantId ───────────────────────────────

  test('returns 401 when tenantId is missing from payload', () => {
    const token = makeToken({ tenantId: undefined });
    const { req, res, next } = buildMocks(token);

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'MISSING_TENANT' })
    );
  });

  test('returns 401 when tenantId is not a valid UUID', () => {
    const token = makeToken({ tenantId: 'not-a-uuid' });
    const { req, res, next } = buildMocks(token);

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  // ── Secret Rotation: Legacy fallback ─────────────────────────

  test('accepts token signed with legacy secret during rotation window', () => {
    // Simulate key rotation: old secret becomes legacy
    const oldSecret = 'old-secret-before-rotation';
    process.env.JWT_SECRET = 'new-primary-secret';
    process.env.JWT_SECRET_LEGACY = oldSecret;

    // Token was issued before rotation — signed with old secret
    const oldToken = jwt.sign(
      {
        userId: 'user-123',
        email: 'u@edars.internal',
        role: 'viewer',
        tenantId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        plan: 'free',
        slug: 'edars-dev',
      },
      oldSecret,
      { expiresIn: '8h' }
    );

    const { req, res, next } = buildMocks(oldToken);
    authenticate(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.user).toBeDefined();
    expect(req.user.userId).toBe('user-123');

    // Restore
    process.env.JWT_SECRET = 'test-primary-secret';
    process.env.JWT_SECRET_LEGACY = '';
  });

  test('rejects token when neither primary nor legacy secret match', () => {
    process.env.JWT_SECRET_LEGACY = 'also-wrong-secret';

    const alienToken = jwt.sign(
      { userId: 'x', tenantId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479', role: 'viewer', plan: 'free', slug: 'x', email: 'x' },
      'completely-alien-secret',
      { expiresIn: '8h' }
    );
    const { req, res, next } = buildMocks(alienToken);

    authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  // ── Response shape ───────────────────────────────────────────

  test('error responses never leak internal stack traces', () => {
    const { req, res, next } = buildMocks(null);

    authenticate(req, res, next);

    const body = res.json.mock.calls[0][0];
    expect(body).not.toHaveProperty('stack');
    expect(body).not.toHaveProperty('trace');
    expect(typeof body.error).toBe('string');
  });
});
