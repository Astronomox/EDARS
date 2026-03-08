'use strict';

/**
 * tests/unit/gateway/tenancy.test.js
 *
 * Unit tests for gateway/src/middleware/tenancy.js
 * Covers: feature gating, plan hierarchy, dynamic route normalisation,
 *         ungated routes pass-through, correct error shape
 */

const tenancy = require('../../../gateway/src/middleware/tenancy');

// ── Helpers ───────────────────────────────────────────────────

/**
 * Build a mock request with a specific plan and route.
 * @param {string} plan    - 'free' | 'growth' | 'enterprise'
 * @param {string} method  - HTTP verb
 * @param {string} path    - Route path
 */
function buildReq(plan, method, path) {
  return {
    user: { plan, tenantId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' },
    method,
    path,
    correlationId: 'test-corr',
  };
}

function buildRes() {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
}

// ── Tests ─────────────────────────────────────────────────────

describe('tenancy (plan-gating) middleware', () => {
  // ── Free plan: blocked routes ────────────────────────────────

  test('free plan cannot access GET /analytics/trends', () => {
    const req = buildReq('free', 'GET', '/analytics/trends');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'PLAN_UPGRADE_REQUIRED',
        requiredPlan: 'growth',
        currentPlan: 'free',
      })
    );
  });

  test('free plan cannot access GET /analytics/anomalies', () => {
    const req = buildReq('free', 'GET', '/analytics/anomalies');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('free plan cannot access POST /reports', () => {
    const req = buildReq('free', 'POST', '/reports');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('free plan cannot access GET /audit', () => {
    const req = buildReq('free', 'GET', '/audit');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  // ── Free plan: allowed routes ────────────────────────────────

  test('free plan CAN access GET /analytics/dashboard (ungated)', () => {
    const req = buildReq('free', 'GET', '/analytics/dashboard');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  test('free plan CAN access GET /users/me (ungated)', () => {
    const req = buildReq('free', 'GET', '/users/me');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  // ── Growth plan: allowed routes ──────────────────────────────

  test('growth plan CAN access GET /analytics/trends', () => {
    const req = buildReq('growth', 'GET', '/analytics/trends');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  test('growth plan CAN access GET /analytics/anomalies', () => {
    const req = buildReq('growth', 'GET', '/analytics/anomalies');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  // ── Growth plan: blocked (enterprise-only) ───────────────────

  test('growth plan cannot access GET /analytics/kpis (enterprise only)', () => {
    const req = buildReq('growth', 'GET', '/analytics/kpis');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        requiredPlan: 'enterprise',
        currentPlan: 'growth',
      })
    );
  });

  // ── Enterprise plan: all routes allowed ──────────────────────

  test('enterprise plan CAN access GET /analytics/kpis', () => {
    const req = buildReq('enterprise', 'GET', '/analytics/kpis');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  test('enterprise plan CAN access all growth routes too', () => {
    const routes = [
      ['GET', '/analytics/trends'],
      ['GET', '/analytics/anomalies'],
      ['POST', '/reports'],
      ['GET', '/exports'],
      ['GET', '/audit'],
    ];

    routes.forEach(([method, path]) => {
      const req = buildReq('enterprise', method, path);
      const res = buildRes();
      const next = jest.fn();

      tenancy(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  // ── Dynamic route normalisation ──────────────────────────────

  test('normalises /users/:uuid to /users/:id for gate lookup', () => {
    // DELETE /users/:id is a growth feature
    const req = buildReq(
      'free',
      'DELETE',
      '/users/f47ac10b-58cc-4372-a567-0e02b2c3d479'
    );
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  // ── Error response shape ─────────────────────────────────────

  test('403 response includes upgradeUrl', () => {
    const req = buildReq('free', 'GET', '/analytics/trends');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    const body = res.json.mock.calls[0][0];
    expect(body).toHaveProperty('upgradeUrl');
    expect(typeof body.upgradeUrl).toBe('string');
  });

  test('403 response never leaks stack traces', () => {
    const req = buildReq('free', 'GET', '/analytics/trends');
    const res = buildRes();
    const next = jest.fn();

    tenancy(req, res, next);

    const body = res.json.mock.calls[0][0];
    expect(body).not.toHaveProperty('stack');
  });
});
