'use strict';

/**
 * gateway/src/middleware/tenancy.js
 *
 * Plan-based feature gating middleware.
 * Must run AFTER authenticate middleware — requires req.user.plan.
 *
 * How it works:
 *   1. Looks up the route key in FEATURE_GATES
 *   2. Compares user's plan level to required plan level
 *   3. Calls next() if allowed, returns 403 if not
 *
 * Adding a new gated route:
 *   Add an entry to FEATURE_GATES below.
 *   Format: 'METHOD /path' — path WITHOUT any API prefix.
 *   Use :id as placeholder for dynamic UUID/numeric segments.
 *
 * Example:
 *   'GET /analytics/my-new-route': 'growth'
 */

// ── Plan hierarchy ────────────────────────────────────────────
// Higher number = more powerful plan.
// A user on plan N can access all routes requiring plan <= N.

const PLAN_HIERARCHY = Object.freeze({
  free: 0,
  growth: 1,
  enterprise: 2,
});

// ── Feature gates ─────────────────────────────────────────────
// Key:   'METHOD /normalised-path'
// Value: minimum plan required to access this route
//
// If a route is NOT listed here, it is accessible on ALL plans.

const FEATURE_GATES = Object.freeze({
  // Analytics (growth tier)
  'GET /analytics/trends': 'growth',
  'GET /analytics/anomalies': 'growth',
  'GET /analytics/sales': 'growth',

  // Analytics (enterprise tier)
  'GET /analytics/kpis': 'enterprise',
  'GET /analytics/department-kpis': 'enterprise',

  // Reports
  'POST /reports': 'growth',
  'POST /reports/generate': 'growth',

  // Exports
  'GET /exports': 'growth',
  'POST /exports': 'growth',

  // User management
  'GET /users': 'growth',
  'POST /users': 'growth',
  'DELETE /users/:id': 'growth',
  'PATCH /users/:id': 'growth',
  'PATCH /users/:id/deactivate': 'growth',

  // Audit log
  'GET /audit': 'growth',
});

// ── Route normaliser ──────────────────────────────────────────
/**
 * Converts a real request path with UUIDs or numeric IDs
 * into the normalised form used in FEATURE_GATES.
 *
 * Examples:
 *   /users/f47ac10b-58cc-4372-a567-0e02b2c3d479  → /users/:id
 *   /reports/42                                   → /reports/:id
 *   /analytics/dashboard                          → /analytics/dashboard
 *
 * @param {string} method - HTTP method ('GET', 'POST', etc.)
 * @param {string} path   - req.path value from Express
 * @returns {string}      - Normalised gate key
 */
function normaliseRouteKey(method, path) {
  const normalisedPath = path
    // Replace full UUIDs
    .replace(
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
      ':id'
    )
    // Replace numeric IDs (/42 → /:id)
    .replace(/\/\d+/g, '/:id')
    // Ensure no double slashes
    .replace(/\/+/g, '/');

  return `${method} ${normalisedPath}`;
}

// ── Middleware ────────────────────────────────────────────────
/**
 * Express middleware — must be used AFTER authenticate.
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function tenancy(req, res, next) {
  // If req.user is missing, authenticate middleware didn't run
  if (!req.user || !req.user.plan) {
    return res.status(401).json({
      error: 'AUTHENTICATION_REQUIRED',
      code: 'MISSING_USER_CONTEXT',
      correlationId: req.correlationId,
    });
  }

  const routeKey = normaliseRouteKey(req.method, req.path);
  const requiredPlan = FEATURE_GATES[routeKey];

  // Route is not gated — allow all plans
  if (!requiredPlan) {
    return next();
  }

  const userPlanLevel = PLAN_HIERARCHY[req.user.plan] ?? -1;
  const requiredPlanLevel = PLAN_HIERARCHY[requiredPlan] ?? 99;

  if (userPlanLevel >= requiredPlanLevel) {
    return next();
  }

  // Block — user's plan is below required
  return res.status(403).json({
    error: 'PLAN_UPGRADE_REQUIRED',
    code: 'FEATURE_GATED',
    requiredPlan,
    currentPlan: req.user.plan,
    upgradeUrl: process.env.PRICING_URL || 'https://edars.io/pricing',
    correlationId: req.correlationId,
  });
}

module.exports = tenancy;

// Export internals for unit testing
module.exports._normaliseRouteKey = normaliseRouteKey;
module.exports._FEATURE_GATES = FEATURE_GATES;
module.exports._PLAN_HIERARCHY = PLAN_HIERARCHY;
