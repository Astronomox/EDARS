// ═══════════════════════════════════════════════════════════════
// tenancy.js — Plan-Based Feature Gating Middleware
// ═══════════════════════════════════════════════════════════════
// Runs AFTER authenticate on every protected route.
// Checks whether the user's tenant plan grants access to the
// requested route. Returns 403 with upgrade info if not.
// ═══════════════════════════════════════════════════════════════
'use strict';

const logger = require('../utils/logger');

/**
 * Map of route patterns to the minimum plan required.
 * Format: 'METHOD /path' — use the path WITHOUT /api prefix.
 * If a route is NOT listed here, it is allowed on ALL plans.
 *
 * @type {Record<string, string>}
 */
const FEATURE_GATES = {
    'GET /analytics/trends': 'growth',
    'GET /analytics/anomalies': 'growth',
    'GET /analytics/kpis': 'enterprise',
    'POST /reports': 'growth',
    'POST /reports/generate': 'growth',
    'GET /exports': 'growth',
    'GET /exports/transactions': 'growth',
    'GET /exports/reports': 'growth',
    'GET /exports/audit': 'growth',
    'GET /users': 'growth',
    'POST /users': 'growth',
    'DELETE /users/:id': 'growth',
    'PATCH /users/:id/deactivate': 'growth',
    'GET /audit': 'growth',
    'GET /admin/tenants': 'enterprise',
    'POST /admin/tenants/:id/suspend': 'enterprise',
    'POST /admin/tenants/:id/request-deletion': 'enterprise',
    'POST /admin/tenants/:id/execute-deletion': 'enterprise',
    'GET /forecasting/revenue-forecast/:id': 'enterprise',
    'GET /forecasting/spending-anomalies': 'enterprise',
    'GET /forecasting/trend-analysis': 'enterprise',
    'POST /pipeline/run/:id': 'enterprise',
    'GET /pipeline/status': 'enterprise',
    'GET /pipeline/history': 'enterprise',
};

/**
 * Plan hierarchy. Higher number = more features.
 * @type {Record<string, number>}
 */
const PLAN_HIERARCHY = { free: 0, growth: 1, enterprise: 2 };

/**
 * Normalises a dynamic path like /users/abc-123 to /users/:id
 * for gate lookups. Replaces UUIDs and numeric IDs with :id.
 *
 * @param {string} method - HTTP method
 * @param {string} path - request path
 * @returns {string} normalised route key
 */
function normaliseRouteKey(method, path) {
    return method + ' ' + path
        // Replace UUIDs with :id
        .replace(
            /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
            ':id'
        )
        // Replace numeric path segments with :id
        .replace(/\/\d+/g, '/:id');
}

/**
 * Express middleware. Must be used AFTER authenticate.
 * Reads req.user.plan and checks whether the current route
 * is gated to a higher plan.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function tenancy(req, res, next) {
    const routeKey = normaliseRouteKey(req.method, req.path);
    const requiredPlan = FEATURE_GATES[routeKey];

    // Route is not gated — allow all plans
    if (!requiredPlan) return next();

    const userPlanLevel = PLAN_HIERARCHY[req.user.plan] ?? -1;
    const requiredLevel = PLAN_HIERARCHY[requiredPlan] ?? 99;

    if (userPlanLevel >= requiredLevel) return next();

    logger.info('Plan gate denied access', {
        tenantId: req.user.tenantId,
        currentPlan: req.user.plan,
        requiredPlan,
        route: routeKey,
        requestId: req.requestId,
    });

    return res.status(403).json({
        error: 'PLAN_UPGRADE_REQUIRED',
        code: 'FEATURE_GATED',
        requiredPlan,
        currentPlan: req.user.plan,
        upgradeUrl: process.env.PRICING_URL || 'https://edars.io/pricing',
        correlationId: req.requestId,
    });
}

module.exports = tenancy;
