// ═══════════════════════════════════════════════════════════════
// Plan-Based Feature Gate Middleware
// ═══════════════════════════════════════════════════════════════
// Reads the tenant plan from the JWT and checks whether the
// current route is available on that plan.  Returns HTTP 403
// with { error: "PLAN_UPGRADE_REQUIRED", requiredPlan } if the
// feature is not available.
// ═══════════════════════════════════════════════════════════════
const logger = require('../utils/logger');

/**
 * Feature access map: maps route prefixes to the minimum plan
 * required. Routes not listed default to 'free' (all plans).
 *
 * Plan hierarchy: free < growth < enterprise
 */
const FEATURE_MAP = {
    '/api/v1/analytics/dashboard': 'free',
    '/api/v1/analytics/sales-summary': 'free',
    '/api/v1/analytics/user-activity': 'growth',
    '/api/v1/analytics/department-kpis': 'growth',
    '/api/v1/reports': 'free',
    '/api/v1/exports': 'growth',
    '/api/v1/audit': 'growth',
    '/api/v1/admin': 'enterprise',
    '/api/v1/forecasting': 'enterprise',
    '/api/v1/pipeline': 'enterprise',
};

const PLAN_RANK = { free: 0, growth: 1, enterprise: 2 };

/**
 * Returns true if the tenant's plan meets or exceeds the required plan.
 * @param {string} tenantPlan - plan from JWT (free|growth|enterprise)
 * @param {string} requiredPlan - minimum plan for the feature
 * @returns {boolean}
 */
function hasAccess(tenantPlan, requiredPlan) {
    return (PLAN_RANK[tenantPlan] || 0) >= (PLAN_RANK[requiredPlan] || 0);
}

/**
 * Middleware: checks tenant plan against the route's required plan.
 * Must be mounted AFTER the authenticate middleware (needs req.user).
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function planGate(req, res, next) {
    const tenantPlan = req.user?.plan || 'free';

    // Find the most specific matching route prefix
    let requiredPlan = 'free';
    let matchedRoute = null;
    const path = req.path;

    for (const [prefix, plan] of Object.entries(FEATURE_MAP)) {
        if (path === prefix || path.startsWith(prefix + '/') || path.startsWith(prefix + '?')) {
            // Longest prefix wins
            if (!matchedRoute || prefix.length > matchedRoute.length) {
                requiredPlan = plan;
                matchedRoute = prefix;
            }
        }
    }

    if (!hasAccess(tenantPlan, requiredPlan)) {
        logger.info('Plan gate denied access', {
            tenantId: req.user?.tenantId,
            tenantPlan,
            requiredPlan,
            path,
            requestId: req.requestId,
        });

        return res.status(403).json({
            error: 'PLAN_UPGRADE_REQUIRED',
            requiredPlan,
            currentPlan: tenantPlan,
            message: `This feature requires the '${requiredPlan}' plan. Your current plan is '${tenantPlan}'.`,
            requestId: req.requestId,
        });
    }

    next();
}

module.exports = { planGate, hasAccess, FEATURE_MAP, PLAN_RANK };
