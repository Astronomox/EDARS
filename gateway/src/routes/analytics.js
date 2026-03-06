// ═══════════════════════════════════════════════════════════════
// Analytics Proxy Routes — Forwards to internal Python service
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const { authorize } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

const ANALYTICS_URL = process.env.ANALYTICS_URL || 'http://analytics:8000';
const SERVICE_TOKEN = process.env.SERVICE_TOKEN;

/**
 * Internal fetch helper — adds service token header.
 */
async function analyticsRequest(path, options = {}) {
    const fetch = (await import('node-fetch')).default;
    const url = `${ANALYTICS_URL}${path}`;

    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'X-Service-Token': SERVICE_TOKEN,
            ...(options.headers || {}),
        },
        timeout: 30000,
    });

    if (!response.ok) {
        const body = await response.text();
        throw new Error(`Analytics service responded with ${response.status}: ${body}`);
    }

    return response.json();
}

// ─── GET /api/v1/analytics/dashboard ─────────────────────────
// Returns aggregated dashboard metrics for the user's department(s)
router.get('/dashboard', async (req, res, next) => {
    try {
        const data = await analyticsRequest(
            `/api/v1/dashboard?userId=${req.user.id}&departmentId=${req.user.departmentId}&role=${req.user.role}`
        );
        res.json(data);
    } catch (err) {
        logger.error('Analytics dashboard request failed', { error: err.message });
        res.status(502).json({ error: 'Analytics service unavailable' });
    }
});

// ─── GET /api/v1/analytics/sales-summary ─────────────────────
router.get('/sales-summary', authorize('analyst', 'manager', 'admin'), async (req, res, next) => {
    try {
        const { startDate, endDate, departmentId } = req.query;
        const data = await analyticsRequest(
            `/api/v1/sales-summary?startDate=${startDate || ''}&endDate=${endDate || ''}&departmentId=${departmentId || req.user.departmentId}&role=${req.user.role}&userId=${req.user.id}`
        );
        res.json(data);
    } catch (err) {
        logger.error('Sales summary request failed', { error: err.message });
        res.status(502).json({ error: 'Analytics service unavailable' });
    }
});

// ─── GET /api/v1/analytics/user-activity ─────────────────────
router.get('/user-activity', authorize('analyst', 'manager', 'admin'), async (req, res, next) => {
    try {
        const { days = 30 } = req.query;
        const data = await analyticsRequest(
            `/api/v1/user-activity?days=${days}&userId=${req.user.id}&role=${req.user.role}`
        );
        res.json(data);
    } catch (err) {
        logger.error('User activity request failed', { error: err.message });
        res.status(502).json({ error: 'Analytics service unavailable' });
    }
});

// ─── GET /api/v1/analytics/department-kpis ───────────────────
router.get('/department-kpis', authorize('manager', 'admin'), async (req, res, next) => {
    try {
        const { departmentId } = req.query;
        const data = await analyticsRequest(
            `/api/v1/department-kpis?departmentId=${departmentId || ''}&userId=${req.user.id}&role=${req.user.role}`
        );
        res.json(data);
    } catch (err) {
        logger.error('Department KPIs request failed', { error: err.message });
        res.status(502).json({ error: 'Analytics service unavailable' });
    }
});

module.exports = router;
