// ═══════════════════════════════════════════════════════════════
// Reports Routes — CRUD + Trigger Generation
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const { authorize } = require('../middleware/auth');
const { getSecureClient } = require('../utils/dbHelper');
const logger = require('../utils/logger');

const router = express.Router();

// ─── GET /api/v1/reports ─────────────────────────────────────
// Viewers, Analysts, Managers, Admins — RLS enforces department scope
router.get('/', async (req, res, next) => {
    let secure;
    try {
        secure = await getSecureClient(req.db, req.user);
        const { status, type, limit = 50, offset = 0 } = req.query;

        let query = 'SELECT r.uuid, r.title, r.report_type, r.status, r.parameters, r.created_at, r.completed_at, d.name AS department FROM reports r JOIN departments d ON d.id = r.department_id WHERE 1=1';
        const params = [];
        let paramIdx = 1;

        if (status) {
            query += ` AND r.status = $${paramIdx++}`;
            params.push(status);
        }
        if (type) {
            query += ` AND r.report_type = $${paramIdx++}`;
            params.push(type);
        }

        query += ` ORDER BY r.created_at DESC LIMIT $${paramIdx++} OFFSET $${paramIdx++}`;
        params.push(Math.min(parseInt(limit), 100), parseInt(offset));

        const result = await secure.query(query, params);
        res.json({ reports: result.rows, count: result.rowCount });
    } catch (err) {
        next(err);
    } finally {
        if (secure) secure.release();
    }
});

// ─── GET /api/v1/reports/:uuid ───────────────────────────────
router.get('/:uuid', async (req, res, next) => {
    let secure;
    try {
        secure = await getSecureClient(req.db, req.user);
        const result = await secure.query(
            `SELECT r.uuid, r.title, r.report_type, r.status, r.parameters,
              r.result_data, r.created_at, r.completed_at,
              u.full_name AS created_by_name, d.name AS department
       FROM reports r
       JOIN users u ON u.id = r.created_by
       JOIN departments d ON d.id = r.department_id
       WHERE r.uuid = $1`,
            [req.params.uuid]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Report not found' });
        }

        res.json({ report: result.rows[0] });
    } catch (err) {
        next(err);
    } finally {
        if (secure) secure.release();
    }
});

// ─── POST /api/v1/reports ────────────────────────────────────
// Analysts, Managers, Admins can create reports
router.post('/', authorize('analyst', 'manager', 'admin'), async (req, res, next) => {
    let secure;
    try {
        secure = await getSecureClient(req.db, req.user);
        const { title, reportType, parameters, departmentId } = req.body;

        if (!title || !reportType) {
            return res.status(400).json({ error: 'title and reportType are required' });
        }

        const validTypes = ['sales_summary', 'user_activity', 'department_kpis'];
        if (!validTypes.includes(reportType)) {
            return res.status(400).json({ error: `reportType must be one of: ${validTypes.join(', ')}` });
        }

        const deptId = departmentId || req.user.departmentId;

        const result = await secure.query(
            `INSERT INTO reports (title, report_type, parameters, department_id, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING uuid, title, report_type, status, created_at`,
            [title, reportType, JSON.stringify(parameters || {}), deptId, req.user.id]
        );

        const report = result.rows[0];

        // Trigger async analytics processing
        try {
            const fetch = (await import('node-fetch')).default;
            const analyticsUrl = process.env.ANALYTICS_URL || 'http://analytics:8000';
            fetch(`${analyticsUrl}/api/v1/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Service-Token': process.env.SERVICE_TOKEN,
                },
                body: JSON.stringify({
                    reportUuid: report.uuid,
                    reportType,
                    parameters: parameters || {},
                    departmentId: deptId,
                }),
            }).catch(err => {
                logger.error('Failed to trigger analytics', { error: err.message });
            });
        } catch (fetchErr) {
            logger.error('Analytics trigger error', { error: fetchErr.message });
        }

        logger.info('Report created', { uuid: report.uuid, type: reportType });

        res.status(201).json({
            message: 'Report created and generation triggered',
            report,
        });
    } catch (err) {
        next(err);
    } finally {
        if (secure) secure.release();
    }
});

module.exports = router;
