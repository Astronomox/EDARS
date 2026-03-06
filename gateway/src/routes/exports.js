// ═══════════════════════════════════════════════════════════════
// Data Export Routes — CSV & JSON Bulk Export
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const { authorize } = require('../middleware/auth');
const { getSecureClient } = require('../utils/dbHelper');
const logger = require('../utils/logger');

const router = express.Router();

// ─── GET /api/v1/exports/transactions ────────────────────────
// Exports transaction data as CSV or JSON
router.get('/transactions', authorize('analyst', 'manager', 'admin'), async (req, res, next) => {
    let secure;
    try {
        secure = await getSecureClient(req.db, req.user);
        const { format = 'json', startDate, endDate, limit = 1000 } = req.query;

        let query = `
      SELECT t.uuid, d.name AS department, t.amount, t.currency,
             t.description, t.category, t.transaction_date, t.created_at
      FROM transactions t
      JOIN departments d ON d.id = t.department_id
      WHERE 1=1`;
        const params = [];
        let idx = 1;

        if (startDate) {
            query += ` AND t.transaction_date >= $${idx++}`;
            params.push(startDate);
        }
        if (endDate) {
            query += ` AND t.transaction_date <= $${idx++}`;
            params.push(endDate);
        }

        query += ` ORDER BY t.transaction_date DESC LIMIT $${idx++}`;
        params.push(Math.min(parseInt(limit), 5000));

        const result = await secure.query(query, params);

        if (format === 'csv') {
            const header = 'uuid,department,amount,currency,description,category,transaction_date,created_at\n';
            const rows = result.rows.map(r =>
                `"${r.uuid}","${r.department}",${r.amount},"${r.currency}","${(r.description || '').replace(/"/g, '""')}","${r.category || ''}","${r.transaction_date}","${r.created_at}"`
            ).join('\n');

            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="transactions_export_${Date.now()}.csv"`);
            return res.send(header + rows);
        }

        res.json({ transactions: result.rows, count: result.rowCount, exportedAt: new Date().toISOString() });
    } catch (err) {
        next(err);
    } finally {
        if (secure) secure.release();
    }
});

// ─── GET /api/v1/exports/reports ─────────────────────────────
router.get('/reports', authorize('analyst', 'manager', 'admin'), async (req, res, next) => {
    let secure;
    try {
        secure = await getSecureClient(req.db, req.user);
        const { format = 'json', status, limit = 500 } = req.query;

        let query = `
      SELECT r.uuid, r.title, r.report_type, r.status, r.parameters,
             r.result_data, r.created_at, r.completed_at,
             u.full_name AS created_by, d.name AS department
      FROM reports r
      JOIN users u ON u.id = r.created_by
      JOIN departments d ON d.id = r.department_id
      WHERE 1=1`;
        const params = [];
        let idx = 1;

        if (status) {
            query += ` AND r.status = $${idx++}`;
            params.push(status);
        }

        query += ` ORDER BY r.created_at DESC LIMIT $${idx++}`;
        params.push(Math.min(parseInt(limit), 2000));

        const result = await secure.query(query, params);

        if (format === 'csv') {
            const header = 'uuid,title,report_type,status,department,created_by,created_at,completed_at\n';
            const rows = result.rows.map(r =>
                `"${r.uuid}","${(r.title || '').replace(/"/g, '""')}","${r.report_type}","${r.status}","${r.department}","${r.created_by}","${r.created_at}","${r.completed_at || ''}"`
            ).join('\n');

            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="reports_export_${Date.now()}.csv"`);
            return res.send(header + rows);
        }

        res.json({ reports: result.rows, count: result.rowCount, exportedAt: new Date().toISOString() });
    } catch (err) {
        next(err);
    } finally {
        if (secure) secure.release();
    }
});

// ─── GET /api/v1/exports/audit (admin only) ──────────────────
router.get('/audit', authorize('admin'), async (req, res, next) => {
    try {
        const { format = 'json', startDate, endDate, limit = 2000 } = req.query;

        let query = `
      SELECT al.uuid, u.email AS user_email, u.full_name AS user_name,
             al.action, al.resource_type, al.resource_id,
             al.ip_address, al.user_agent, al.metadata, al.created_at
      FROM audit_log al
      LEFT JOIN users u ON u.id = al.user_id
      WHERE 1=1`;
        const params = [];
        let idx = 1;

        if (startDate) { query += ` AND al.created_at >= $${idx++}`; params.push(startDate); }
        if (endDate) { query += ` AND al.created_at <= $${idx++}`; params.push(endDate); }

        query += ` ORDER BY al.created_at DESC LIMIT $${idx++}`;
        params.push(Math.min(parseInt(limit), 10000));

        const result = await req.db.query(query, params);

        if (format === 'csv') {
            const header = 'uuid,user_email,user_name,action,resource_type,resource_id,ip_address,created_at\n';
            const rows = result.rows.map(r =>
                `"${r.uuid}","${r.user_email || ''}","${r.user_name || ''}","${r.action}","${r.resource_type}","${r.resource_id || ''}","${r.ip_address || ''}","${r.created_at}"`
            ).join('\n');

            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="audit_export_${Date.now()}.csv"`);
            return res.send(header + rows);
        }

        res.json({ auditEntries: result.rows, count: result.rowCount, exportedAt: new Date().toISOString() });
    } catch (err) {
        next(err);
    }
});

module.exports = router;
