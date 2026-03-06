// ═══════════════════════════════════════════════════════════════
// User Management Routes
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const { authorize } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// ─── GET /api/v1/users/me ────────────────────────────────────
router.get('/me', async (req, res, next) => {
    try {
        const result = await req.db.query(
            `SELECT u.uuid, u.email, u.full_name, u.role, u.is_active,
              u.last_login_at, u.created_at,
              d.name AS department, d.uuid AS department_uuid
       FROM users u
       JOIN departments d ON d.id = u.department_id
       WHERE u.id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Fetch all assigned departments
        const depts = await req.db.query(
            `SELECT d.uuid, d.name FROM user_departments ud
       JOIN departments d ON d.id = ud.department_id
       WHERE ud.user_id = $1`,
            [req.user.id]
        );

        res.json({
            user: {
                ...result.rows[0],
                assignedDepartments: depts.rows,
            },
        });
    } catch (err) {
        next(err);
    }
});

// ─── GET /api/v1/users (admin only) ─────────────────────────
router.get('/', authorize('admin'), async (req, res, next) => {
    try {
        const { limit = 50, offset = 0, role, department } = req.query;

        let query = `
      SELECT u.uuid, u.email, u.full_name, u.role, u.is_active,
             u.last_login_at, u.created_at, d.name AS department
      FROM users u
      JOIN departments d ON d.id = u.department_id
      WHERE 1=1`;
        const params = [];
        let idx = 1;

        if (role) {
            query += ` AND u.role = $${idx++}`;
            params.push(role);
        }
        if (department) {
            query += ` AND d.name ILIKE $${idx++}`;
            params.push(`%${department}%`);
        }

        query += ` ORDER BY u.created_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
        params.push(Math.min(parseInt(limit), 200), parseInt(offset));

        const result = await req.db.query(query, params);

        res.json({ users: result.rows, count: result.rowCount });
    } catch (err) {
        next(err);
    }
});

// ─── PATCH /api/v1/users/:uuid/deactivate (admin only) ──────
router.patch('/:uuid/deactivate', authorize('admin'), async (req, res, next) => {
    try {
        const result = await req.db.query(
            `UPDATE users SET is_active = FALSE, updated_at = NOW()
       WHERE uuid = $1
       RETURNING uuid, email, full_name, is_active`,
            [req.params.uuid]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        logger.info('User deactivated', { uuid: req.params.uuid, by: req.user.email });

        res.json({ message: 'User deactivated', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

module.exports = router;
