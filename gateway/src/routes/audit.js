// ═══════════════════════════════════════════════════════════════
// Audit Trail Routes — Admin Only
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const { authorize } = require('../middleware/auth');

const router = express.Router();

// ─── GET /api/v1/audit ───────────────────────────────────────
// Full audit trail — admin eyes only
router.get('/', authorize('admin'), async (req, res, next) => {
    try {
        const {
            userId, action, resourceType,
            startDate, endDate,
            limit = 50, offset = 0,
        } = req.query;

        let query = `
      SELECT al.uuid, al.action, al.resource_type, al.resource_id,
             al.ip_address, al.user_agent, al.metadata, al.created_at,
             u.full_name AS user_name, u.email AS user_email
      FROM audit_log al
      LEFT JOIN users u ON u.id = al.user_id
      WHERE 1=1`;
        const params = [];
        let idx = 1;

        if (userId) {
            query += ` AND al.user_id = $${idx++}`;
            params.push(userId);
        }
        if (action) {
            query += ` AND al.action ILIKE $${idx++}`;
            params.push(`%${action}%`);
        }
        if (resourceType) {
            query += ` AND al.resource_type = $${idx++}`;
            params.push(resourceType);
        }
        if (startDate) {
            query += ` AND al.created_at >= $${idx++}`;
            params.push(startDate);
        }
        if (endDate) {
            query += ` AND al.created_at <= $${idx++}`;
            params.push(endDate);
        }

        query += ` ORDER BY al.created_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
        params.push(Math.min(parseInt(limit), 200), parseInt(offset));

        const result = await req.db.query(query, params);

        res.json({ auditEntries: result.rows, count: result.rowCount });
    } catch (err) {
        next(err);
    }
});

module.exports = router;
