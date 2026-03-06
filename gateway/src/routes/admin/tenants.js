// ═══════════════════════════════════════════════════════════════
// Admin Tenant Management Routes
// ═══════════════════════════════════════════════════════════════
// All routes require BOTH:
//   1. JWT authentication (authenticate middleware at server level)
//   2. Admin role
//   3. IP whitelist (explicitly applied on each route)
//
// SECURITY: These routes can suspend, delete, or wipe tenant data.
// They are the most sensitive endpoints in the system.
// ═══════════════════════════════════════════════════════════════
'use strict';

const express = require('express');
const logger = require('../../utils/logger');
const { ipWhitelist } = require('../../middleware/ipWhitelist');

const router = express.Router();

/**
 * Reusable admin check. Returns 403 if not admin.
 */
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            error: 'INSUFFICIENT_PERMISSIONS',
            code: 'ADMIN_REQUIRED',
            correlationId: req.requestId,
        });
    }
    next();
}

// Every route in this file requires admin + IP whitelist
router.use(requireAdmin, ipWhitelist);


// ═══════════════════════════════════════════════════════════════
// GET /api/v1/admin/tenants
// Lists all tenants with plan, status, user count, deletion info
// ═══════════════════════════════════════════════════════════════
router.get('/tenants', async (req, res, next) => {
    try {
        const result = await req.db.query(`
            SELECT
                t.id,
                t.name,
                t.slug,
                t.plan,
                t.is_active,
                t.max_users,
                t.data_retention_days,
                t.created_at,
                t.suspended_at,
                t.suspension_reason,
                t.deletion_requested_at,
                t.deletion_scheduled_at,
                t.deleted_at,
                COUNT(u.id) AS user_count
            FROM tenants t
            LEFT JOIN users u ON u.tenant_id = t.id AND u.is_active = TRUE
            GROUP BY t.id
            ORDER BY t.created_at DESC
        `);

        res.json({
            tenants: result.rows,
            total: result.rowCount,
            correlationId: req.requestId,
        });
    } catch (err) {
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/admin/tenants/:id/suspend
// Suspends a tenant. Body: { reason: string }
// ═══════════════════════════════════════════════════════════════
router.post('/tenants/:id/suspend', async (req, res, next) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;

        if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
            return res.status(400).json({
                error: 'VALIDATION_ERROR',
                code: 'MISSING_REASON',
                message: 'A suspension reason is required.',
                correlationId: req.requestId,
            });
        }

        // Update tenant
        const result = await req.db.query(
            `UPDATE tenants SET
                suspended_at = NOW(),
                suspension_reason = $1,
                is_active = FALSE
             WHERE id = $2
             RETURNING *`,
            [reason.trim(), id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                code: 'TENANT_NOT_FOUND',
                correlationId: req.requestId,
            });
        }

        // Audit
        await req.db.query(
            `INSERT INTO audit_log
                (tenant_id, user_id, action, resource_type, resource_id,
                 ip_address, user_agent, metadata)
             VALUES ($1, $2, 'TENANT_SUSPENDED', 'tenants', $3, $4, $5, $6)`,
            [
                id, req.user.userId, id,
                req.ip, req.get('User-Agent') || 'unknown',
                JSON.stringify({
                    reason: reason.trim(),
                    suspendedBy: req.user.userId,
                    timestamp: new Date().toISOString(),
                }),
            ]
        );

        logger.info('Tenant suspended', {
            tenantId: id,
            reason: reason.trim(),
            suspendedBy: req.user.userId,
            requestId: req.requestId,
        });

        res.json({
            tenant: result.rows[0],
            message: 'Tenant suspended successfully.',
            correlationId: req.requestId,
        });
    } catch (err) {
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/admin/tenants/:id/request-deletion
// Initiates the 30-day deletion hold period
// ═══════════════════════════════════════════════════════════════
router.post('/tenants/:id/request-deletion', async (req, res, next) => {
    try {
        const { id } = req.params;

        const result = await req.db.query(
            'SELECT * FROM request_tenant_deletion($1)',
            [id]
        );

        const tenant = result.rows[0];

        logger.warn('Tenant deletion requested', {
            tenantId: id,
            scheduledFor: tenant.deletion_scheduled_at,
            requestedBy: req.user.userId,
            requestId: req.requestId,
        });

        res.json({
            tenant,
            scheduledDeletionDate: tenant.deletion_scheduled_at,
            message: 'Tenant deletion has been scheduled. '
                + 'Data will be permanently wiped after the 30-day hold period. '
                + 'This action can be cancelled by contacting support before the scheduled date.',
            correlationId: req.requestId,
        });
    } catch (err) {
        // Surface known exceptions from the stored procedure
        if (err.message.includes('TENANT_NOT_FOUND')) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                code: 'TENANT_NOT_FOUND',
                correlationId: req.requestId,
            });
        }
        if (err.message.includes('TENANT_ALREADY_DELETED')) {
            return res.status(409).json({
                error: 'CONFLICT',
                code: 'TENANT_ALREADY_DELETED',
                correlationId: req.requestId,
            });
        }
        if (err.message.includes('DELETION_ALREADY_REQUESTED')) {
            return res.status(409).json({
                error: 'CONFLICT',
                code: 'DELETION_ALREADY_REQUESTED',
                correlationId: req.requestId,
            });
        }
        next(err);
    }
});


// ═══════════════════════════════════════════════════════════════
// POST /api/v1/admin/tenants/:id/execute-deletion
// IRREVERSIBLE. Wipes all tenant data.
// Body: { confirm: true } — safety gate
// ═══════════════════════════════════════════════════════════════
router.post('/tenants/:id/execute-deletion', async (req, res, next) => {
    try {
        const { id } = req.params;
        const { confirm } = req.body;

        // Safety gate — must explicitly confirm
        if (confirm !== true) {
            return res.status(422).json({
                error: 'CONFIRMATION_REQUIRED',
                code: 'MISSING_CONFIRM',
                message: 'This action is IRREVERSIBLE. '
                    + 'Set { "confirm": true } in the request body '
                    + 'to proceed with permanent data deletion.',
                correlationId: req.requestId,
            });
        }

        const result = await req.db.query(
            'SELECT * FROM execute_tenant_deletion($1)',
            [id]
        );

        const tenant = result.rows[0];

        logger.warn('TENANT DATA WIPED — IRREVERSIBLE', {
            tenantId: id,
            tenantName: tenant.name,
            executedBy: req.user.userId,
            requestId: req.requestId,
        });

        res.json({
            message: 'Tenant data wiped. This action is irreversible.',
            tenant: {
                id: tenant.id,
                slug: tenant.slug,
                deleted_at: tenant.deleted_at,
            },
            correlationId: req.requestId,
        });
    } catch (err) {
        if (err.message.includes('TENANT_NOT_FOUND')) {
            return res.status(404).json({
                error: 'NOT_FOUND',
                code: 'TENANT_NOT_FOUND',
                correlationId: req.requestId,
            });
        }
        if (err.message.includes('DELETION_NOT_REQUESTED')) {
            return res.status(422).json({
                error: 'PRECONDITION_FAILED',
                code: 'DELETION_NOT_REQUESTED',
                message: 'Call /request-deletion first.',
                correlationId: req.requestId,
            });
        }
        if (err.message.includes('DELETION_HOLD_PERIOD')) {
            return res.status(422).json({
                error: 'PRECONDITION_FAILED',
                code: 'HOLD_PERIOD_ACTIVE',
                message: 'Cannot delete before the 30-day hold period expires.',
                correlationId: req.requestId,
            });
        }
        if (err.message.includes('TENANT_ALREADY_DELETED')) {
            return res.status(409).json({
                error: 'CONFLICT',
                code: 'TENANT_ALREADY_DELETED',
                correlationId: req.requestId,
            });
        }
        next(err);
    }
});


module.exports = router;
