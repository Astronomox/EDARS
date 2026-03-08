'use strict';

/**
 * gateway/src/routes/admin/tenants.js
 *
 * Admin-only tenant management endpoints.
 * Handles tenant suspension, deletion scheduling, and GDPR erasure.
 *
 * Security requirements (enforced on EVERY route in this file):
 *   1. authenticate middleware (JWT validation)
 *   2. Admin role check
 *   3. IP whitelist middleware
 *
 * These three layers mean that even if a JWT is stolen, the
 * attacker cannot reach these endpoints from outside your VPN/office IP.
 */

const express = require('express');
const { pool, getTenantClient } = require('../../utils/dbHelper');
const logger = require('../../utils/logger');

const router = express.Router();

// ── Admin role guard ──────────────────────────────────────────
// This middleware runs on every route in this file.
// Importing ipWhitelist here because admin routes need BOTH.

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    logger.warn({
      event:         'ADMIN_ACCESS_DENIED',
      userId:        req.user?.userId,
      tenantId:      req.user?.tenantId,
      role:          req.user?.role,
      path:          req.path,
      ip:            req.ip,
      correlationId: req.correlationId,
    });

    return res.status(403).json({
      error:         'FORBIDDEN',
      code:          'ADMIN_ROLE_REQUIRED',
      correlationId: req.correlationId,
    });
  }
  next();
}

router.use(requireAdmin);

// ── GET /admin/tenants ────────────────────────────────────────
/**
 * List all tenants with status summary.
 * Returns: id, name, slug, plan, is_active, user_count,
 *          deletion_scheduled_at, created_at
 */
router.get('/', async (req, res) => {
  const client = await pool.connect(); // superuser connection — no RLS for admin list
  try {
    const { rows } = await client.query(`
      SELECT
        t.id,
        t.name,
        t.slug,
        t.plan,
        t.is_active,
        t.created_at,
        t.suspended_at,
        t.suspension_reason,
        t.deletion_requested_at,
        t.deletion_scheduled_at,
        t.deleted_at,
        t.max_users,
        t.data_retention_days,
        COUNT(u.id) FILTER (WHERE u.id IS NOT NULL) AS user_count
      FROM tenants t
      LEFT JOIN users u ON u.tenant_id = t.id
        AND u.email NOT LIKE 'deleted-%@redacted.invalid'
      GROUP BY t.id
      ORDER BY t.created_at DESC
    `);

    logger.info({
      event:         'ADMIN_TENANTS_LISTED',
      adminId:       req.user.userId,
      count:         rows.length,
      correlationId: req.correlationId,
    });

    return res.json({ tenants: rows, count: rows.length });
  } catch (err) {
    logger.error({
      event:         'ADMIN_TENANTS_LIST_FAILED',
      error:         err.message,
      correlationId: req.correlationId,
    });
    return res.status(500).json({
      error:         'INTERNAL_ERROR',
      correlationId: req.correlationId,
    });
  } finally {
    client.release();
  }
});

// ── POST /admin/tenants/:id/suspend ───────────────────────────
/**
 * Suspend a tenant — disables all their logins immediately.
 * Body: { reason: string }
 */
router.post('/:id/suspend', async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;

  if (!reason || typeof reason !== 'string' || reason.trim().length < 5) {
    return res.status(422).json({
      error:         'VALIDATION_ERROR',
      code:          'SUSPENSION_REASON_REQUIRED',
      message:       'Provide a suspension reason of at least 5 characters.',
      correlationId: req.correlationId,
    });
  }

  const client = await pool.connect();
  try {
    // Update tenant
    const { rows } = await client.query(
      `UPDATE tenants
       SET suspended_at = NOW(), suspension_reason = $1, is_active = false
       WHERE id = $2 AND deleted_at IS NULL
       RETURNING id, name, slug, suspended_at, suspension_reason`,
      [reason.trim(), id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        error:         'TENANT_NOT_FOUND',
        correlationId: req.correlationId,
      });
    }

    // Write audit entry
    await client.query(
      `INSERT INTO audit_log
         (tenant_id, user_id, action, resource, resource_id, ip, correlation_id, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [id, req.user.userId, 'TENANT_SUSPENDED', 'tenants', id, req.ip, req.correlationId]
    );

    logger.warn({
      event:         'TENANT_SUSPENDED',
      tenantId:      id,
      reason:        reason.trim(),
      adminId:       req.user.userId,
      correlationId: req.correlationId,
    });

    return res.json({ tenant: rows[0], message: 'Tenant suspended.' });
  } catch (err) {
    logger.error({
      event:         'TENANT_SUSPEND_FAILED',
      tenantId:      id,
      error:         err.message,
      correlationId: req.correlationId,
    });
    return res.status(500).json({
      error:         'INTERNAL_ERROR',
      correlationId: req.correlationId,
    });
  } finally {
    client.release();
  }
});

// ── POST /admin/tenants/:id/request-deletion ──────────────────
/**
 * Schedule a tenant for GDPR deletion 30 days from now.
 * This is the first step of the two-step erasure process.
 */
router.post('/:id/request-deletion', async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();

  try {
    const { rows } = await client.query(
      `SELECT request_tenant_deletion($1, $2)`,
      [id, req.user.userId]
    );

    // Fetch the updated tenant to return the scheduled date
    const { rows: tenants } = await client.query(
      `SELECT id, name, deletion_requested_at, deletion_scheduled_at
       FROM tenants WHERE id = $1`,
      [id]
    );

    const tenant = tenants[0];

    logger.warn({
      event:                  'TENANT_DELETION_REQUESTED',
      tenantId:               id,
      scheduledDeletionDate:  tenant?.deletion_scheduled_at,
      adminId:                req.user.userId,
      correlationId:          req.correlationId,
    });

    return res.json({
      message:               'Deletion scheduled. Data will be wiped after the hold period.',
      scheduledDeletionDate: tenant?.deletion_scheduled_at,
      tenantId:              id,
    });
  } catch (err) {
    if (err.message.includes('DELETION_ALREADY_REQUESTED') ||
        err.message.includes('TENANT_ALREADY_DELETED') ||
        err.message.includes('TENANT_NOT_FOUND')) {
      return res.status(409).json({
        error:         err.message,
        correlationId: req.correlationId,
      });
    }

    logger.error({
      event:         'TENANT_DELETION_REQUEST_FAILED',
      tenantId:      id,
      error:         err.message,
      correlationId: req.correlationId,
    });
    return res.status(500).json({
      error:         'INTERNAL_ERROR',
      correlationId: req.correlationId,
    });
  } finally {
    client.release();
  }
});

// ── POST /admin/tenants/:id/execute-deletion ──────────────────
/**
 * IRREVERSIBLE: Permanently anonymise all PII for a tenant.
 * Can only run after the 30-day hold period has passed.
 *
 * Body MUST include: { confirm: true }
 * This is a safety gate — prevents accidental execution.
 */
router.post('/:id/execute-deletion', async (req, res) => {
  const { id } = req.params;
  const { confirm } = req.body;

  // Hard safety gate
  if (confirm !== true) {
    return res.status(422).json({
      error:   'CONFIRMATION_REQUIRED',
      code:    'MUST_CONFIRM_DELETION',
      message: 'This action is IRREVERSIBLE. '
             + 'You must send { "confirm": true } in the request body.',
      correlationId: req.correlationId,
    });
  }

  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      `SELECT execute_tenant_deletion($1) AS result`,
      [id]
    );

    const result = rows[0]?.result;

    logger.warn({
      event:         'TENANT_DATA_WIPED',
      tenantId:      id,
      result,
      adminId:       req.user.userId,
      correlationId: req.correlationId,
    });

    return res.json({
      message:  'Tenant data permanently wiped.',
      detail:   result,
      tenantId: id,
    });
  } catch (err) {
    // Propagate known business logic errors as 409
    const knownErrors = [
      'TENANT_NOT_FOUND',
      'TENANT_ALREADY_DELETED',
      'DELETION_NOT_REQUESTED',
      'DELETION_HOLD_ACTIVE',
    ];

    if (knownErrors.some((e) => err.message.includes(e))) {
      return res.status(409).json({
        error:         err.message,
        correlationId: req.correlationId,
      });
    }

    logger.error({
      event:         'TENANT_DELETION_EXECUTE_FAILED',
      tenantId:      id,
      error:         err.message,
      correlationId: req.correlationId,
    });
    return res.status(500).json({
      error:         'INTERNAL_ERROR',
      correlationId: req.correlationId,
    });
  } finally {
    client.release();
  }
});

module.exports = router;
