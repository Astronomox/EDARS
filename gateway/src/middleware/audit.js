// ═══════════════════════════════════════════════════════════════
// Audit Logging Middleware — Tenant-Aware
// ═══════════════════════════════════════════════════════════════
// Records every mutating or sensitive request to the immutable
// audit_log table.  Includes tenant_id for multi-tenant isolation.
//
// CRITICAL: If an audit log write fails, the parent request MUST
// also fail.  Audit integrity is not optional.
// ═══════════════════════════════════════════════════════════════
const logger = require('../utils/logger');

/**
 * Middleware: records an audit log entry for mutating requests
 * and sensitive GETs (audit, users, exports).
 *
 * Mounted AFTER authenticate middleware so req.user is available.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function auditLog(req, res, next) {
    // Audit all mutating methods + sensitive GETs
    const shouldAudit =
        ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ||
        req.path.includes('/audit') ||
        req.path.includes('/users') ||
        req.path.includes('/exports') ||
        req.path.includes('/admin');

    if (!shouldAudit) {
        return next();
    }

    // Capture the original res.json to write audit entry
    // AFTER the route handler has produced a response but
    // BEFORE sending it to the client.
    const originalJson = res.json.bind(res);
    res.json = async (body) => {
        try {
            await writeAuditEntry(req, res.statusCode);
        } catch (err) {
            // AUDIT INTEGRITY: If audit write fails, fail the request
            logger.error('CRITICAL: Audit log write failed — request will be rejected', {
                error: err.message,
                requestId: req.requestId,
                userId: req.user?.id,
                tenantId: req.user?.tenantId,
                action: `${req.method} ${req.baseUrl}${req.path}`,
            });
            return originalJson({
                error: 'Request failed due to audit system error',
                code: 'AUDIT_FAILURE',
                correlationId: req.requestId,
            });
        }
        return originalJson(body);
    };

    next();
}

/**
 * Writes an audit log entry to the database.
 *
 * @param {import('express').Request} req - Express request with user context
 * @param {number} statusCode - HTTP status code of the response
 * @returns {Promise<void>}
 * @throws {Error} If the database write fails
 * @side-effect Inserts a row into audit_log table
 */
async function writeAuditEntry(req, statusCode) {
    const { db, user } = req;
    if (!db || !user) return;

    const action = `${req.method} ${req.baseUrl}${req.path}`;
    const resourceParts = req.baseUrl.split('/').filter(Boolean);
    // resource_type is the API resource (e.g., 'reports', 'users', 'analytics')
    const resourceType = resourceParts[resourceParts.length - 1] || 'unknown';
    // resource_id is the specific entity (e.g., UUID from path param)
    const pathParts = req.path.split('/').filter(Boolean);
    const resourceId = pathParts[0] || null;

    await db.query(
        `INSERT INTO audit_log (tenant_id, user_id, action, resource_type, resource_id,
                                ip_address, user_agent, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
            user.tenantId || 1,
            user.id,
            action,
            resourceType,
            resourceId,
            req.ip,
            req.get('User-Agent') || 'unknown',
            JSON.stringify({
                status_code: statusCode,
                correlationId: req.requestId,
                timestamp: new Date().toISOString(),
            }),
        ]
    );
}

module.exports = { auditLog };
