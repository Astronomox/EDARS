// ═══════════════════════════════════════════════════════════════
// Database Helper — RLS + Tenant Context Per Request
// ═══════════════════════════════════════════════════════════════
'use strict';

const logger = require('./logger');

// pool is injected at server startup via setPool()
let pool = null;

/**
 * Sets the database pool reference. Called once at server startup.
 * @param {import('pg').Pool} p - pg Pool instance
 */
function setPool(p) {
    pool = p;
}

/**
 * Returns the current pool reference.
 * @returns {import('pg').Pool}
 */
function getPool() {
    if (!pool) throw new Error('Database pool not initialised — call setPool() first');
    return pool;
}

/**
 * Acquires a client from the pool and sets the RLS session
 * variables so PostgreSQL row-level policies filter correctly.
 *
 * @param {import('pg').Pool} dbPool - pg Pool instance
 * @param {object} user - decoded JWT user payload
 * @param {number} user.userId - user integer ID
 * @param {string} user.role - user role (viewer|analyst|manager|admin)
 * @returns {object} { query, release } — release() MUST be called when done
 * @throws {Error} If pool.connect() or SET LOCAL fails
 */
async function getSecureClient(dbPool, user) {
    const client = await dbPool.connect();

    try {
        await client.query('BEGIN');

        // Validate types to prevent injection via SET LOCAL
        const userId = parseInt(user.userId || user.id, 10);
        const role = String(user.role).replace(/[^a-z_]/gi, '');

        if (isNaN(userId)) {
            throw new Error('Invalid user context: userId must be an integer');
        }

        await client.query(`SET LOCAL app.current_user_id = '${userId}'`);
        await client.query(`SET LOCAL app.current_user_role = '${role}'`);

        // If tenantId is present (UUID), also set tenant context
        if (user.tenantId) {
            await client.query('SELECT set_tenant_context($1)', [user.tenantId]);
        }
    } catch (err) {
        client.release();
        throw err;
    }

    return {
        /**
         * Runs a parameterised query within the RLS-secured context.
         * @param {string} text - SQL with $1, $2... placeholders
         * @param {any[]}  params - parameter values
         * @returns {import('pg').QueryResult}
         */
        async query(text, params) {
            return client.query(text, params);
        },

        /**
         * Commits the transaction and releases the client.
         */
        async release() {
            try {
                await client.query('COMMIT');
            } catch (err) {
                await client.query('ROLLBACK').catch(() => { });
                logger.error('Transaction commit failed', { error: err.message });
            } finally {
                client.release();
            }
        },
    };
}

/**
 * Returns a PostgreSQL client scoped to one tenant.
 * Sets app.current_tenant_id so RLS policies enforce
 * data isolation automatically.
 *
 * ALWAYS use this for any query touching tenant data.
 * NEVER query pool.connect() directly from routes.
 *
 * @param {string} tenantId - UUID from req.user.tenantId
 * @returns {Promise<import('pg').PoolClient>}
 *
 * @example
 *   const client = await getTenantClient(req.user.tenantId);
 *   try {
 *     const { rows } = await client.query('SELECT * FROM reports');
 *     res.json(rows);
 *   } finally {
 *     client.release();
 *   }
 */
async function getTenantClient(tenantId) {
    if (!tenantId || typeof tenantId !== 'string') {
        throw new Error('getTenantClient: valid tenantId string (UUID) required');
    }

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(tenantId)) {
        throw new Error('getTenantClient: tenantId must be a valid UUID');
    }

    const dbPool = getPool();
    const client = await dbPool.connect();

    try {
        await client.query('SELECT set_tenant_context($1)', [tenantId]);
        return client;
    } catch (err) {
        client.release();
        throw err;
    }
}

module.exports = { getSecureClient, getTenantClient, setPool, getPool };
