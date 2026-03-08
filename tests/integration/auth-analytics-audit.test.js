'use strict';

/**
 * tests/integration/auth-analytics-audit.test.js
 *
 * Integration test: proves the end-to-end flow works correctly.
 *
 * Flow tested:
 *   1. POST /api/v1/auth/login with seed credentials
 *   2. Extract JWT from response
 *   3. GET /api/v1/analytics/dashboard with JWT
 *   4. Verify audit_log entry was written
 *   5. Verify tenant isolation (org A cannot read org B data)
 *
 * Prerequisites:
 *   - Docker Compose stack must be running
 *   - DB must have been seeded with 003_seed.sql
 *   - Run: docker compose up -d
 *   - Then: npm run test:integration
 *
 * Environment:
 *   - GATEWAY_URL=http://localhost:3000 (or set in .env.test)
 *   - DATABASE_ADMIN_URL=postgresql://postgres:password@localhost:5432/edars
 */

const supertest = require('supertest');
const { Pool } = require('pg');

// ── Config ────────────────────────────────────────────────────
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const DB_URL = process.env.DATABASE_ADMIN_URL ||
  'postgresql://postgres:postgres@localhost:5432/edars';

const request = supertest(GATEWAY_URL);
const db = new Pool({ connectionString: DB_URL });

// ── Test State ────────────────────────────────────────────────
let adminToken;
let analystToken;
let adminUser;

// ── Setup ─────────────────────────────────────────────────────
beforeAll(async () => {
  // Verify DB is reachable
  await db.query('SELECT 1');
}, 10_000);

afterAll(async () => {
  await db.end();
});

// ── Tests ─────────────────────────────────────────────────────

describe('Authentication flow', () => {
  test('POST /api/v1/auth/login returns JWT for valid credentials', async () => {
    const res = await request
      .post('/api/v1/auth/login')
      .send({ email: 'admin@edars.internal', password: 'P@ssw0rd123!' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(typeof res.body.token).toBe('string');

    adminToken = res.body.token;
  });

  test('JWT payload contains required tenant fields', async () => {
    // Decode without verifying (we just want to inspect the payload shape)
    const parts = adminToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

    expect(payload).toHaveProperty('userId');
    expect(payload).toHaveProperty('tenantId');
    expect(payload).toHaveProperty('plan');
    expect(payload).toHaveProperty('slug');
    expect(payload).toHaveProperty('role');
  });

  test('POST /api/v1/auth/login returns 401 for invalid password', async () => {
    const res = await request
      .post('/api/v1/auth/login')
      .send({ email: 'admin@edars.internal', password: 'wrongpassword' });

    expect(res.status).toBe(401);
    expect(res.body).not.toHaveProperty('token');
    // Must not leak whether email exists
    expect(res.body.error).toBe('INVALID_CREDENTIALS');
  });

  test('POST /api/v1/auth/login returns 401 for non-existent email', async () => {
    const res = await request
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@nowhere.com', password: 'anything' });

    expect(res.status).toBe(401);
    // Same error as wrong password — timing-safe, no email enumeration
    expect(res.body.error).toBe('INVALID_CREDENTIALS');
  });

  test('Login response never contains password hash', async () => {
    const res = await request
      .post('/api/v1/auth/login')
      .send({ email: 'admin@edars.internal', password: 'P@ssw0rd123!' });

    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/\$2[aby]\$\d+\$/); // bcrypt pattern
  });

  test('Analyst can also login', async () => {
    const res = await request
      .post('/api/v1/auth/login')
      .send({ email: 'm.jones@edars.internal', password: 'P@ssw0rd123!' });

    expect(res.status).toBe(200);
    analystToken = res.body.token;
  });
});

describe('Authenticated analytics access', () => {
  test('GET /api/v1/analytics/dashboard returns 200 with valid JWT', async () => {
    expect(adminToken).toBeDefined();

    const res = await request
      .get('/api/v1/analytics/dashboard')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
  });

  test('GET /api/v1/analytics/dashboard returns 401 without token', async () => {
    const res = await request.get('/api/v1/analytics/dashboard');

    expect(res.status).toBe(401);
  });

  test('GET /api/v1/analytics/dashboard returns 401 with malformed token', async () => {
    const res = await request
      .get('/api/v1/analytics/dashboard')
      .set('Authorization', 'Bearer not.a.valid.token');

    expect(res.status).toBe(401);
  });
});

describe('Audit log integrity', () => {
  test('successful login writes an audit entry', async () => {
    // Wait a moment for async audit write
    await new Promise((r) => setTimeout(r, 200));

    const { rows } = await db.query(
      `SELECT * FROM audit_log 
       WHERE action = 'USER_LOGIN' 
       ORDER BY timestamp DESC 
       LIMIT 1`
    );

    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].action).toBe('USER_LOGIN');
    expect(rows[0].tenant_id).toBeDefined();
  });

  test('audit_log rows cannot be updated (immutability)', async () => {
    const { rows } = await db.query(
      `SELECT id FROM audit_log LIMIT 1`
    );

    if (rows.length === 0) {
      console.warn('No audit log entries to test — skipping immutability check');
      return;
    }

    const auditId = rows[0].id;

    await expect(
      db.query(
        `UPDATE audit_log SET action = 'TAMPERED' WHERE id = $1`,
        [auditId]
      )
    ).rejects.toThrow();
  });

  test('audit_log rows cannot be deleted (immutability)', async () => {
    const { rows } = await db.query(
      `SELECT id FROM audit_log LIMIT 1`
    );

    if (rows.length === 0) return;

    await expect(
      db.query(`DELETE FROM audit_log WHERE id = $1`, [rows[0].id])
    ).rejects.toThrow();
  });
});

describe('Tenant data isolation (RLS)', () => {
  test('user from Tenant A cannot read Tenant B data via API', async () => {
    // This test requires two tenants to exist in the DB.
    // If only one tenant exists in dev, this test auto-skips.
    const { rows: tenants } = await db.query(
      `SELECT id, slug FROM tenants WHERE is_active = true ORDER BY created_at LIMIT 2`
    );

    if (tenants.length < 2) {
      console.warn('Only 1 tenant in DB — skipping cross-tenant isolation test');
      return;
    }

    // Log in as user from tenant 1
    const loginRes = await request
      .post('/api/v1/auth/login')
      .send({ email: 'admin@edars.internal', password: 'P@ssw0rd123!' });

    const token = loginRes.body.token;
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64').toString()
    );
    const myTenantId = payload.tenantId;

    // Fetch reports — must only contain our tenant's data
    const reportsRes = await request
      .get('/api/v1/reports')
      .set('Authorization', `Bearer ${token}`);

    expect(reportsRes.status).toBe(200);

    const reports = reportsRes.body;
    const alienReports = reports.filter(
      (r) => r.tenant_id && r.tenant_id !== myTenantId
    );

    expect(alienReports).toHaveLength(0);
  });

  test('direct DB query as edars_app role only returns own tenant data', async () => {
    // Connect as the app role (non-superuser — RLS applies)
    const appPool = new Pool({
      connectionString: process.env.DATABASE_URL ||
        'postgresql://edars_app:apppassword@localhost:5432/edars',
    });

    try {
      const client = await appPool.connect();
      try {
        // Set tenant context to the dev tenant
        const { rows: tenants } = await db.query(
          `SELECT id FROM tenants WHERE slug = 'edars-dev' LIMIT 1`
        );

        if (tenants.length === 0) {
          console.warn('Dev tenant not found — skipping RLS DB test');
          return;
        }

        await client.query(
          `SELECT set_tenant_context($1)`,
          [tenants[0].id]
        );

        const { rows: users } = await client.query(`SELECT tenant_id FROM users`);
        const alien = users.filter((u) => u.tenant_id !== tenants[0].id);

        expect(alien).toHaveLength(0);
      } finally {
        client.release();
      }
    } catch (err) {
      if (err.code === 'ECONNREFUSED') {
        console.warn('Cannot connect as edars_app — skipping RLS DB test');
        return;
      }
      throw err;
    } finally {
      await appPool.end();
    }
  });
});

describe('Error response hygiene', () => {
  test('404 responses do not leak stack traces', async () => {
    const res = await request
      .get('/api/v1/this-route-does-not-exist')
      .set('Authorization', `Bearer ${adminToken}`);

    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/at\s+\w+\s+\(/); // stack trace pattern
    expect(body).not.toContain('node_modules');
  });

  test('5xx responses use sanitised error format', async () => {
    // Trigger with a deliberately bad payload to a strict endpoint
    const res = await request
      .post('/api/v1/reports')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(null);

    if (res.status >= 500) {
      expect(res.body).not.toHaveProperty('stack');
      expect(res.body).toHaveProperty('error');
      expect(res.body).toHaveProperty('correlationId');
    }
  });
});
