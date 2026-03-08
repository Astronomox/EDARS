// ═══════════════════════════════════════════════════════════════
// EDARS API Gateway — Main Server  (ENHANCED v3.0)
// ═══════════════════════════════════════════════════════════════
// Features: Request tracing, compression, graceful shutdown,
//           input sanitisation, circuit breaker, IP whitelisting,
//           threat intelligence, HMAC request signing, Prometheus
//           metrics, honeypot traps, security dashboard
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const { Pool } = require('pg');
const Redis = require('ioredis');
const { v4: uuid } = require('uuid');
const logger = require('./utils/logger');

// ─── Middleware ────────────────────────────────────────────────
const { createRateLimiter } = require('./middleware/rateLimiter');
const { authenticate } = require('./middleware/auth');
const { auditLog } = require('./middleware/audit');
const { sanitise } = require('./middleware/sanitise');
const { requestTracer } = require('./middleware/tracer');
const { circuitBreaker } = require('./middleware/circuitBreaker');
const { metricsCollector, metricsEndpoint } = require('./middleware/metrics');
const { createThreatIntel, honeypotHandler, getThreatSummary } = require('./middleware/threatIntel');
const { createHmacVerifier } = require('./middleware/hmacVerify');

// ─── Routes ───────────────────────────────────────────────────
const authRoutes = require('./routes/auth');
const reportRoutes = require('./routes/reports');
const userRoutes = require('./routes/users');
const analyticsRoutes = require('./routes/analytics');
const auditRoutes = require('./routes/audit');
const healthRoutes = require('./routes/health');
const exportRoutes = require('./routes/exports');

const tenancy = require('./middleware/tenancy');
const { ipWhitelist } = require('./middleware/ipWhitelist');
const adminTenants = require('./routes/admin/tenants');

// ─── Database Pool (expanded) ─────────────────────────────────
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'edars',
  user: process.env.DB_USER || 'edars_admin',
  password: process.env.DB_PASSWORD,
  max: parseInt(process.env.DB_POOL_MAX || '20'),
  min: parseInt(process.env.DB_POOL_MIN || '5'),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  statement_timeout: 30000,  // Kill queries running > 30s
  query_timeout: 30000,
});

pool.on('error', (err) => {
  logger.error('Unexpected database pool error', { error: err.message });
});

// ─── Redis Client (with reconnect strategy) ──────────────────
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
  enableReadyCheck: true,
  lazyConnect: false,
});

redis.on('error', (err) => logger.error('Redis error', { error: err.message }));
redis.on('connect', () => logger.info('Redis connected'));
redis.on('reconnecting', () => logger.warn('Redis reconnecting'));

// ─── Express App ──────────────────────────────────────────────
const app = express();

// Trust proxy (for correct IP behind Nginx)
app.set('trust proxy', 1);

// ── Request Tracing (X-Request-ID on every response) ─────────
app.use(requestTracer);

// ── Prometheus Metrics Collection ────────────────────────────
app.use(metricsCollector);

// ── Compression (gzip/brotli) ────────────────────────────────
app.use(compression({
  level: 6,
  threshold: 1024,  // Only compress responses > 1KB
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
}));

// ── Security Headers (hardened) ──────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
}));

// ── Body Parsing — 10KB limit ────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ── Input Sanitisation ───────────────────────────────────────
app.use(sanitise);

// ── CORS ─────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Signature', 'X-Timestamp', 'X-Nonce'],
  exposedHeaders: ['X-Request-ID', 'X-RateLimit-Remaining', 'Retry-After', 'X-Threat-Level'],
  credentials: true,
  maxAge: 86400,
}));

// ── Rate Limiting ────────────────────────────────────────────
app.use(createRateLimiter(redis));

// ── Threat Intelligence ──────────────────────────────────────
app.use(createThreatIntel(redis));

// ── HMAC Request Signing Verification ────────────────────────
app.use(createHmacVerifier(redis, {
  excludePaths: ['/health', '/metrics', '/api/v1/auth/login', '/api/v1/auth/password-policy'],
}));

// ── Inject dependencies ─────────────────────────────────────
app.use((req, res, next) => {
  req.db = pool;
  req.redis = redis;
  next();
});

// ── Request Logging ──────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 400 ? 'warn' : 'info';
    logger[level]('Request completed', {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      threatScore: req.threatScore || 0,
    });
  });
  next();
});

// ─── Honeypot Trap Routes ────────────────────────────────────
// These paths attract scanners — any hit is malicious
const trapPaths = [
  '/wp-login.php', '/wp-admin', '/administrator',
  '/phpmyadmin', '/xmlrpc.php', '/.env', '/.git/config',
  '/actuator/env', '/debug/vars', '/server-info',
  '/console', '/_debug', '/api/swagger.json',
];
for (const trap of trapPaths) {
  app.all(trap, honeypotHandler(redis));
}

// ─── Health (unauthenticated) ────────────────────────────────
app.use('/health', healthRoutes(pool, redis));

// ─── Prometheus Metrics (internal only) ──────────────────────
app.get('/metrics', metricsEndpoint(pool, redis));

// ─── Public Routes ───────────────────────────────────────────
app.use('/api/v1/auth', authRoutes);

// ─── Protected Routes ────────────────────────────────────────
// Flow: authenticate → tenancy (plan gate) → auditLog → route handler
app.use('/api/v1/reports', authenticate, tenancy, auditLog, reportRoutes);
app.use('/api/v1/users', authenticate, tenancy, auditLog, userRoutes);
app.use('/api/v1/analytics', authenticate, tenancy, auditLog, circuitBreaker('analytics'), analyticsRoutes);
app.use('/api/v1/audit', authenticate, tenancy, auditLog, auditRoutes);
app.use('/api/v1/exports', authenticate, tenancy, auditLog, exportRoutes);

// ─── Admin-Only Internal Routes ──────────────────────────────
app.use('/api/v1/admin', authenticate, ipWhitelist, adminTenants);

app.post('/api/v1/admin/refresh-views', authenticate, ipWhitelist, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('SELECT refresh_all_materialized_views()');
    res.json({ message: 'Materialized views refreshed', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to refresh views' });
  }
});

app.get('/api/v1/admin/anomalies', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const { days = 90 } = req.query;
    const result = await pool.query('SELECT * FROM detect_spending_anomalies($1)', [parseInt(days)]);
    res.json({ anomalies: result.rows, count: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Anomaly detection failed' });
  }
});

app.get('/api/v1/admin/inactive-users', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const { days = 90 } = req.query;
    const result = await pool.query('SELECT * FROM get_inactive_users($1)', [parseInt(days)]);
    res.json({ inactiveUsers: result.rows, count: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

app.get('/api/v1/admin/department-health/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query('SELECT * FROM calculate_department_health($1)', [parseInt(req.params.id)]);
    res.json({ health: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: 'Health calculation failed' });
  }
});

// ─── Threat Intelligence Admin Endpoints ─────────────────────
app.get('/api/v1/admin/threats', authenticate, ipWhitelist, getThreatSummary(redis));

app.post('/api/v1/admin/threats/unblock', authenticate, ipWhitelist, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP address required' });
  try {
    await redis.del(`threat:permban:${ip}`);
    await redis.del(`threat:tempban:${ip}`);
    await redis.del(`threat:score:${ip}`);
    // Also unblock in database
    await pool.query('DELETE FROM blocked_ips WHERE ip_address = $1', [ip]);
    logger.info('IP manually unblocked by admin', { ip, adminId: req.user.id });
    res.json({ message: `IP ${ip} unblocked`, unblockedBy: req.user.email });
  } catch (err) {
    res.status(500).json({ error: 'Unblock failed' });
  }
});

// ─── Security Dashboard Endpoint ─────────────────────────────
app.get('/api/v1/admin/security-dashboard', authenticate, ipWhitelist, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const [failedLogins, targetedAccounts, sessions, blockedIps, chainIntegrity] = await Promise.all([
      pool.query('SELECT * FROM security_failed_login_timeline(24)'),
      pool.query('SELECT * FROM security_targeted_accounts(24, 10)'),
      pool.query('SELECT * FROM security_active_sessions_summary()'),
      pool.query('SELECT COUNT(*) AS total FROM blocked_ips WHERE is_permanent = TRUE OR expires_at > NOW()'),
      pool.query('SELECT COUNT(*) AS broken FROM verify_audit_chain(500) WHERE chain_valid = FALSE'),
    ]);

    res.json({
      failedLoginTimeline: failedLogins.rows,
      targetedAccounts: targetedAccounts.rows,
      activeSessions: sessions.rows[0] || {},
      blockedIps: parseInt(blockedIps.rows[0]?.total || 0),
      auditChainBroken: parseInt(chainIntegrity.rows[0]?.broken || 0),
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    logger.error('Security dashboard query failed', { error: err.message });
    res.status(500).json({ error: 'Failed to generate security dashboard' });
  }
});

// ─── 404 Handler ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    requestId: req.requestId,
  });
});

// ─── Global Error Handler ────────────────────────────────────
// SECURITY: Never expose internal stack traces in API responses.
// Only logged server-side. Response always returns sanitised body.
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', {
    requestId: req.requestId,
    error: err.message,
    stack: err.stack,
    method: req.method,
    path: req.path,
    userId: req.user?.id,
    tenantId: req.user?.tenantId,
  });
  const statusCode = err.status || 500;
  res.status(statusCode).json({
    error: statusCode >= 500 ? 'Internal server error' : err.message,
    code: statusCode >= 500 ? 'INTERNAL_ERROR' : (err.code || 'REQUEST_ERROR'),
    correlationId: req.requestId,
  });
});

// ─── Graceful Shutdown ───────────────────────────────────────
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`EDARS API Gateway v3.0 running on port ${PORT}`, {
    env: process.env.NODE_ENV || 'development',
    pid: process.pid,
    threatIntel: 'enabled',
    hmacSigning: process.env.HMAC_ENABLED !== 'false' ? 'enabled' : 'disabled',
    metrics: 'enabled',
  });
});

async function gracefulShutdown(signal) {
  logger.info(`${signal} received — starting graceful shutdown`);

  // Stop accepting new connections
  server.close(() => {
    logger.info('HTTP server closed');
  });

  // Allow in-flight requests 10 seconds to complete
  setTimeout(async () => {
    try {
      await pool.end();
      logger.info('Database pool closed');
      redis.disconnect();
      logger.info('Redis disconnected');
    } catch (err) {
      logger.error('Error during shutdown', { error: err.message });
    }
    process.exit(0);
  }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
