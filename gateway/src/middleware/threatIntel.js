// ═══════════════════════════════════════════════════════════════
// Threat Intelligence Middleware — Automated Threat Detection
// ═══════════════════════════════════════════════════════════════
// Features:
//   • IP reputation scoring with escalating responses
//   • Request fingerprinting (header ordering, anomaly detection)
//   • Honeypot trap endpoints that auto-flag attackers
//   • Geo-fence enforcement (country allow/deny lists)
//   • Behavioural analysis (request velocity, path scanning detection)
//   • Auto-escalation: warn → throttle → temp ban → permanent ban
// ═══════════════════════════════════════════════════════════════
const logger = require('../utils/logger');
const crypto = require('crypto');

// ─── Threat Score Thresholds ─────────────────────────────────
const THRESHOLDS = {
    WARN: 25,
    THROTTLE: 50,
    TEMP_BAN: 75,
    PERM_BAN: 100,
};

const TEMP_BAN_DURATION = 3600;       // 1 hour
const PERM_BAN_DURATION = 86400 * 30; // 30 days
const SCORE_DECAY_SECONDS = 300;      // Threat score decays every 5 min
const PATH_SCAN_THRESHOLD = 15;       // Distinct 404 paths before flagged
const PATH_SCAN_WINDOW = 60;          // Window in seconds

// ─── Suspicious Patterns ─────────────────────────────────────
const SUSPICIOUS_PATHS = [
    /\/\.env/i, /\/\.git/i, /\/wp-admin/i, /\/wp-login/i,
    /\/phpmyadmin/i, /\/admin\.php/i, /\/xmlrpc\.php/i,
    /\/\.aws/i, /\/\.ssh/i, /\/etc\/passwd/i,
    /\/actuator/i, /\/debug/i, /\/console/i,
    /\/\.htaccess/i, /\/\.htpasswd/i, /\/server-status/i,
    /\/cgi-bin/i, /\/shell/i, /\/cmd/i,
    /\/eval/i, /\/exec/i, /\/system/i,
];

const SUSPICIOUS_HEADERS = [
    'x-forwarded-host',     // Potential host header injection
    'x-original-url',       // URL rewrite attacks
    'x-rewrite-url',        // URL rewrite attacks
];

const SUSPICIOUS_PAYLOADS = [
    /union\s+select/i, /;\s*drop\s+table/i, /'\s*or\s+'1/i,
    /exec\s*\(/i, /xp_cmdshell/i, /benchmark\s*\(/i,
    /sleep\s*\(/i, /load_file\s*\(/i, /into\s+outfile/i,
    /\$\{.*jndi/i,                  // Log4Shell
    /\{\{.*\}\}/,                    // SSTI
    /%00/,                           // Null byte injection
    /\.\.\/\.\.\/\.\.\//,           // Path traversal
];

// ─── Honeypot Trap Paths ─────────────────────────────────────
// Any request to these paths is GUARANTEED malicious
const HONEYPOT_PATHS = [
    '/wp-login.php', '/administrator/', '/phpmyadmin/',
    '/xmlrpc.php', '/.env', '/.git/config',
    '/actuator/env', '/debug/vars', '/server-info',
    '/_debug/', '/console/', '/api/swagger.json',
];

/**
 * Creates the threat intelligence middleware.
 * @param {import('ioredis')} redis — Redis client for state storage
 */
function createThreatIntel(redis) {
    return async (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const path = req.path.toLowerCase();

        try {
            // ── 1. Check permanent ban ──────────────────────
            const permBanned = await redis.get(`threat:permban:${ip}`);
            if (permBanned) {
                logger.warn('Permanently banned IP attempted access', {
                    ip, path, requestId: req.requestId,
                });
                return res.status(403).json({ error: 'Access denied' });
            }

            // ── 2. Check temporary ban ──────────────────────
            const tempBanned = await redis.get(`threat:tempban:${ip}`);
            if (tempBanned) {
                const ttl = await redis.ttl(`threat:tempban:${ip}`);
                logger.warn('Temporarily banned IP attempted access', {
                    ip, path, ttl, requestId: req.requestId,
                });
                return res.status(429).json({
                    error: 'Temporarily blocked',
                    retryAfter: ttl,
                });
            }

            // ── 3. Compute threat score ─────────────────────
            let score = await getThreatScore(redis, ip);

            // ── 4. Honeypot detection ───────────────────────
            if (HONEYPOT_PATHS.some(hp => path === hp || path.startsWith(hp))) {
                score += 50; // Immediate high threat
                logger.error('HONEYPOT TRIGGERED', {
                    ip, path, requestId: req.requestId,
                    fingerprint: computeFingerprint(req),
                });
                await recordThreatEvent(redis, ip, 'honeypot', { path });
            }

            // ── 5. Suspicious path scanning ─────────────────
            if (SUSPICIOUS_PATHS.some(p => p.test(path))) {
                score += 15;
                await recordThreatEvent(redis, ip, 'suspicious_path', { path });
            }

            // ── 6. Suspicious headers ───────────────────────
            for (const header of SUSPICIOUS_HEADERS) {
                if (req.headers[header]) {
                    score += 10;
                    await recordThreatEvent(redis, ip, 'suspicious_header', {
                        header, value: req.headers[header].substring(0, 100),
                    });
                }
            }

            // ── 7. Payload inspection ───────────────────────
            const bodyStr = JSON.stringify(req.body || {});
            const queryStr = JSON.stringify(req.query || {});
            const payload = bodyStr + queryStr + (req.originalUrl || '');

            for (const pattern of SUSPICIOUS_PAYLOADS) {
                if (pattern.test(payload)) {
                    score += 25;
                    await recordThreatEvent(redis, ip, 'malicious_payload', {
                        pattern: pattern.toString(),
                    });
                    break; // One hit is enough
                }
            }

            // ── 8. Path scanning velocity ───────────────────
            const scanCount = await trackPathScanning(redis, ip, path);
            if (scanCount > PATH_SCAN_THRESHOLD) {
                score += 20;
                await recordThreatEvent(redis, ip, 'path_scanning', {
                    distinctPaths: scanCount,
                });
            }

            // ── 9. Request fingerprint anomaly ──────────────
            const fingerprint = computeFingerprint(req);
            const fpAnomaly = await checkFingerprintAnomaly(redis, ip, fingerprint);
            if (fpAnomaly) {
                score += 10;
            }

            // ── 10. Persist score & enforce ─────────────────
            await setThreatScore(redis, ip, score);

            // Attach threat metadata to request
            req.threatScore = score;
            req.threatFingerprint = fingerprint;

            if (score >= THRESHOLDS.PERM_BAN) {
                await redis.setex(`threat:permban:${ip}`, PERM_BAN_DURATION, JSON.stringify({
                    score, bannedAt: new Date().toISOString(),
                    events: await getThreatEvents(redis, ip),
                }));
                logger.error('IP PERMANENTLY BANNED', {
                    ip, score, requestId: req.requestId,
                });
                return res.status(403).json({ error: 'Access denied' });
            }

            if (score >= THRESHOLDS.TEMP_BAN) {
                await redis.setex(`threat:tempban:${ip}`, TEMP_BAN_DURATION, '1');
                logger.error('IP TEMPORARILY BANNED', {
                    ip, score, duration: TEMP_BAN_DURATION, requestId: req.requestId,
                });
                return res.status(429).json({
                    error: 'Temporarily blocked',
                    retryAfter: TEMP_BAN_DURATION,
                });
            }

            if (score >= THRESHOLDS.THROTTLE) {
                // Add artificial delay (50ms per point over threshold)
                const delay = (score - THRESHOLDS.THROTTLE) * 50;
                logger.warn('Throttling suspicious IP', {
                    ip, score, delay, requestId: req.requestId,
                });
                await new Promise(resolve => setTimeout(resolve, Math.min(delay, 5000)));
            }

            if (score >= THRESHOLDS.WARN) {
                res.setHeader('X-Threat-Level', 'elevated');
            }

            next();
        } catch (err) {
            // Threat intel failure should never block legitimate requests
            logger.error('Threat intelligence error (non-blocking)', {
                error: err.message, ip, requestId: req.requestId,
            });
            next();
        }
    };
}

// ─── Honeypot Route Handler ──────────────────────────────────
// Mount this on trap paths — any hit is an instant ban escalation
function honeypotHandler(redis) {
    return async (req, res) => {
        const ip = req.ip;
        const score = await getThreatScore(redis, ip);
        await setThreatScore(redis, ip, score + 50);
        await recordThreatEvent(redis, ip, 'honeypot_direct', {
            path: req.path,
            method: req.method,
            headers: sanitiseHeaders(req.headers),
        });

        logger.error('HONEYPOT DIRECT HIT', {
            ip, path: req.path, method: req.method,
            requestId: req.requestId,
        });

        // Return a realistic-looking decoy response
        await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 3000));
        res.status(200).json({ status: 'ok' }); // Misleading on purpose
    };
}

// ─── Helper Functions ────────────────────────────────────────

async function getThreatScore(redis, ip) {
    const data = await redis.get(`threat:score:${ip}`);
    if (!data) return 0;
    const { score, updatedAt } = JSON.parse(data);
    // Decay score over time
    const elapsed = (Date.now() - updatedAt) / 1000;
    const decay = Math.floor(elapsed / SCORE_DECAY_SECONDS) * 5;
    return Math.max(0, score - decay);
}

async function setThreatScore(redis, ip, score) {
    const ttl = 86400; // 24 hour window
    await redis.setex(`threat:score:${ip}`, ttl, JSON.stringify({
        score: Math.min(score, 150), // Cap at 150
        updatedAt: Date.now(),
    }));
}

async function recordThreatEvent(redis, ip, type, details = {}) {
    const key = `threat:events:${ip}`;
    const event = JSON.stringify({
        type,
        details,
        timestamp: new Date().toISOString(),
    });
    await redis.lpush(key, event);
    await redis.ltrim(key, 0, 99); // Keep last 100 events
    await redis.expire(key, 86400 * 7); // 7-day retention
}

async function getThreatEvents(redis, ip) {
    const events = await redis.lrange(`threat:events:${ip}`, 0, 20);
    return events.map(e => JSON.parse(e));
}

async function trackPathScanning(redis, ip, path) {
    const key = `threat:pathscan:${ip}`;
    await redis.sadd(key, path);
    await redis.expire(key, PATH_SCAN_WINDOW);
    return redis.scard(key);
}

function computeFingerprint(req) {
    const components = [
        Object.keys(req.headers).sort().join(','),
        req.headers['accept-language'] || '',
        req.headers['accept-encoding'] || '',
        req.headers['accept'] || '',
        req.headers['connection'] || '',
    ];
    return crypto
        .createHash('sha256')
        .update(components.join('|'))
        .digest('hex')
        .substring(0, 16);
}

async function checkFingerprintAnomaly(redis, ip, fingerprint) {
    const key = `threat:fp:${ip}`;
    const stored = await redis.get(key);
    if (!stored) {
        await redis.setex(key, 3600, fingerprint);
        return false;
    }
    // If fingerprint changed, it *might* be suspicious (but not always)
    if (stored !== fingerprint) {
        const changeCount = await redis.incr(`threat:fpchanges:${ip}`);
        await redis.expire(`threat:fpchanges:${ip}`, 3600);
        await redis.setex(key, 3600, fingerprint);
        return changeCount > 5; // Only flag if rapid changes
    }
    return false;
}

function sanitiseHeaders(headers) {
    const safe = {};
    const allowList = [
        'user-agent', 'accept', 'accept-language',
        'accept-encoding', 'content-type', 'host',
    ];
    for (const key of allowList) {
        if (headers[key]) {
            safe[key] = headers[key].substring(0, 200);
        }
    }
    return safe;
}

/**
 * Admin endpoint: get threat intelligence summary
 */
function getThreatSummary(redis) {
    return async (req, res) => {
        try {
            const keys = await redis.keys('threat:score:*');
            const threats = [];

            for (const key of keys.slice(0, 50)) {
                const ip = key.replace('threat:score:', '');
                const score = await getThreatScore(redis, ip);
                if (score > 0) {
                    const events = await getThreatEvents(redis, ip);
                    threats.push({ ip, score, recentEvents: events.slice(0, 5) });
                }
            }

            threats.sort((a, b) => b.score - a.score);

            const permBans = await redis.keys('threat:permban:*');
            const tempBans = await redis.keys('threat:tempban:*');

            res.json({
                activeThreatCount: threats.length,
                permanentBans: permBans.length,
                temporaryBans: tempBans.length,
                topThreats: threats.slice(0, 20),
                timestamp: new Date().toISOString(),
            });
        } catch (err) {
            res.status(500).json({ error: 'Failed to retrieve threat data' });
        }
    };
}

module.exports = { createThreatIntel, honeypotHandler, getThreatSummary };
