// ═══════════════════════════════════════════════════════════════
// Structured JSON Logger — Winston
// ═══════════════════════════════════════════════════════════════
// Every log line includes: { timestamp, level, service, message,
//   correlationId?, userId?, tenantId? }
// NEVER logs passwords, raw tokens, JWT secrets, or plain PII.
// ═══════════════════════════════════════════════════════════════
const { createLogger, format, transports } = require('winston');

/**
 * Custom format: adds correlationId, userId, and tenantId when
 * present in the log metadata.  Strips any fields that should
 * never appear in log output for security reasons.
 */
const securityFilter = format((info) => {
    // Strip sensitive fields if they leaked into metadata
    const REDACTED_KEYS = ['password', 'password_hash', 'token', 'accessToken',
        'refreshToken', 'secret', 'jwt', 'authorization', 'cookie'];

    for (const key of REDACTED_KEYS) {
        if (info[key]) info[key] = '[REDACTED]';
        if (info.metadata?.[key]) info.metadata[key] = '[REDACTED]';
    }

    // Mask email if present (show only domain)
    if (info.email && typeof info.email === 'string') {
        info.email = info.email.replace(/^[^@]+/, '***');
    }

    return info;
});

const logger = createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        format.errors({ stack: true }),
        securityFilter(),
        format.json()
    ),
    defaultMeta: { service: 'edars-gateway' },
    transports: [
        new transports.Console({
            format: process.env.NODE_ENV !== 'production'
                ? format.combine(format.colorize(), format.simple())
                : format.json(),
        }),
    ],
});

module.exports = logger;
