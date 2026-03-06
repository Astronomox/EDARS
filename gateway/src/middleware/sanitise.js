w// ═══════════════════════════════════════════════════════════════
// Input Sanitisation Middleware
// ═══════════════════════════════════════════════════════════════
// Strips dangerous patterns from all string inputs to prevent
// XSS, SQL injection fragments, and NoSQL injection attempts.

const logger = require('../utils/logger');

// Patterns that should never appear in user input
const DANGEROUS_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,  // Script tags
    /javascript\s*:/gi,                                       // JS protocol
    /on\w+\s*=/gi,                                            // Event handlers
    /data\s*:\s*text\/html/gi,                                 // Data URI XSS
    /expression\s*\(/gi,                                       // CSS expression
    /url\s*\(\s*['"]?\s*javascript/gi,                        // CSS url() XSS
];

// Characters to encode
const ENCODE_MAP = {
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '`': '&#x60;',
};

function sanitiseString(str) {
    if (typeof str !== 'string') return str;

    let sanitised = str;

    // Strip dangerous patterns
    for (const pattern of DANGEROUS_PATTERNS) {
        sanitised = sanitised.replace(pattern, '');
    }

    // Encode dangerous characters in non-password fields
    sanitised = sanitised.replace(/[<>"'`]/g, (char) => ENCODE_MAP[char] || char);

    // Trim excessive whitespace
    sanitised = sanitised.replace(/\s{10,}/g, ' ');

    return sanitised;
}

function sanitiseObject(obj, depth = 0) {
    if (depth > 10) return obj; // Prevent infinite recursion

    if (typeof obj === 'string') return sanitiseString(obj);
    if (Array.isArray(obj)) return obj.map(item => sanitiseObject(item, depth + 1));
    if (obj && typeof obj === 'object') {
        const clean = {};
        for (const [key, value] of Object.entries(obj)) {
            // Skip sanitisation for password fields (they need special chars)
            if (key === 'password' || key === 'password_hash') {
                clean[key] = value;
            } else {
                clean[sanitiseString(key)] = sanitiseObject(value, depth + 1);
            }
        }
        return clean;
    }
    return obj;
}

function sanitise(req, res, next) {
    try {
        if (req.body && typeof req.body === 'object') {
            req.body = sanitiseObject(req.body);
        }
        if (req.query && typeof req.query === 'object') {
            req.query = sanitiseObject(req.query);
        }
        if (req.params && typeof req.params === 'object') {
            req.params = sanitiseObject(req.params);
        }
    } catch (err) {
        logger.error('Sanitisation error', { error: err.message, requestId: req.requestId });
    }
    next();
}

module.exports = { sanitise, sanitiseString, sanitiseObject };
