// ═══════════════════════════════════════════════════════════════
// IP Whitelist Middleware — Admin Operations Only
// ═══════════════════════════════════════════════════════════════
// Restricts sensitive admin endpoints (view refresh, db ops)
// to a set of trusted IP addresses / CIDR ranges.

const logger = require('../utils/logger');

// Default whitelist: loopback + Docker internal networks
const DEFAULT_WHITELIST = [
    '127.0.0.1',
    '::1',
    '::ffff:127.0.0.1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
];

function parseCIDR(cidr) {
    const [ip, bits] = cidr.split('/');
    if (!bits) return { ip, mask: 0xFFFFFFFF };
    const mask = (~0 << (32 - parseInt(bits))) >>> 0;
    return { ip, mask };
}

function ipToInt(ip) {
    // Handle IPv4-mapped IPv6
    const v4 = ip.replace('::ffff:', '');
    const parts = v4.split('.');
    if (parts.length !== 4) return 0;
    return ((parseInt(parts[0]) << 24) |
        (parseInt(parts[1]) << 16) |
        (parseInt(parts[2]) << 8) |
        parseInt(parts[3])) >>> 0;
}

function isInRange(clientIp, cidr) {
    const { ip: rangeIp, mask } = parseCIDR(cidr);
    const clientInt = ipToInt(clientIp);
    const rangeInt = ipToInt(rangeIp);
    return (clientInt & mask) === (rangeInt & mask);
}

function ipWhitelist(req, res, next) {
    const whitelist = process.env.ADMIN_IP_WHITELIST
        ? process.env.ADMIN_IP_WHITELIST.split(',').map(s => s.trim())
        : DEFAULT_WHITELIST;

    const clientIp = req.ip || req.connection.remoteAddress;

    const allowed = whitelist.some(entry => {
        if (entry.includes('/')) return isInRange(clientIp, entry);
        return clientIp === entry || clientIp === `::ffff:${entry}`;
    });

    if (!allowed) {
        logger.warn('IP whitelist rejection', {
            ip: clientIp,
            path: req.path,
            requestId: req.requestId,
            userId: req.user?.id,
        });
        return res.status(403).json({
            error: 'Access denied — IP not whitelisted',
            requestId: req.requestId,
        });
    }

    next();
}

module.exports = { ipWhitelist };
