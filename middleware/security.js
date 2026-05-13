const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

let redisWarningLogged = false;
redis.on('error', (err) => {
    if (!redisWarningLogged) {
        console.warn('[SECURITY] Redis is unavailable. Security features (Rate Limiting/Replay Protection) are in fail-open mode.');
        redisWarningLogged = true;
    }
});

// 1. Rate Limiter (Redis-based)
const rateLimiter = async (req, res, next) => {
    const ip = req.ip;
    const key = `ratelimit:${ip}`;
    
    try {
        const count = await redis.incr(key);
        if (count === 1) await redis.expire(key, 60); // 60s window
        
        if (count > 100) { // Limit: 100 requests per minute
            return res.status(429).json({ error: "Too many requests. Security threshold exceeded." });
        }
        next();
    } catch (err) {
        next(); // Fail open if Redis is down (policy choice)
    }
};

// 2. Replay Attack Prevention
// Expecting 'x-nonce' and 'x-timestamp' headers
const replayProtection = async (req, res, next) => {
    const nonce = req.headers['x-nonce'];
    const timestamp = req.headers['x-timestamp'];

    if (!nonce || !timestamp) {
        // For public routes, skip. For transactions, enforce.
        if (req.path.includes('/transactions')) {
            return res.status(400).json({ error: "Security validation failed: Missing nonce/timestamp" });
        }
        return next();
    }

    // Check if timestamp is within a 5-minute window
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    if (Math.abs(now - requestTime) > 300000) {
        return res.status(403).json({ error: "Request expired. Replay attack blocked." });
    }

    // Check if nonce has been used
    const nonceKey = `nonce:${nonce}`;
    const wasSet = await redis.set(nonceKey, '1', 'EX', 300, 'NX');
    if (!wasSet) {
        return res.status(403).json({ error: "Identity mismatch: Nonce already used." });
    }

    next();
};

module.exports = { rateLimiter, replayProtection };
