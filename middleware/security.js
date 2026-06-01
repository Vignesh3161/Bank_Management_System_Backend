const Redis = require('ioredis');

// Configure Redis to fail fast and not queue commands when disconnected
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
    enableOfflineQueue: false,
    maxRetriesPerRequest: 0,
    connectTimeout: 1000 // Fast timeout
});

let isRedisConnected = false;
let redisWarningLogged = false;

redis.on('connect', () => {
    isRedisConnected = true;
    redisWarningLogged = false;
    console.log('[SECURITY] Redis connected successfully. Security features active.');
});

redis.on('error', (err) => {
    isRedisConnected = false;
    if (!redisWarningLogged) {
        console.warn('[SECURITY] Redis is unavailable. Security features (Rate Limiting/Replay Protection) are in fail-open mode.');
        redisWarningLogged = true;
    }
});

redis.on('close', () => {
    isRedisConnected = false;
});

// 1. Rate Limiter (Redis-based, with in-memory fallback or immediate bypass)
const rateLimiter = async (req, res, next) => {
    if (!isRedisConnected) {
        // Fail-open immediately with 0ms latency if Redis is down
        return next();
    }

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
        // For public/GET routes, skip. For mutating transaction submissions (POST), enforce.
        if (req.path.includes('/transactions') && req.method === 'POST') {
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

    if (!isRedisConnected) {
        // Fail-open immediately if Redis is down
        return next();
    }

    // Check if nonce has been used
    const nonceKey = `nonce:${nonce}`;
    try {
        const wasSet = await redis.set(nonceKey, '1', 'EX', 300, 'NX');
        if (!wasSet) {
            return res.status(403).json({ error: "Identity mismatch: Nonce already used." });
        }
    } catch (err) {
        // Fail-open on Redis error
    }

    next();
};

module.exports = { rateLimiter, replayProtection };

