const { Pool } = require('pg');
const dotenv = require('dotenv');
const dns = require('dns');

dotenv.config();

// Create a custom DNS resolver to bypass local ISP / network blocks on Neon databases
const resolver = new dns.Resolver();
resolver.setServers(['8.8.8.8', '1.1.1.1']);

// DNS Cache to avoid redundant DNS lookups
let cachedIp = null;
let dnsCacheTime = 0;
const DNS_CACHE_TTL = 300000; // 5 minutes cache TTL

const customLookup = (hostname, options, callback) => {
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
        return dns.lookup(hostname, options, callback);
    }

    const now = Date.now();
    if (cachedIp && (now - dnsCacheTime < DNS_CACHE_TTL)) {
        return callback(null, cachedIp, 4);
    }

    resolver.resolve4(hostname, (err, addresses) => {
        if (!err && addresses && addresses.length > 0) {
            cachedIp = addresses[0];
            dnsCacheTime = now;
            return callback(null, cachedIp, 4);
        }
        // Fallback to standard DNS lookup
        dns.lookup(hostname, options, callback);
    });
};

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    lookup: customLookup,
    // Pool optimizations
    max: 20,                  // Increase max connections from default 10 to 20
    idleTimeoutMillis: 120000, // Keep idle connections open for 2 minutes (prevents constant SSL handshakes to remote db)
    connectionTimeoutMillis: 5000 // Fast connection timeout
});

module.exports = {
    query: (text, params) => pool.query(text, params),
    getClient: () => pool.connect(),
};

