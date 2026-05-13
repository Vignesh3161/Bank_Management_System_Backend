const db = require('../db');

const auditLog = async (req, res, next) => {
    const originalSend = res.send;

    res.send = function (data) {
        const userId = req.user ? req.user.id : null;
        const actorType = req.user ? req.user.role === 'CUSTOMER' ? 'CUSTOMER' : 'USER' : 'SYSTEM';
        const action = `${req.method} ${req.originalUrl}`;

        // Log asynchronously to not block the main response
        db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, details, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, actorType, action, JSON.stringify({ resource: req.originalUrl, body: req.body, response: data }), req.ip, req.headers['user-agent']]
        ).catch(err => console.error('Audit log failed:', err));

        originalSend.apply(res, arguments);
    };

    next();
};

module.exports = { auditLog };
