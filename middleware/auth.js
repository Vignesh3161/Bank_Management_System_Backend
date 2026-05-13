const jwt = require('jsonwebtoken');
const db = require('../db');

// Verify the JWT is valid and check for revocation
const verifyToken = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'Authentication required' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Immediate Revocation check via Database `token_version`
        let table = 'users';
        if (decoded.role === 'CUSTOMER') table = 'customers';
        
        const result = await db.query(`SELECT token_version, is_locked FROM ${table} WHERE id = $1`, [decoded.id]);
        const user = result.rows[0];
        
        if (!user) return res.status(401).json({ error: 'Invalid user context' });
        
        if (user.is_locked) {
            return res.status(403).json({ error: 'Account is securely locked.' });
        }
        
        if (user.token_version !== decoded.token_version) {
            return res.status(401).json({ error: 'Token Revoked. Please re-authenticate.' });
        }

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Session Expired or JWT Malformed' });
    }
};

// Check if user has specific role permissions
const authorize = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: `Access Denied: ${req.user?.role || 'Unknown'} role does not have permission for this action.` 
            });
        }
        next();
    };
};

module.exports = { verifyToken, authorize };
