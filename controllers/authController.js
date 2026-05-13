const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db');
const otplib = require('otplib');
const qrcode = require('qrcode');
const { comparePassword: cmpPw, hashPassword: hshPw, hashHMAC, generateAccountNumber, encryptAES } = require('../utils/cryptoUtils');

exports.login = async (req, res) => {
    const { username, password } = req.body;

    try {
        // Search in both users (staff) and customers
        let result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        let user = result.rows[0];
        let actorType = 'USER';

        if (!user) {
            result = await db.query('SELECT * FROM customers WHERE username = $1', [username]);
            user = result.rows[0];
            if (user) {
                actorType = 'CUSTOMER';
            }
        }

        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (user.is_locked) return res.status(403).json({ error: 'Account is locked.' });

        const isMatch = await cmpPw(password, user.password_hash);
        const table = actorType === 'CUSTOMER' ? 'customers' : 'users';

        if (!isMatch) {
            const newAttempts = user.failed_login_count + 1;
            let updateQuery = `UPDATE ${table} SET failed_login_count = $1 WHERE id = $2`;
            if (newAttempts >= 5) updateQuery = `UPDATE ${table} SET failed_login_count = $1, is_locked = TRUE WHERE id = $2`;
            await db.query(updateQuery, [newAttempts, user.id]);
            
            await db.query(
                'INSERT INTO audit_log (actor_id, actor_type, action, details) VALUES ($1, $2, $3, $4)',
                [user.id, actorType, 'LOGIN_FAILED', JSON.stringify({ reason: 'Invalid password', attempt: newAttempts })]
            );

            return res.status(401).json({ error: 'Invalid credentials' });
        }

        await db.query(`UPDATE ${table} SET failed_login_count = 0 WHERE id = $1`, [user.id]);

        // Hardcoded OTP for development/testing
        const otp = "666666";
        const otpHash = hashHMAC(otp);
        const targetHmac = actorType === 'CUSTOMER' ? user.mobile_hmac : hashHMAC(user.username); // Simplified target

        await db.query(
            'INSERT INTO otp_verifications (target_hmac, otp_hash, purpose, expires_at) VALUES ($1, $2, $3, $4)',
            [targetHmac, otpHash, 'LOGIN', new Date(Date.now() + 15 * 60000)] // 15 min
        );

        // In a real system, send SMS here via Twilio/Bull
        console.log(`[DEBUG] OTP for ${username}: ${otp}`);

        const otpSessionToken = jwt.sign(
            { id: user.id, username: user.username, role: user.role || 'CUSTOMER', actorType, targetHmac, purpose: 'LOGIN' },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({ 
            message: "Step 1 complete. OTP sent to registered mobile.",
            otp_session_token: otpSessionToken,
            requires_2fa: true 
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
};

exports.verifyOTP = async (req, res) => {
    const { otp_session_token, otp } = req.body;
    try {
        const decoded = jwt.verify(otp_session_token, process.env.JWT_SECRET);
        if (decoded.purpose !== 'LOGIN') return res.status(401).json({ error: 'Invalid session' });

        const otpHash = hashHMAC(otp);
        const otpRes = await db.query(
            'SELECT * FROM otp_verifications WHERE target_hmac = $1 AND otp_hash = $2 AND purpose = $3 AND is_used = FALSE AND expires_at > NOW()',
            [decoded.targetHmac, otpHash, 'LOGIN']
        );

        if (otpRes.rowCount === 0) return res.status(401).json({ error: 'Invalid or expired OTP' });

        // Mark OTP as used
        await db.query('UPDATE otp_verifications SET is_used = TRUE WHERE id = $1', [otpRes.rows[0].id]);

        // Issue JWT Access Token
        const token = jwt.sign(
            { id: decoded.id, username: decoded.username, role: decoded.role, token_version: 1 },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Issue Refresh Token
        const refreshToken = jwt.sign(
            { id: decoded.id, username: decoded.username, role: decoded.role, purpose: 'REFRESH', jti: crypto.randomUUID() },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Audit Log
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action) VALUES ($1, $2, $3)',
            [decoded.id, decoded.actorType, 'LOGIN_SUCCESS']
        );

        res.json({ token, refresh_token: refreshToken, user: { id: decoded.id, username: decoded.username, role: decoded.role } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Verification failed' });
    }
};

exports.register = async (req, res) => {
    const { username, password, full_name, email, mobile, dob } = req.body;
    try {
        const hashedPassword = await hshPw(password);
        const emailHmac = hashHMAC(email);
        const mobileHmac = hashHMAC(mobile);

        // Check for duplicates
        const dupCheck = await db.query('SELECT id FROM customers WHERE email_hmac = $1 OR mobile_hmac = $2', [emailHmac, mobileHmac]);
        if (dupCheck.rowCount > 0) return res.status(400).json({ error: 'Email or mobile already registered' });

        const result = await db.query(
            'INSERT INTO customers (username, password_hash, full_name, email_hmac, mobile_hmac, dob, kyc_status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, username',
            [username, hashedPassword, full_name, emailHmac, mobileHmac, dob, 'PENDING']
        );
        
        // Audit Log
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [result.rows[0].id, 'CUSTOMER', 'CUSTOMER_REGISTERED', result.rows[0].id, 'CUSTOMER', JSON.stringify({ username })]
        );

        res.json({ ...result.rows[0], role: 'CUSTOMER' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Registration failed' });
    }
};

exports.refresh = async (req, res) => {
    const { refresh_token } = req.body; // In real app, use HttpOnly cookie
    try {
        const decoded = jwt.verify(refresh_token, process.env.JWT_SECRET);
        if (decoded.purpose !== 'REFRESH') return res.status(401).json({ error: 'Invalid refresh token' });

        // Check if blacklisted
        const sessionRes = await db.query('SELECT * FROM sessions WHERE jti = $1', [decoded.jti]);
        if (sessionRes.rowCount > 0) return res.status(401).json({ error: 'Session revoked' });

        const newToken = jwt.sign(
            { id: decoded.id, username: decoded.username, role: decoded.role, token_version: 1 },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token: newToken });
    } catch (err) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
};

exports.logout = async (req, res) => {
    const { id: userId, role, jti } = req.user;
    try {
        // Insert JTI into blacklisted sessions (if using DB for blacklist)
        if (jti) {
            await db.query(
                'INSERT INTO sessions (user_id, jti, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'1 hour\')',
                [userId, jti]
            );
        }

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action) VALUES ($1, $2, $3)',
            [userId, role === 'CUSTOMER' ? 'CUSTOMER' : 'USER', 'LOGOUT']
        );

        res.json({ message: "Logout successful" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Logout failed" });
    }
};

exports.changePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const { id: userId, role } = req.user;
    const table = role === 'CUSTOMER' ? 'customers' : 'users';

    try {
        const userRes = await db.query(`SELECT password_hash FROM ${table} WHERE id = $1`, [userId]);
        const isMatch = await cmpPw(currentPassword, userRes.rows[0].password_hash);
        if (!isMatch) return res.status(401).json({ error: "Current password incorrect" });

        const hashedNew = await hshPw(newPassword);
        await db.query(`UPDATE ${table} SET password_hash = $1, token_version = token_version + 1 WHERE id = $2`, [hashedNew, userId]);

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action) VALUES ($1, $2, $3)',
            [userId, role === 'CUSTOMER' ? 'CUSTOMER' : 'USER', 'PASSWORD_CHANGED']
        );

        res.json({ message: "Password changed successfully. All sessions invalidated." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Password change failed" });
    }
};

exports.forgotPassword = async (req, res) => {
    const { mobile } = req.body;
    try {
        const mobileHmac = hashHMAC(mobile);
        const customerRes = await db.query('SELECT id, username FROM customers WHERE mobile_hmac = $1', [mobileHmac]);
        
        // Generic response for security
        const response = { message: "If the mobile number is registered, an OTP has been sent." };
        
        if (customerRes.rowCount > 0) {
            // Hardcoded OTP for development/testing
            const otp = "666666";
            const otpHash = hashHMAC(otp);

            await db.query(
                'INSERT INTO otp_verifications (target_hmac, otp_hash, purpose, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
                [mobileHmac, otpHash, 'PASSWORD_RESET']
            );
            
            console.log(`[DEBUG] Reset OTP for ${customer.username}: ${otp}`);
        }

        res.json(response);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Forgot password request failed" });
    }
};

exports.resetPassword = async (req, res) => {
    const { mobile, otp, newPassword } = req.body;
    try {
        const mobileHmac = hashHMAC(mobile);
        const otpHash = hashHMAC(otp);

        const otpRes = await db.query(
            'SELECT * FROM otp_verifications WHERE target_hmac = $1 AND otp_hash = $2 AND purpose = $3 AND is_used = FALSE AND expires_at > NOW()',
            [mobileHmac, otpHash, 'PASSWORD_RESET']
        );

        if (otpRes.rowCount === 0) return res.status(401).json({ error: "Invalid or expired reset OTP" });

        const customerRes = await db.query('SELECT id FROM customers WHERE mobile_hmac = $1', [mobileHmac]);
        const customerId = customerRes.rows[0].id;

        const hashedNew = await hshPw(newPassword);
        await db.query('UPDATE customers SET password_hash = $1, failed_login_count = 0, is_locked = FALSE WHERE id = $2', [hashedNew, customerId]);
        await db.query('UPDATE otp_verifications SET is_used = TRUE WHERE id = $1', [otpRes.rows[0].id]);

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action) VALUES ($1, $2, $3)',
            [customerId, 'CUSTOMER', 'PASSWORD_RESET']
        );

        res.json({ message: "Password reset successful. You can now login with your new password." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Password reset failed" });
    }
};
