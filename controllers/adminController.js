const db = require('../db');
const crypto = require('crypto');
const { hashPassword: hshPw, decryptAES, encryptAES } = require('../utils/cryptoUtils');

exports.createUser = async (req, res) => {
    const { username, password, role, branch_id } = req.body;
    const { id: adminId } = req.user;
    try {
        const hashedPassword = await hshPw(password || crypto.randomBytes(8).toString('hex'));
        const result = await db.query(
            'INSERT INTO users (username, password_hash, role, branch_id) VALUES ($1, $2, $3, $4) RETURNING id, username, role',
            [username, hashedPassword, role, branch_id]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [adminId, 'USER', 'USER_CREATED', result.rows[0].id, 'USER']
        );

        res.json({ message: "User created successfully", user: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to create user" });
    }
};

exports.updateRole = async (req, res) => {
    const { userId } = req.params;
    const { role } = req.body;
    const { id: adminId } = req.user;
    try {
        await db.query('UPDATE users SET role = $1, token_version = token_version + 1 WHERE id = $2', [role, userId]);
        
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [adminId, 'USER', 'ROLE_CHANGED', userId, 'USER', JSON.stringify({ role })]
        );

        res.json({ message: "Role updated and sessions revoked" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update role" });
    }
};

exports.deactivateUser = async (req, res) => {
    const { userId } = req.params;
    const { id: adminId } = req.user;
    try {
        await db.query('UPDATE users SET is_active = false, token_version = token_version + 1 WHERE id = $1', [userId]);
        
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [adminId, 'USER', 'USER_DEACTIVATED', userId, 'USER']
        );

        res.json({ message: "User deactivated" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Deactivation failed" });
    }
};

exports.revokeSessions = async (req, res) => {
    const { userId } = req.params;
    const { id: adminId } = req.user;
    try {
        await db.query('UPDATE users SET token_version = token_version + 1 WHERE id = $1', [userId]);
        
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [adminId, 'USER', 'SESSIONS_REVOKED', userId, 'USER']
        );

        res.json({ message: "All sessions revoked for user" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Revocation failed" });
    }
};

exports.listUsers = async (req, res) => {
    try {
        const result = await db.query('SELECT id, username, role, branch_id, is_active, last_login_at FROM users');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch users" });
    }
};

exports.updateBranchConfig = async (req, res) => {
    const { branchId } = req.params;
    const { daily_limit, upi_limit, teller_limit } = req.body;
    const { id: adminId } = req.user;
    try {
        await db.query(
            'UPDATE branch_config SET daily_limit = $1, upi_limit = $2, teller_limit = $3 WHERE id = $4',
            [daily_limit, upi_limit, teller_limit, branchId]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [adminId, 'USER', 'BRANCH_CONFIG_UPDATED', branchId, 'BRANCH', JSON.stringify({ daily_limit, upi_limit, teller_limit })]
        );

        res.json({ message: "Branch config updated" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update config" });
    }
};

exports.getHealth = async (req, res) => {
    try {
        const dbStatus = await db.query('SELECT 1');
        res.json({
            status: 'UP',
            database: dbStatus.rowCount > 0 ? 'CONNECTED' : 'DISCONNECTED',
            timestamp: new Date(),
            uptime: process.uptime()
        });
    } catch (err) {
        res.status(500).json({ status: 'DOWN', error: err.message });
    }
};

// Branch Management
exports.listBranches = async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM branch_config ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch branches" });
    }
};

exports.createBranch = async (req, res) => {
    const { branch_name, daily_limit, upi_limit, teller_limit } = req.body;
    const { id: adminId } = req.user;
    try {
        const result = await db.query(
            'INSERT INTO branch_config (branch_name, daily_limit, upi_limit, teller_limit) VALUES ($1, $2, $3, $4) RETURNING *',
            [branch_name, daily_limit || 100000, upi_limit || 50000, teller_limit || 500000]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [adminId, 'USER', 'BRANCH_CREATED', result.rows[0].id, 'BRANCH', JSON.stringify(result.rows[0])]
        );

        res.status(201).json({ message: "Branch created successfully", branch: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to create branch. Check if name is unique." });
    }
};

exports.updateBranch = async (req, res) => {
    const { branchId } = req.params;
    const { branch_name, daily_limit, upi_limit, teller_limit, is_active } = req.body;
    const { id: adminId } = req.user;
    try {
        const result = await db.query(
            'UPDATE branch_config SET branch_name = $1, daily_limit = $2, upi_limit = $3, teller_limit = $4, is_active = $5 WHERE id = $6 RETURNING *',
            [branch_name, daily_limit, upi_limit, teller_limit, is_active, branchId]
        );

        if (result.rowCount === 0) return res.status(404).json({ error: "Branch not found" });

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [adminId, 'USER', 'BRANCH_UPDATED', branchId, 'BRANCH', JSON.stringify(req.body)]
        );

        res.json({ message: "Branch updated successfully", branch: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Update failed" });
    }
};

exports.deleteBranch = async (req, res) => {
    const { branchId } = req.params;
    const { id: adminId } = req.user;
    try {
        // Soft delete: Deactivate the branch
        await db.query('UPDATE branch_config SET is_active = false WHERE id = $1', [branchId]);

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [adminId, 'USER', 'BRANCH_DEACTIVATED', branchId, 'BRANCH']
        );

        res.json({ message: "Branch deactivated" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Deactivation failed" });
    }
};
