const db = require('../db');
const { decryptAES } = require('../utils/cryptoUtils');

exports.getAuditLogs = async (req, res) => {
    const { entity_type, action, actor_id, startDate, endDate, branch_id } = req.query;
    const { id: userId, role, branch_id: userBranchId } = req.user;

    try {
        let query = 'SELECT * FROM audit_log WHERE 1=1';
        let params = [];
        let count = 1;

        if (role === 'BRANCH_MANAGER') {
            query += ` AND branch_id = $${count++}`;
            params.push(userBranchId);
        }

        if (entity_type) { query += ` AND entity_type = $${count++}`; params.push(entity_type); }
        if (action) { query += ` AND action = $${count++}`; params.push(action); }
        if (actor_id) { query += ` AND actor_id = $${count++}`; params.push(actor_id); }
        if (startDate) { query += ` AND created_at >= $${count++}`; params.push(startDate); }
        if (endDate) { query += ` AND created_at <= $${count++}`; params.push(endDate); }

        query += ' ORDER BY log_id DESC LIMIT 100';

        const result = await db.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch audit logs" });
    }
};

exports.getEntityLogs = async (req, res) => {
    const { entityId } = req.params;
    try {
        const result = await db.query('SELECT * FROM audit_log WHERE entity_id = $1 ORDER BY created_at DESC', [entityId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch entity logs" });
    }
};

exports.getCTRReport = async (req, res) => {
    const { startDate, endDate } = req.query;
    try {
        const threshold = 1000000.00; // ₹10 Lakh
        const result = await db.query(
            'SELECT t.*, c.full_name FROM transactions t JOIN accounts a ON t.from_account_id = a.id JOIN customers c ON a.customer_id = c.id WHERE t.amount_numeric >= $1 AND t.transaction_type = \'WITHDRAWAL\' AND t.created_at BETWEEN $2 AND $3',
            [threshold, startDate || '1970-01-01', endDate || new Date()]
        );
        res.json({ report_type: "CTR", transactions: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to generate CTR" });
    }
};

exports.getSTRReport = async (req, res) => {
    const { startDate, endDate } = req.query;
    try {
        const result = await db.query(
            'SELECT f.*, t.amount_numeric, c.full_name FROM fraud_alerts f JOIN transactions t ON f.transaction_id = t.id JOIN accounts a ON t.from_account_id = a.id JOIN customers c ON a.customer_id = c.id WHERE f.status = \'ESCALATED\' AND f.created_at BETWEEN $1 AND $2',
            [startDate || '1970-01-01', endDate || new Date()]
        );
        res.json({ report_type: "STR", alerts: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to generate STR" });
    }
};

exports.verifyBatchSignatures = async (req, res) => {
    const { startDate, endDate } = req.query;
    try {
        const txs = await db.query('SELECT id, rsa_signature FROM transactions WHERE created_at BETWEEN $1 AND $2', [startDate, endDate]);
        let valid = 0, tampered = 0;
        
        // Simulation for now
        txs.rows.forEach(tx => {
            if (tx.rsa_signature) valid++;
            else tampered++;
        });

        res.json({ total: txs.rowCount, valid, tampered });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Batch verification failed" });
    }
};

exports.checkGaps = async (req, res) => {
    try {
        const result = await db.query(`
            SELECT log_id + 1 AS gap_start
            FROM audit_log t1
            WHERE NOT EXISTS (
                SELECT 1 FROM audit_log t2 WHERE t2.log_id = t1.log_id + 1
            ) AND log_id < (SELECT MAX(log_id) FROM audit_log)
        `);
        res.json({ gaps: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Gap check failed" });
    }
};
