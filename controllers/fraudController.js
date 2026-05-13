const db = require('../db');

exports.getAlerts = async (req, res) => {
    const { id: userId, role, branch_id } = req.user;
    try {
        let query = 'SELECT f.*, t.amount_numeric FROM fraud_alerts f JOIN transactions t ON f.transaction_id = t.id WHERE f.status IN (\'OPEN\', \'UNDER_REVIEW\')';
        let params = [];
        
        if (role === 'BRANCH_MANAGER') {
            query += ' AND t.from_account_id IN (SELECT id FROM accounts WHERE branch_id = $1)';
            params.push(branch_id);
        }

        query += ' ORDER BY f.risk_score DESC';
        const result = await db.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch alerts" });
    }
};

exports.reviewAlert = async (req, res) => {
    const { alertId } = req.params;
    const { decision, reason } = req.body;
    const { id: userId } = req.user;

    if (!['DISMISSED', 'ESCALATED'].includes(decision)) return res.status(400).json({ error: "Invalid decision" });
    if (!reason) return res.status(400).json({ error: "Reason is mandatory" });

    try {
        await db.query(
            'UPDATE fraud_alerts SET status = $1, resolution_note = $2, reviewed_by = $3 WHERE id = $4',
            [decision, reason, userId, alertId]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, 'USER', 'ALERT_REVIEWED', alertId, 'FRAUD_ALERT', JSON.stringify({ decision, reason })]
        );

        res.json({ message: `Alert ${decision}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Review failed" });
    }
};

exports.blockAccount = async (req, res) => {
    const { alertId } = req.params;
    const { id: userId } = req.user;
    try {
        const alertRes = await db.query('SELECT transaction_id FROM fraud_alerts WHERE id = $1', [alertId]);
        const txId = alertRes.rows[0].transaction_id;
        const txRes = await db.query('SELECT from_account_id FROM transactions WHERE id = $1', [txId]);
        const accountId = txRes.rows[0].from_account_id;

        await db.query('UPDATE accounts SET status = \'FROZEN\' WHERE id = $1', [accountId]);
        await db.query('UPDATE fraud_alerts SET status = \'BLOCKED\' WHERE id = $1', [alertId]);

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [userId, 'USER', 'EMERGENCY_ACCOUNT_FREEZE', accountId, 'ACCOUNT']
        );

        res.json({ message: "Account frozen and alert marked as BLOCKED" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Block action failed" });
    }
};
