const db = require('../db');
const { decryptAES, encryptAES } = require('../utils/cryptoUtils');

exports.getAccruals = async (req, res) => {
    const { accountId } = req.params;
    const { id: userId, role } = req.user;
    try {
        const accCheck = await db.query('SELECT customer_id FROM accounts WHERE id = $1', [accountId]);
        if (role === 'CUSTOMER' && accCheck.rows[0]?.customer_id !== userId) return res.status(403).json({ error: "Access Denied" });

        const result = await db.query('SELECT * FROM interest_accruals WHERE account_id = $1 ORDER BY accrual_date DESC', [accountId]);
        const list = result.rows.map(a => {
            a.principal_balance = parseFloat(decryptAES(a.principal_balance_encrypted));
            a.interest_amount = parseFloat(decryptAES(a.interest_amount_encrypted));
            delete a.principal_balance_encrypted;
            delete a.interest_amount_encrypted;
            return a;
        });
        res.json(list);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch accruals" });
    }
};

exports.creditMonthlyInterest = async (req, res) => {
    const { id: userId } = req.user;
    const client = await db.getClient();
    try {
        await client.query('BEGIN');
        
        // Fetch all uncredited accruals
        const accrualsRes = await client.query('SELECT * FROM interest_accruals WHERE is_credited = FALSE');
        
        if (accrualsRes.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.json({ message: "No interest accruals to credit." });
        }

        // Group by account and sum decrypted amounts
        const sums = {};
        const accrualIds = [];
        
        accrualsRes.rows.forEach(a => {
            const amount = parseFloat(decryptAES(a.interest_amount_encrypted));
            sums[a.account_id] = (sums[a.account_id] || 0) + amount;
            accrualIds.push(a.id);
        });

        // Apply credits to each account
        for (const [accountId, totalAmount] of Object.entries(sums)) {
            const accRes = await client.query('SELECT balance_encrypted FROM accounts WHERE id = $1 FOR UPDATE', [accountId]);
            const currentBalance = parseFloat(decryptAES(accRes.rows[0].balance_encrypted));
            const newBalance = currentBalance + totalAmount;

            // Create INTEREST transaction
            const txRes = await client.query(
                'INSERT INTO transactions (to_account_id, amount_encrypted, amount_numeric, transaction_type, status, initiated_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [accountId, encryptAES(totalAmount.toString()), totalAmount, 'INTEREST', 'COMPLETED', userId]
            );

            // Update balance
            await client.query('UPDATE accounts SET balance_encrypted = $1 WHERE id = $2', [encryptAES(newBalance.toString()), accountId]);
            
            // Add ledger entry
            await client.query(
                'INSERT INTO ledger_entries (transaction_id, account_id, credit, balance_after) VALUES ($1, $2, $3, $4)',
                [txRes.rows[0].id, accountId, totalAmount, newBalance]
            );
        }

        // Mark all processed accruals as credited
        await client.query('UPDATE interest_accruals SET is_credited = TRUE WHERE id = ANY($1)', [accrualIds]);

        await client.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, details) VALUES ($1, $2, $3, $4)',
            [userId, 'USER', 'INTEREST_CREDITED', JSON.stringify({ accounts_count: Object.keys(sums).length, total_accruals: accrualIds.length })]
        );

        await client.query('COMMIT');
        res.json({ message: `Successfully credited interest to ${Object.keys(sums).length} accounts.` });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Failed to credit interest: " + err.message });
    } finally {
        client.release();
    }
};
