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

        const accountIds = Object.keys(sums);
        
        // Batch fetch all accounts with FOR UPDATE lock in a single query to minimize RTT
        const accountsRes = await client.query(
            'SELECT id, balance_encrypted FROM accounts WHERE id = ANY($1) FOR UPDATE',
            [accountIds]
        );
        
        const accountBalances = {};
        accountsRes.rows.forEach(row => {
            accountBalances[row.id] = parseFloat(decryptAES(row.balance_encrypted));
        });

        // Apply credits to each account using in-memory balances
        for (const accountId of accountIds) {
            const totalAmount = sums[accountId];
            const currentBalance = accountBalances[accountId];
            if (currentBalance === undefined) continue; // Skip invalid accounts
            
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

        await client.query('COMMIT');

        // Audit Log (Non-blocking background query outside transaction)
        db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, details) VALUES ($1, $2, $3, $4)',
            [userId, 'USER', 'INTEREST_CREDITED', JSON.stringify({ accounts_count: accountIds.length, total_accruals: accrualIds.length })]
        ).catch(err => console.error('Audit log failed:', err));

        res.json({ message: `Successfully credited interest to ${accountIds.length} accounts.` });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: "Failed to credit interest: " + err.message });
    } finally {
        client.release();
    }
};
