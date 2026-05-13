const db = require('../db');
const { generateAccountNumber, encryptAES, decryptAES } = require('../utils/cryptoUtils');

exports.openAccount = async (req, res) => {
    const { account_type } = req.body;
    const { id: userId, role } = req.user;

    try {
        // Ownership check: If customer, they can only open for themselves
        // In this simplified system, we assume the JWT id is the customer id if role is CUSTOMER
        const customerId = userId; 

        const customerRes = await db.query('SELECT kyc_status FROM customers WHERE id = $1', [customerId]);
        if (customerRes.rowCount === 0) return res.status(404).json({ error: "Customer not found" });
        if (customerRes.rows[0].kyc_status !== 'VERIFIED') {
            return res.status(403).json({ error: "KYC not verified. Please complete KYC before opening an account." });
        }

        const accountNumber = generateAccountNumber();
        const initialBalance = encryptAES("0.00");

        const result = await db.query(
            'INSERT INTO accounts (customer_id, account_number, account_type, balance_encrypted, status) VALUES ($1, $2, $3, $4, $5) RETURNING id, account_number',
            [customerId, accountNumber, account_type || 'SAVINGS', initialBalance, 'ACTIVE']
        );

        // Audit Log
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, role === 'CUSTOMER' ? 'CUSTOMER' : 'USER', 'ACCOUNT_OPENED', result.rows[0].id, 'ACCOUNT', JSON.stringify({ account_number: accountNumber })]
        );

        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to open account" });
    }
};

exports.getAccountDetails = async (req, res) => {
    const { accountId } = req.params;
    const { id: userId, role } = req.user;

    try {
        const result = await db.query('SELECT * FROM accounts WHERE id = $1', [accountId]);
        if (result.rowCount === 0) return res.status(404).json({ error: "Account not found" });

        const account = result.rows[0];

        // Ownership check for CUSTOMER
        if (role === 'CUSTOMER' && account.customer_id !== userId) {
            return res.status(403).json({ error: "Access Denied" });
        }

        // Decrypt balance in memory
        account.balance = parseFloat(decryptAES(account.balance_encrypted));
        delete account.balance_encrypted;

        // Log access for TELLER+
        if (role !== 'CUSTOMER') {
            await db.query(
                'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
                [userId, 'USER', 'ACCOUNT_FETCHED', accountId, 'ACCOUNT']
            );
        }

        res.json(account);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch account" });
    }
};

exports.getBalance = async (req, res) => {
    const { accountId } = req.params;
    const { id: userId, role } = req.user;

    try {
        const result = await db.query('SELECT customer_id, balance_encrypted FROM accounts WHERE id = $1', [accountId]);
        if (result.rowCount === 0) return res.status(404).json({ error: "Account not found" });

        const account = result.rows[0];
        if (role === 'CUSTOMER' && account.customer_id !== userId) {
            return res.status(403).json({ error: "Access Denied" });
        }

        const balance = parseFloat(decryptAES(account.balance_encrypted));
        res.json({ accountId, balance });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch balance" });
    }
};

exports.getMyAccounts = async (req, res) => {
    const { id: userId } = req.user;
    try {
        const result = await db.query('SELECT * FROM accounts WHERE customer_id = $1', [userId]);
        const accounts = result.rows.map(acc => {
            acc.balance = parseFloat(decryptAES(acc.balance_encrypted));
            delete acc.balance_encrypted;
            return acc;
        });
        res.json(accounts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch accounts" });
    }
};

exports.updateAccountStatus = async (req, res) => {
    const { accountId } = req.params;
    const { status, reason } = req.body;
    const { id: userId } = req.user;

    if (!['ACTIVE', 'FROZEN', 'CLOSED'].includes(status)) {
        return res.status(400).json({ error: "Invalid status" });
    }
    if (!reason) return res.status(400).json({ error: "Reason is mandatory" });

    try {
        await db.query('UPDATE accounts SET status = $1 WHERE id = $2', [status, accountId]);
        
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, 'USER', 'ACCOUNT_STATUS_CHANGED', accountId, 'ACCOUNT', JSON.stringify({ status, reason })]
        );

        res.json({ message: `Account status updated to ${status}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update status" });
    }
};

exports.updateLimits = async (req, res) => {
    const { accountId } = req.params;
    const { limit_type, max_amount } = req.body;
    const { id: userId } = req.user;

    try {
        await db.query(
            'INSERT INTO transaction_limits (account_id, limit_type, max_amount, updated_by) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET max_amount = $3, updated_by = $4',
            [accountId, limit_type, max_amount, userId]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, 'USER', 'LIMIT_CHANGED', accountId, 'ACCOUNT', JSON.stringify({ limit_type, max_amount })]
        );

        res.json({ message: "Limits updated successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update limits" });
    }
};

exports.searchAccounts = async (req, res) => {
    const { query } = req.query;
    const { branch_id } = req.user;

    try {
        const result = await db.query(
            'SELECT a.id, a.account_number, c.full_name, a.status FROM accounts a JOIN customers c ON a.customer_id = c.id WHERE (a.account_number LIKE $1 OR c.full_name ILIKE $1) AND (a.branch_id = $2 OR $2 IS NULL)',
            [`%${query}%`, branch_id]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, details) VALUES ($1, $2, $3, $4)',
            [req.user.id, 'USER', 'ACCOUNT_SEARCH', JSON.stringify({ query })]
        );

        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Search failed" });
    }
};

exports.getStatement = async (req, res) => {
    const { accountId } = req.params;
    const { startDate, endDate } = req.query;
    const { id: userId, role } = req.user;

    try {
        const accCheck = await db.query('SELECT customer_id FROM accounts WHERE id = $1', [accountId]);
        if (accCheck.rowCount === 0) return res.status(404).json({ error: "Account not found" });
        if (role === 'CUSTOMER' && accCheck.rows[0].customer_id !== userId) {
            return res.status(403).json({ error: "Access Denied" });
        }

        const result = await db.query(
            'SELECT * FROM ledger_entries WHERE account_id = $1 AND created_at BETWEEN $2 AND $3 ORDER BY created_at ASC',
            [accountId, startDate || '1970-01-01', endDate || new Date()]
        );

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [userId, role === 'CUSTOMER' ? 'CUSTOMER' : 'USER', 'STATEMENT_DOWNLOADED', accountId, 'ACCOUNT']
        );

        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to generate statement" });
    }
};
