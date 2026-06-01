require('dotenv').config();
const db = require('./index');

const indexes = [
    { name: 'idx_customers_mobile_hmac', sql: 'CREATE INDEX IF NOT EXISTS idx_customers_mobile_hmac ON customers(mobile_hmac)' },
    { name: 'idx_customers_email_hmac', sql: 'CREATE INDEX IF NOT EXISTS idx_customers_email_hmac ON customers(email_hmac)' },
    { name: 'idx_customers_username', sql: 'CREATE INDEX IF NOT EXISTS idx_customers_username ON customers(username)' },
    { name: 'idx_users_username', sql: 'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)' },
    { name: 'idx_accounts_customer_id', sql: 'CREATE INDEX IF NOT EXISTS idx_accounts_customer_id ON accounts(customer_id)' },
    { name: 'idx_accounts_account_number', sql: 'CREATE INDEX IF NOT EXISTS idx_accounts_account_number ON accounts(account_number)' },
    { name: 'idx_transactions_from_account', sql: 'CREATE INDEX IF NOT EXISTS idx_transactions_from_account ON transactions(from_account_id)' },
    { name: 'idx_transactions_to_account', sql: 'CREATE INDEX IF NOT EXISTS idx_transactions_to_account ON transactions(to_account_id)' },
    { name: 'idx_ledger_entries_transaction_id', sql: 'CREATE INDEX IF NOT EXISTS idx_ledger_entries_transaction_id ON ledger_entries(transaction_id)' },
    { name: 'idx_ledger_entries_account_id', sql: 'CREATE INDEX IF NOT EXISTS idx_ledger_entries_account_id ON ledger_entries(account_id)' },
    { name: 'idx_otp_verifications_target_hash', sql: 'CREATE INDEX IF NOT EXISTS idx_otp_verifications_target_hash ON otp_verifications(target_hmac, otp_hash)' },
    { name: 'idx_sessions_jti', sql: 'CREATE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(jti)' },
    { name: 'idx_audit_log_actor_id', sql: 'CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON audit_log(actor_id)' }
];

async function run() {
    console.log("Starting index creation...");
    let successCount = 0;
    for (const idx of indexes) {
        try {
            console.log(`Creating index: ${idx.name}...`);
            await db.query(idx.sql);
            console.log(`Successfully created index: ${idx.name}`);
            successCount++;
        } catch (err) {
            console.error(`Failed to create index ${idx.name}:`, err.message);
        }
    }
    console.log(`Index creation completed: ${successCount}/${indexes.length} created successfully.`);
    process.exit(0);
}

run();
