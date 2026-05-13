require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function run() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        console.log("Dropping old tables...");
        await client.query(`
            DROP TABLE IF EXISTS audit_log CASCADE;
            DROP TABLE IF EXISTS audit_logs CASCADE;
            DROP TABLE IF EXISTS fraud_alerts CASCADE;
            DROP TABLE IF EXISTS interest_accruals CASCADE;
            DROP TABLE IF EXISTS kyc_verifications CASCADE;
            DROP TABLE IF EXISTS notifications CASCADE;
            DROP TABLE IF EXISTS otp_verifications CASCADE;
            DROP TABLE IF EXISTS sessions CASCADE;
            DROP TABLE IF EXISTS transaction_limits CASCADE;
            DROP TABLE IF EXISTS branch_config CASCADE;
            DROP TABLE IF EXISTS ledger_entries CASCADE;
            DROP TABLE IF EXISTS transactions CASCADE;
            DROP TABLE IF EXISTS accounts CASCADE;
            DROP TABLE IF EXISTS users CASCADE;
            DROP TABLE IF EXISTS customers CASCADE;
            DROP TABLE IF EXISTS encryption_keys CASCADE;
        `);
        
        console.log("Creating full 14-table architecture...");
        await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);
        
        // 1. encryption_keys
        await client.query(`
            CREATE TABLE encryption_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                key_value TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        const currentKey = process.env.AES_SECRET_KEY || 'vXf3289v92mvm392nv932nv932nv9322';
        await client.query(`INSERT INTO encryption_keys (key_value, is_active) VALUES ($1, TRUE)`, [currentKey]);
        
        // 2. customers (Account Holders)
        await client.query(`
            CREATE TABLE customers (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                full_name TEXT NOT NULL,
                email TEXT UNIQUE,
                phone TEXT UNIQUE,
                pan_encrypted TEXT,
                aadhaar_encrypted TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. users (Bank Staff)
        await client.query(`
            CREATE TABLE users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT CHECK (role IN ('TELLER', 'MANAGER', 'AUDITOR', 'ADMIN', 'SYSTEM_ADMIN')),
                failed_attempts INT DEFAULT 0,
                is_locked BOOLEAN DEFAULT FALSE,
                totp_secret TEXT,
                is_totp_enabled BOOLEAN DEFAULT FALSE,
                token_version INTEGER DEFAULT 1,
                branch TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // Insert a default SYSTEM_ADMIN
        const bcrypt = require('bcryptjs');
        const defaultAdminHash = await bcrypt.hash('admin123', 10);
        await client.query(`
            INSERT INTO users (username, password_hash, role) 
            VALUES ('admin', $1, 'SYSTEM_ADMIN')
        `, [defaultAdminHash]);
        
        // 4. accounts
        await client.query(`
            CREATE TABLE accounts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
                account_number_encrypted TEXT NOT NULL,
                account_type TEXT,
                balance NUMERIC(15,2) DEFAULT 0.00,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 5. transactions
        await client.query(`
            CREATE TABLE transactions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                from_account_id UUID REFERENCES accounts(id),
                to_account_id UUID REFERENCES accounts(id),
                amount NUMERIC(15,2) NOT NULL,
                transaction_type TEXT,
                status TEXT DEFAULT 'pending',
                rsa_signature TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 6. ledger_entries
        await client.query(`
            CREATE TABLE ledger_entries (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                transaction_id UUID REFERENCES transactions(id),
                account_id UUID REFERENCES accounts(id),
                entry_type TEXT CHECK (entry_type IN ('debit', 'credit')),
                amount NUMERIC(15,2) NOT NULL,
                balance_after NUMERIC(15,2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 7. sessions (JWT Blacklist)
        await client.query(`
            CREATE TABLE sessions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID,
                token TEXT NOT NULL,
                is_revoked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 8. otp_verifications
        await client.query(`
            CREATE TABLE otp_verifications (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID,
                otp_code TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE
            );
        `);

        // 9. fraud_alerts
        await client.query(`
            CREATE TABLE fraud_alerts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                account_id UUID REFERENCES accounts(id),
                reason TEXT NOT NULL,
                severity TEXT,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 10. audit_log (Using BIGSERIAL for sequential integrity)
        await client.query(`
            CREATE TABLE audit_log (
                log_id BIGSERIAL PRIMARY KEY,
                entity_type TEXT,
                entity_id UUID,
                action TEXT NOT NULL,
                performed_by UUID,
                details JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 11. kyc_verifications
        await client.query(`
            CREATE TABLE kyc_verifications (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                customer_id UUID REFERENCES customers(id),
                document_type TEXT,
                status TEXT DEFAULT 'pending',
                verified_at TIMESTAMP
            );
        `);

        // 12. branch_config
        await client.query(`
            CREATE TABLE branch_config (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                branch_name TEXT NOT NULL,
                config_key TEXT NOT NULL,
                config_value TEXT NOT NULL
            );
        `);

        // 13. transaction_limits
        await client.query(`
            CREATE TABLE transaction_limits (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                account_type TEXT NOT NULL,
                daily_limit NUMERIC(15,2) NOT NULL,
                per_transaction_limit NUMERIC(15,2) NOT NULL
            );
        `);

        // 14. notifications
        await client.query(`
            CREATE TABLE notifications (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'unread',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 15. interest_accruals
        await client.query(`
            CREATE TABLE interest_accruals (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                account_id UUID REFERENCES accounts(id),
                interest_amount NUMERIC(15,2) NOT NULL,
                accrual_date DATE NOT NULL
            );
        `);

        await client.query('COMMIT');
        console.log("Database reset and 14-table architecture created successfully.");
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("Migration failed:", e);
    } finally {
        client.release();
        pool.end();
    }
}

run();
