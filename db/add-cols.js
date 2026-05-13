require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function run() {
    const client = await pool.connect();
    try {
        await client.query('ALTER TABLE customers ADD COLUMN failed_attempts INT DEFAULT 0');
        await client.query('ALTER TABLE customers ADD COLUMN is_locked BOOLEAN DEFAULT FALSE');
        await client.query('ALTER TABLE customers ADD COLUMN token_version INT DEFAULT 1');
        console.log("Added login columns to customers table");
    } catch (e) {
        console.error(e);
    } finally {
        client.release();
        pool.end();
    }
}

run();
