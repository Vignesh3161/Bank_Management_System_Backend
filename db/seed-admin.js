require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function run() {
    const client = await pool.connect();
    try {
        const hashedPassword = await bcrypt.hash('Admin@123', 10);

        // Delete old default admin if it exists
        await client.query("DELETE FROM users WHERE username = 'admin' OR username = 'Admin'");

        await client.query(`
            INSERT INTO users (username, password_hash, role) 
            VALUES ('Admin', $1, 'SYSTEM_ADMIN')
        `, [hashedPassword]);

        console.log("Initialized First Admin: Admin / Admin@123");
    } catch (e) {
        console.error(e);
    } finally {
        client.release();
        pool.end();
    }
}

run();
