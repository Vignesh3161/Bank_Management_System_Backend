require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
pool.query('ALTER TABLE customers ADD COLUMN password_hash TEXT').then(() => { console.log('done'); pool.end() }).catch(console.error);
