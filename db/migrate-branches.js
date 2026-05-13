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

        console.log("Creating branches table...");
        await client.query(`
            CREATE TABLE IF NOT EXISTS branches (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL UNIQUE,
                location TEXT,
                manager_id UUID, -- Foreign key to users added later
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Creating password_reset_requests table...");
        await client.query(`
            CREATE TABLE IF NOT EXISTS password_reset_requests (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL,
                status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'escalated')),
                escalated_to_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Updating users table schema...");
        // 1. Add branch_id
        await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS branch_id UUID REFERENCES branches(id);`);
        
        // 2. Create a default branch
        let defaultBranchId;
        const existingBranch = await client.query(`SELECT id FROM branches WHERE name = 'Main Branch'`);
        if (existingBranch.rowCount > 0) {
            defaultBranchId = existingBranch.rows[0].id;
        } else {
            const branchRes = await client.query(`
                INSERT INTO branches (name, location) 
                VALUES ('Main Branch', 'Mumbai') 
                RETURNING id
            `);
            defaultBranchId = branchRes.rows[0].id;
        }

        // 3. Move data from text 'branch' to 'branch_id' (if old column exists)
        const colsRes = await client.query(`
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'branch'
        `);
        if (colsRes.rowCount > 0) {
            await client.query(`UPDATE users SET branch_id = $1 WHERE branch_id IS NULL`, [defaultBranchId]);
            await client.query(`ALTER TABLE users DROP COLUMN branch;`);
        }

        // 4. Add foreign key from branches.manager_id to users.id
        // Note: We do this after users table is ready
        await client.query(`ALTER TABLE branches ADD CONSTRAINT fk_manager FOREIGN KEY (manager_id) REFERENCES users(id);`);

        await client.query('COMMIT');
        console.log("Migration successful: Branch-based hierarchy implemented.");
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("Migration failed:", e);
    } finally {
        client.release();
        pool.end();
    }
}

run();
