require('dotenv').config();
const db = require('./index');

async function run() {
    try {
        console.log("Fetching database indexes...");
        const indexesRes = await db.query(`
            SELECT
                tablename,
                indexname,
                indexdef
            FROM
                pg_indexes
            WHERE
                schemaname = 'public'
            ORDER BY
                tablename, indexname;
        `);
        console.log(`Found ${indexesRes.rowCount} indexes:`);
        indexesRes.rows.forEach(idx => {
            console.log(`- Table: ${idx.tablename} | Index: ${idx.indexname}`);
            console.log(`  SQL: ${idx.indexdef}`);
        });

    } catch (err) {
        console.error("Query failed:", err);
    }
}

run();
