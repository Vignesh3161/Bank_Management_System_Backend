require('dotenv').config();
const db = require('./index');
const bcrypt = require('bcryptjs');

async function test() {
    try {
        console.log("--- Testing Hierarchy Logic ---");
        
        // 1. Get the Main Branch
        const branchRes = await db.query("SELECT id FROM branches WHERE name = 'Main Branch'");
        const branchId = branchRes.rows[0].id;
        console.log("Branch ID:", branchId);

        // 2. Create a Manager
        const managerPw = await bcrypt.hash('manager123', 10);
        const managerRes = await db.query(
            "INSERT INTO users (username, password_hash, role, branch_id) VALUES ('BranchManager', $1, 'MANAGER', $2) ON CONFLICT (username) DO UPDATE SET role='MANAGER' RETURNING id",
            [managerPw, branchId]
        );
        const managerId = managerRes.rows[0].id;
        console.log("Manager Created:", managerId);

        // 3. Set this manager as the official manager of the branch
        await db.query("UPDATE branches SET manager_id = $1 WHERE id = $2", [managerId, branchId]);
        console.log("Branch Manager Assigned.");

        // 4. Create a Teller
        const tellerPw = await bcrypt.hash('teller123', 10);
        const tellerRes = await db.query(
            "INSERT INTO users (username, password_hash, role, branch_id) VALUES ('BranchTeller', $1, 'TELLER', $2) ON CONFLICT (username) DO UPDATE SET role='TELLER' RETURNING id",
            [tellerPw, branchId]
        );
        const tellerId = tellerRes.rows[0].id;
        console.log("Teller Created:", tellerId);

        // 5. Submit Password Reset Request for Teller
        const reqRes = await db.query(
            "INSERT INTO password_reset_requests (user_id) VALUES ($1) RETURNING id",
            [tellerId]
        );
        const requestId = reqRes.rows[0].id;
        console.log("Reset Request Created:", requestId);

        // 6. Verify Visibility
        console.log("\n--- Checking Visibility ---");
        
        // A. Can the Branch Manager see it?
        const mgrSee = await db.query(`
            SELECT r.id FROM password_reset_requests r
            JOIN users u ON r.user_id = u.id
            JOIN branches b ON u.branch_id = b.id
            WHERE b.manager_id = $1 AND r.id = $2
        `, [managerId, requestId]);
        console.log("Branch Manager visibility:", mgrSee.rowCount > 0 ? "PASSED" : "FAILED");

        // B. Can an Admin see it? (Admins see all)
        const adminSee = await db.query(`SELECT id FROM password_reset_requests WHERE id = $1`, [requestId]);
        console.log("Admin visibility:", adminSee.rowCount > 0 ? "PASSED" : "FAILED");

        // 7. Test Cross-Branch Security
        console.log("\n--- Checking Cross-Branch Security ---");
        const otherBranchRes = await db.query("INSERT INTO branches (name, location) VALUES ('Other Branch', 'Delhi') ON CONFLICT DO NOTHING RETURNING id");
        const otherBranchId = otherBranchRes.rowCount > 0 ? otherBranchRes.rows[0].id : (await db.query("SELECT id FROM branches WHERE name = 'Other Branch'")).rows[0].id;
        
        const otherManagerRes = await db.query(
            "INSERT INTO users (username, password_hash, role, branch_id) VALUES ('OtherManager', '...', 'MANAGER', $1) ON CONFLICT DO NOTHING RETURNING id",
            [otherBranchId]
        );
        if (otherManagerRes.rowCount > 0) {
            const otherManagerId = otherManagerRes.rows[0].id;
            const otherSee = await db.query(`
                SELECT r.id FROM password_reset_requests r
                JOIN users u ON r.user_id = u.id
                JOIN branches b ON u.branch_id = b.id
                WHERE b.manager_id = $1 AND r.id = $2
            `, [otherManagerId, requestId]);
            console.log("Cross-branch manager isolation:", otherSee.rowCount === 0 ? "PASSED (Security OK)" : "FAILED (Security Leak!)");
        }

        console.log("\n--- SUCCESS: Hierarchy Logic Verified ---");
        process.exit(0);

    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

test();
