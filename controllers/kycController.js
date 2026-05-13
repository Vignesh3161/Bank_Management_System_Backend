const db = require('../db');
const { encryptAES, decryptAES } = require('../utils/cryptoUtils');

exports.submitKYC = async (req, res) => {
    const { document_type, document_content } = req.body; // In real app, use file upload
    const { id: userId } = req.user;

    try {
        const encryptedPath = encryptAES(`uploads/kyc_${userId}_${Date.now()}.pdf`);
        
        const result = await db.query(
            'INSERT INTO kyc_verifications (customer_id, document_type, document_path_encrypted, face_match_score, decision) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [userId, document_type, encryptedPath, 95.0, 'PENDING']
        );

        await db.query('UPDATE customers SET kyc_status = \'SUBMITTED\' WHERE id = $1', [userId]);

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [userId, 'CUSTOMER', 'KYC_SUBMITTED', result.rows[0].id, 'KYC']
        );

        res.json({ message: "KYC submitted successfully", kycId: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "KYC submission failed" });
    }
};

exports.getKYCStatus = async (req, res) => {
    const { id: userId } = req.user;
    try {
        const result = await db.query('SELECT kyc_status FROM customers WHERE id = $1', [userId]);
        const kycRes = await db.query('SELECT decision, reject_reason, expires_at FROM kyc_verifications WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 1', [userId]);
        
        res.json({
            status: result.rows[0].kyc_status,
            details: kycRes.rows[0] || null
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch KYC status" });
    }
};

exports.getPendingKYC = async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM kyc_verifications WHERE decision = \'PENDING\' ORDER BY created_at ASC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch pending KYC" });
    }
};

exports.getDocumentUrl = async (req, res) => {
    const { kycId } = req.params;
    const { id: userId } = req.user;
    try {
        const result = await db.query('SELECT document_path_encrypted FROM kyc_verifications WHERE id = $1', [kycId]);
        if (result.rowCount === 0) return res.status(404).json({ error: "KYC not found" });

        const path = decryptAES(result.rows[0].document_path_encrypted);
        
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type) VALUES ($1, $2, $3, $4, $5)',
            [userId, 'USER', 'DOCUMENT_ACCESSED', kycId, 'KYC']
        );

        res.json({ url: `https://bank-storage.internal/${path}?token=signed_temp_token` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch document" });
    }
};

exports.reviewKYC = async (req, res) => {
    const { kycId } = req.params;
    const { decision, reason } = req.body;
    const { id: userId } = req.user;

    try {
        await db.query(
            'UPDATE kyc_verifications SET decision = $1, reject_reason = $2, reviewed_by = $3 WHERE id = $4',
            [decision, reason, userId, kycId]
        );

        const kyc = await db.query('SELECT customer_id FROM kyc_verifications WHERE id = $1', [kycId]);
        const status = decision === 'APPROVE' ? 'VERIFIED' : 'REJECTED';
        await db.query('UPDATE customers SET kyc_status = $1 WHERE id = $2', [status, kyc.rows[0].customer_id]);

        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, entity_id, entity_type, details) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, 'USER', 'KYC_REVIEWED', kycId, 'KYC', JSON.stringify({ decision, reason })]
        );

        res.json({ message: `KYC ${decision}D` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Review failed" });
    }
};

exports.getExpiringSoon = async (req, res) => {
    try {
        const result = await db.query('SELECT c.full_name, k.expires_at FROM kyc_verifications k JOIN customers c ON k.customer_id = c.id WHERE k.expires_at < NOW() + INTERVAL \'30 days\'');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch expiring KYC" });
    }
};
