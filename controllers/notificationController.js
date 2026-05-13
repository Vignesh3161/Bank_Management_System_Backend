const db = require('../db');
const { decryptAES } = require('../utils/cryptoUtils');

exports.getMyNotifications = async (req, res) => {
    const { id: userId } = req.user;
    try {
        const result = await db.query('SELECT * FROM notifications WHERE customer_id = $1 ORDER BY created_at DESC', [userId]);
        const list = result.rows.map(n => {
            n.content = decryptAES(n.content_encrypted);
            delete n.content_encrypted;
            return n;
        });
        res.json(list);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch notifications" });
    }
};

exports.updatePreferences = async (req, res) => {
    const { id: userId } = req.user;
    const { sms, email, push } = req.body;
    try {
        const prefs = JSON.stringify({ sms, email, push });
        await db.query('UPDATE customers SET notification_preferences = $1 WHERE id = $2', [prefs, userId]);
        
        await db.query(
            'INSERT INTO audit_log (actor_id, actor_type, action, details) VALUES ($1, $2, $3, $4)',
            [userId, 'CUSTOMER', 'PREFERENCES_UPDATED', prefs]
        );

        res.json({ message: "Preferences updated" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update preferences" });
    }
};
