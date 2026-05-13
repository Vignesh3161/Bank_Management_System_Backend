const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const db = require('../db');

dotenv.config();

// Memory Cache for AES Keys to prevent DB bottleneck
let AES_SECRET_KEY = process.env.AES_SECRET_KEY || 'vXf3289v92mvm392nv932nv932nv9322';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;

// Call this on initialization and after rotation
const loadActiveKey = async () => {
    try {
        const result = await db.query('SELECT key_value FROM encryption_keys WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1');
        if (result.rows.length > 0) {
            AES_SECRET_KEY = result.rows[0].key_value;
            console.log("KMS: Active AES Key loaded into memory cache.");
        } else {
            console.log("KMS: No active key found in DB. Falling back to ENV key.");
        }
    } catch (err) {
        console.error("KMS Error: Failed to load AES keys from database.", err);
    }
};

// Expose setter for dynamic rotation updates
const setActiveKey = (newKey) => {
    AES_SECRET_KEY = newKey;
};

const getActiveKey = () => AES_SECRET_KEY;
const HMAC_SECRET = process.env.HMAC_SECRET || 'banking-system-hmac-secret-2024';

// HMAC-SHA256 for deduplication (mobile/email)
const hashHMAC = (text) => {
    return crypto.createHmac('sha256', HMAC_SECRET).update(text).digest('hex');
};

// Cryptographically random 12-digit account number
const generateAccountNumber = () => {
    const bytes = crypto.randomBytes(6);
    const hex = bytes.toString('hex');
    const num = parseInt(hex, 16).toString().slice(0, 12).padStart(12, '0');
    return num;
};

// AES-256-CBC Encryption/Decryption
const encryptAES = (text, customKey = AES_SECRET_KEY) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(customKey), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

const decryptAES = (text, customKey = AES_SECRET_KEY) => {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(customKey), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
};

// RSA Key Pair
let { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const signTransaction = (data) => {
    const sign = crypto.createSign('SHA256');
    sign.update(JSON.stringify(data));
    sign.end();
    return sign.sign(privateKey, 'base64');
};

const verifyTransaction = (data, signature) => {
    const verify = crypto.createVerify('SHA256');
    verify.update(JSON.stringify(data));
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
};

// Bcrypt
const hashPassword = async (password) => {
    return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
};

const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

module.exports = {
    encryptAES,
    decryptAES,
    signTransaction,
    verifyTransaction,
    hashPassword,
    comparePassword,
    publicKey,
    loadActiveKey,
    setActiveKey,
    getActiveKey,
    hashHMAC,
    generateAccountNumber
};
