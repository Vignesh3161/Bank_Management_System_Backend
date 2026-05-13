const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { auditLog } = require('./middleware/audit');
const { rateLimiter, replayProtection } = require('./middleware/security');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: 'http://localhost:5173', // Allow your Vite frontend
    credentials: true,               // Allow cookies/tokens to be sent
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-request-id', 'x-hmac-signature']
}));
app.use(express.json());
app.use(rateLimiter); // Protect against brute force/DOS
app.use(replayProtection); // Protect against request capturing
app.use(auditLog); // Immutable trail for all API actions

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/accounts', require('./routes/accounts'));
app.use('/api/transactions', require('./routes/transactions'));
app.use('/api/kyc', require('./routes/kyc'));
app.use('/api/audit', require('./routes/audit'));
app.use('/api/fraud', require('./routes/fraud'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/interest', require('./routes/interest'));

// Basic Health Check (Public)
app.get('/health', (req, res) => {
    res.json({ status: 'UP', timestamp: new Date() });
});

const { loadActiveKey } = require('./utils/cryptoUtils');

app.listen(PORT, async () => {
    await loadActiveKey(); // Fetch highest security Master Key on boot
    console.log(`Core Banking Server running on port ${PORT}`);
});
