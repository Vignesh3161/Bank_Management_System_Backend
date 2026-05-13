const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifyToken } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

router.use(auditLog);

router.post('/login', authController.login);
router.post('/verify-otp', authController.verifyOTP);
router.post('/register', authController.register);
router.post('/refresh', authController.refresh);
router.post('/logout', verifyToken, authController.logout);
router.post('/change-password', verifyToken, authController.changePassword);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

module.exports = router;
