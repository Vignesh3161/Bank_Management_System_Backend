const express = require('express');
const router = express.Router();
const fraudController = require('../controllers/fraudController');
const { verifyToken, authorize } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

router.use(verifyToken);
router.use(auditLog);

router.get('/alerts', authorize(['BRANCH_MANAGER', 'AUDITOR']), fraudController.getAlerts);
router.post('/alerts/:alertId/review', authorize(['BRANCH_MANAGER', 'AUDITOR']), fraudController.reviewAlert);
router.post('/alerts/:alertId/block-account', authorize(['BRANCH_MANAGER']), fraudController.blockAccount);

module.exports = router;
