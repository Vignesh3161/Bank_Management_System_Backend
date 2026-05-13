const express = require('express');
const router = express.Router();
const auditController = require('../controllers/auditController');
const { verifyToken, authorize } = require('../middleware/auth');

router.use(verifyToken);

router.get('/logs', authorize(['AUDITOR', 'BRANCH_MANAGER']), auditController.getAuditLogs);
router.get('/logs/:entityId', authorize(['AUDITOR', 'BRANCH_MANAGER']), auditController.getEntityLogs);
router.get('/reports/ctr', authorize(['AUDITOR']), auditController.getCTRReport);
router.get('/reports/str', authorize(['AUDITOR']), auditController.getSTRReport);
router.post('/verify-batch', authorize(['AUDITOR']), auditController.verifyBatchSignatures);
router.get('/gap-check', authorize(['AUDITOR']), auditController.checkGaps);

module.exports = router;
