const express = require('express');
const router = express.Router();
const kycController = require('../controllers/kycController');
const { verifyToken, authorize } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

router.use(verifyToken);
router.use(auditLog);

router.post('/submit', authorize(['CUSTOMER']), kycController.submitKYC);
router.get('/status', authorize(['CUSTOMER']), kycController.getKYCStatus);
router.get('/pending', authorize(['KYC_OFFICER']), kycController.getPendingKYC);
router.get('/:kycId/document', authorize(['KYC_OFFICER']), kycController.getDocumentUrl);
router.post('/:kycId/review', authorize(['KYC_OFFICER']), kycController.reviewKYC);
router.get('/expiring-soon', authorize(['KYC_OFFICER', 'BRANCH_MANAGER']), kycController.getExpiringSoon);

module.exports = router;
