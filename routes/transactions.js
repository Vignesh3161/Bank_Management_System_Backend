const express = require('express');
const router = express.Router();
const transactionController = require('../controllers/transactionController');
const { verifyToken, authorize } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

router.use(verifyToken);
router.use(auditLog);

router.post('/transfer', authorize(['CUSTOMER', 'TELLER']), transactionController.transfer);
router.post('/deposit', authorize(['TELLER']), transactionController.deposit);
router.post('/withdraw', authorize(['TELLER']), transactionController.withdraw);
router.post('/:txnId/approve', authorize(['BRANCH_MANAGER']), transactionController.approveTransaction);
router.post('/:txnId/reject', authorize(['BRANCH_MANAGER']), transactionController.rejectTransaction);
router.post('/:txnId/reverse', authorize(['BRANCH_MANAGER']), transactionController.reverseTransaction);
router.get('/:accountId/history', authorize(['CUSTOMER', 'TELLER', 'BRANCH_MANAGER', 'AUDITOR']), transactionController.getHistory);
router.get('/pending-approval', authorize(['BRANCH_MANAGER']), transactionController.getPendingApprovals);
router.get('/:txnId', authorize(['CUSTOMER', 'TELLER', 'BRANCH_MANAGER', 'AUDITOR']), transactionController.getTransactionDetails);
router.get('/:txnId/verify-signature', authorize(['AUDITOR']), transactionController.verifySignature);

module.exports = router;
