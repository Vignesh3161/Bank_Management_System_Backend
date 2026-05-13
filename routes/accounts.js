const express = require('express');
const router = express.Router();
const accountController = require('../controllers/accountController');
const { verifyToken, authorize } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

router.use(verifyToken);
router.use(auditLog);

router.post('/open', authorize(['CUSTOMER', 'TELLER']), accountController.openAccount);
router.get('/my', authorize(['CUSTOMER']), accountController.getMyAccounts);
router.get('/search', authorize(['TELLER', 'BRANCH_MANAGER']), accountController.searchAccounts);
router.get('/:accountId', authorize(['CUSTOMER', 'TELLER', 'BRANCH_MANAGER', 'AUDITOR']), accountController.getAccountDetails);
router.get('/:accountId/balance', authorize(['CUSTOMER', 'TELLER', 'BRANCH_MANAGER']), accountController.getBalance);
router.patch('/:accountId/status', authorize(['BRANCH_MANAGER']), accountController.updateAccountStatus);
router.put('/:accountId/limits', authorize(['BRANCH_MANAGER']), accountController.updateLimits);
router.get('/:accountId/statement', authorize(['CUSTOMER', 'TELLER', 'BRANCH_MANAGER']), accountController.getStatement);

module.exports = router;
