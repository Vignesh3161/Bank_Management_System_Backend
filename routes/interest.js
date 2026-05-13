const express = require('express');
const router = express.Router();
const interestController = require('../controllers/interestController');
const { verifyToken, authorize } = require('../middleware/auth');

router.use(verifyToken);
router.get('/:accountId/accruals', authorize(['CUSTOMER', 'BRANCH_MANAGER']), interestController.getAccruals);
router.post('/credit-monthly', authorize(['SYSTEM_ADMIN']), interestController.creditMonthlyInterest);

module.exports = router;
