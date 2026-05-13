const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { verifyToken, authorize } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

router.use(verifyToken);
router.use(auditLog);

router.get('/health', authorize(['SYSTEM_ADMIN']), adminController.getHealth);
router.post('/users/create', authorize(['SYSTEM_ADMIN']), adminController.createUser);
router.patch('/users/:userId/role', authorize(['SYSTEM_ADMIN']), adminController.updateRole);
router.patch('/users/:userId/deactivate', authorize(['SYSTEM_ADMIN']), adminController.deactivateUser);
router.post('/users/:userId/revoke-sessions', authorize(['SYSTEM_ADMIN']), adminController.revokeSessions);
router.get('/users', authorize(['SYSTEM_ADMIN']), adminController.listUsers);

// Branch Management
router.get('/branches', authorize(['SYSTEM_ADMIN']), adminController.listBranches);
router.post('/branches', authorize(['SYSTEM_ADMIN']), adminController.createBranch);
router.put('/branches/:branchId', authorize(['SYSTEM_ADMIN']), adminController.updateBranch);
router.delete('/branches/:branchId', authorize(['SYSTEM_ADMIN']), adminController.deleteBranch);

router.put('/branch/:branchId/config', authorize(['SYSTEM_ADMIN', 'BRANCH_MANAGER']), adminController.updateBranchConfig);

module.exports = router;
