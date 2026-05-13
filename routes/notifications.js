const express = require('express');
const router = express.Router();
const notificationController = require('../controllers/notificationController');
const { verifyToken, authorize } = require('../middleware/auth');

router.use(verifyToken);
router.get('/my', authorize(['CUSTOMER']), notificationController.getMyNotifications);
router.post('/preferences', authorize(['CUSTOMER']), notificationController.updatePreferences);

module.exports = router;
