const router = require('express').Router();
const usersController = require('../controllers/users.controller');
const { requireAuth, requireRole } = require('../middlewares/auth.middleware');

router.get('/me', requireAuth, usersController.me);
router.get('/', requireAuth, requireRole('admin'), usersController.getAllUsers);
router.get('/:id', requireAuth, requireRole('admin'), usersController.getUserById);
router.patch('/:id', requireAuth, requireRole('admin'), usersController.updateUserById);
router.delete('/:id', requireAuth, requireRole('admin'), usersController.deleteUserById);
router.patch('/me/password', requireAuth, usersController.changePassword);


module.exports = router;