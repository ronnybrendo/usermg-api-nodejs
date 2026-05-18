const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/auth.controller');
const { requireAuth, requireRole } = require('../middlewares/auth.middleware');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
    max: 10,
    message: { ok: false, message: "Muitas tentativas. Tente novamente mais tarde." },
});
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
    max: 30, // 30 tentativas
    message: { ok: false, message: "Muitas tentativas de refresh. Tente novamente mais tarde." },
});

router.post('/register', authController.register);
router.post('/login', loginLimiter, authController.login);
router.post('/logout', authController.logout);
router.post('/logout-all', requireAuth, authController.logoutAll);
router.post('/refresh', refreshLimiter, authController.refresh);

module.exports = router;