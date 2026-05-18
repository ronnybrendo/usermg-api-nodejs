const jwt = require('jsonwebtoken');
const authService = require('../services/auth.service');

module.exports = {

    requireAuth: async (req, res, next) => {

        try {
            const authHeader = req.headers.authorization;

            if (!authHeader || !authHeader.startsWith("Bearer ")) {
                return res.status(401).json({ ok: false, message: 'Token não fornecido'});
            }

            const [type, token] = authHeader.split(" ");

            if (type !== "Bearer" || !token) {
                return res.status(401).json({ ok: false, message: 'Token inválido'});
            }

            const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
            //console.log('decoded: ', decoded);

            const isValidToken = await authService.isValidToken({ sub: decoded.sub, sid: decoded.sid });
            //console.log('isValidToken: ', isValidToken);

            req.user = { id: decoded.sub, role: decoded.role, sid: decoded.sid };

            return next();

        } catch (error) {
            if (error.code === "INVALID_SESSION") {
                return res.status(401).json({ ok: false, message: error.message });
            }
            return res.status(401).json({ ok: false, message: error.message });
        }
    },

    requireRole: (...allowedRoles) => {
        return (req, res, next) => {

            console.log('allowedRoles: ', allowedRoles);
            console.log('user: ', req.user.id);
            console.log('user.role: ', req.user.role);
            console.log('allowedRoles.includes(user.role): ', allowedRoles.includes(req.user.role));

            //const { user } = req.user;

            if (!req.user) {
                return res.status(401).json({ ok: false, message: 'Usuário não autenticado'});
            }

            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({ ok: false, message: 'Usuário não autorizado para acessar este recurso'});
            }

            return next();
        }
    }

}