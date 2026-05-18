const authService = require('../services/auth.service');

module.exports = {

    register: async (req, res) => {
        try {
            const { name, email, password } = req.body;

            const user = await authService.register({name, email, password});

            return res.status(201).json({ ok: true, message: 'Usuário registrado com sucesso', user });
        } catch (error) {
            if (error.code === "EMAIL_IN_USE") return res.status(409).json({ ok: false, message: 'Email já em uso'});
            if (error.code === "MISSING_FIELDS") return res.status(400).json({ ok: false, message: 'Nome, email e senha são obrigatórios'});
            if (error.code === "INVALID_FIELD") return res.status(400).json({ ok: false, message: 'Senha deve ter pelo menos 6 caracteres'});
            return res.status(500).json({ ok: false, message: 'Erro ao registrar usuário', error: error.message });
        }
    },
    
    login: async (req, res) => {
        try {
            const { email, password } = req.body;

            const data = await authService.login({email, password});

            return res.status(200).json({ ok: true, message: 'Login realizado com sucesso', data });
        } catch (error) {
            if (error.code === "INVALID_USER") return res.status(401).json({ ok: false, message: 'Usuário ou senha incorretos'});
            if (error.code === "MISSING_FIELDS") return res.status(400).json({ ok: false, message: 'Email e senha são obrigatórios'});
            return res.status(500).json({ ok: false, message: 'Erro ao realizar login', error: error.message });
        }
    },

    logout: async (req, res) => {
        try {
            const { refreshToken } = req.body;
            await authService.logout({refreshToken});

            return res.status(204).send();
        } catch (error) {
            if (error.code === "MISSING_FIELDS") {
                return res.status(400).json({ ok: false, message: 'Token é obrigatório'});
            }
            if (error.code === "INVALID_SESSION") {
                return res.status(401).json({ ok: false, message: 'Sessão inválida'});
            }
            return res.status(500).json({ ok: false, message: 'Erro ao realizar logout', error: error.message });
        }
    },

    logoutAll: async (req, res) => {
        try {
            //const { refreshToken } = req.body;
            const userId = req.user.id;
            const {result} = await authService.logoutAll(userId);

            return res.status(200).json({ ok: true, message: 'Logout de todas as sessões realizado com sucesso', result });
        } catch (error) {
            return res.status(500).json({ ok: false, message: 'Erro ao buscar todas as sessões', error: error.message });
        }
    },

    refresh: async (req, res) => {
        try {
            const { refreshToken } = req.body;
            const data = await authService.refresh({refreshToken});
            return res.status(200).json({ ok: true, message: 'Token atualizado com sucesso', data });
        } catch (error) {
            if (error.code === "MISSING_FIELDS") {
                return res.status(400).json({ ok: false, message: 'Token é obrigatório'});
            }
            if (error.code === 'INVALID_REFRESH_TOKEN') {
                return res.status(401).json({ ok: false, message: 'Refresh token inválido ou expirado' });
            }
            if (error.code === "INVALID_USER") {
                return res.status(401).json({ ok: false, message: 'Usuário não encontrado'});
            }
            if (error.code === "INVALID_SESSION") {
                return res.status(401).json({ ok: false, message: 'Sessão inválida'});
            }
            return res.status(500).json({ ok: false, message: 'Erro ao realizar refresh', error: error.message });
        }
    }
}
