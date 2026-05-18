const usersService = require('../services/users.service');

module.exports = {
    
    me: async (req, res) => {

        try {
            const userId = req.user.id;
            const user = await usersService.getUserById(userId);

            return res.status(200).json({ ok: true, message: 'Usuário encontrado com sucesso', user });
        } catch (error) {
            return res.status(404).json({ ok: false, message: 'Erro ao buscar usuário', error: error.message });
        }
    },

    getAllUsers: async (req, res) => {
        try {
            const users = await usersService.getAllUsers();
            return res.status(200).json({ ok: true, message: 'Usuários encontrados com sucesso', users });
        } catch (error) {
            return res.status(500).json({ ok: false, message: 'Erro ao buscar usuários', error: error.message });
        }
    },

    getUserById: async (req, res) => {
        try {
            const userId = req.params.id;
            if (!userId || isNaN(userId)) {
                return res.status(400).json({ ok: false, message: 'ID do usuário é obrigatório e deve ser um número' });
            }
            const user = await usersService.getUserById(userId);
            return res.status(200).json({ ok: true, message: 'Usuário encontrado com sucesso', user });
        } catch (error) {
            if (error.code === "USER_NOT_FOUND") return res.status(404).json({ ok: false, message: 'Usuário não encontrado' });
            return res.status(500).json({ ok: false, message: 'Erro ao buscar usuário', error: error.message });
        }
    },

    updateUserById: async (req, res) => {
        try {
            const userId = req.params.id;
            const { name, email, role } = req.body;
            const user = await usersService.updateUser(userId, { name, email, role });
            return res.status(200).json({ ok: true, message: 'Usuário atualizado com sucesso', user });
        } catch (error) {
            if (error.code === "EMAIL_IN_USE") return res.status(409).json({ ok: false, message: error.message });
            if (error.code === "USER_NOT_FOUND") return res.status(404).json({ ok: false, message: error.message });
            return res.status(500).json({ ok: false, message: 'Erro ao atualizar usuário', error: error.message });
        }
    },

    deleteUserById: async (req, res) => {
        try {
            const userId = req.params.id;
            await usersService.deleteUser(userId);
            return res.status(200).json({ ok: true, message: 'Usuário deletado com sucesso' });
        } catch (error) {
            if (error.code === "USER_NOT_FOUND") return res.status(404).json({ ok: false, message: error.message });
            return res.status(500).json({ ok: false, message: 'Erro ao deletar usuário', error: error.message });
        }
    },

    changePassword: async (req, res) => {
        try {
            const userId = req.user.id;
            const { currentPassword, newPassword } = req.body;
            await usersService.changePassword(userId, { currentPassword, newPassword });
            return res.status(200).json({ ok: true, message: 'Senha atualizada com sucesso' });
        } catch (error) {
            if (error.code === "INVALID_PASSWORD") return res.status(401).json({ ok: false, message: error.message });
            if (error.code === "USER_NOT_FOUND") return res.status(404).json({ ok: false, message: error.message });
            if (error.code === "NEW_PASSWORD_TOO_SHORT") return res.status(400).json({ ok: false, message: error.message });
            if (error.code === "NEW_PASSWORD_SAME_AS_CURRENT") return res.status(400).json({ ok: false, message: error.message });
            if (error.code === "MISSING_FIELDS") return res.status(400).json({ ok: false, message: error.message });
            return res.status(500).json({ ok: false, message: 'Erro ao atualizar senha', error: error.message });
        }
    },
}