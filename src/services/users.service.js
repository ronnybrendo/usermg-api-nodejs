const pool = require('../config/db');
const bcrypt = require('bcrypt');

module.exports = {
    
    getUserById: async (userId) => {
        const result = await pool.query('SELECT id, name, email, role, created_at FROM users WHERE id = $1', [userId]);
        if (result.rows.length === 0) {
            const error = new Error('Usuário não encontrado');
            error.code = "USER_NOT_FOUND";
            throw error;
        }
        return result.rows[0];
    },

    getAllUsers: async () => {
        const result = await pool.query('SELECT id, name, email, role, created_at FROM users ORDER BY id DESC');

        return result.rows;
    },

    updateUser: async (userId, { name, email, role }) => {

        console.log("payload", { name, email, role, userId });

        if (email) {
        const emailInUse = await pool.query('SELECT * FROM users WHERE email = $1 AND id = $2', [email, userId]);
        console.log("emailInUse", emailInUse.rows);

            if (emailInUse.rows.length > 0) {
                const error = new Error('Email já em uso');
                error.code = "EMAIL_IN_USE";
                throw error;
            }
        }

        const result = await pool.query('UPDATE users SET name = $1, email = $2, role = $3 WHERE id = $4', [name, email, role, userId]);

        if (result.rowCount === 0) {
            const error = new Error('Usuário não encontrado');
            error.code = "USER_NOT_FOUND";
            throw error;
        }

        return result.rows[0];
    },

    deleteUser: async (userId) => {
        const result = await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        if (result.rowCount === 0) {
            const error = new Error('Usuário não encontrado');
            error.code = "USER_NOT_FOUND";
            throw error;
        }
        return result.rows[0];
    },

    changePassword: async (userId, { currentPassword, newPassword }) => {

        if (!currentPassword || !newPassword) {
            const error = new Error('Senha atual e nova senha são obrigatórias');
            error.code = "MISSING_FIELDS";
            throw error;
        }

        if (currentPassword === newPassword) {
            const error = new Error('A nova senha não pode ser igual à senha atual');
            error.code = "NEW_PASSWORD_SAME_AS_CURRENT";
            throw error;
        }

        if (newPassword.length < process.env.MIN_PASSWORD_LENGTH) {
            const error = new Error(`A nova senha deve ter pelo menos ${process.env.MIN_PASSWORD_LENGTH} caracteres`);
            error.code = "NEW_PASSWORD_TOO_SHORT";
            throw error;
        }

        const userResult = await pool.query(
            "SELECT id, password_hash FROM users WHERE id = $1",
            [userId]
        );

        if (userResult.rows.length === 0) {
            const error = new Error('Usuário não encontrado');
            error.code = "USER_NOT_FOUND";
            throw error;
        }

        const user = userResult.rows[0];
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isPasswordValid) {
            const error = new Error('Senha atual incorreta');
            error.code = "INVALID_PASSWORD";
            throw error;
        }

        const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS);
        const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
        await pool.query(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            [newPasswordHash, userId]
        );

        await pool.query(
            "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            [userId]
        );

        return true;
    },
}