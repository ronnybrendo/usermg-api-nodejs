const pool = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

module.exports = {

        register : async ({ name, email, password }) => {

            if (!name || !email || !password) {
                const error = new Error('Nome, email e senha são obrigatórios');
                error.code = "MISSING_FIELDS";
                throw error;
            }

            if (password.length < 6) {
                const error = new Error('Senha deve ter pelo menos 6 caracteres');
                error.code = "INVALID_FIELD";
                throw error;
            }

            const emailLower = email.toLowerCase().trim();

            const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);

            if (userExists.rows.length > 0) {
                const error = new Error('Usuário já existe');
                error.code = "EMAIL_IN_USE";
                throw error;
            }

            const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS);

            const passwordHash = await bcrypt.hash(password, saltRounds);

            const result = await pool.query('INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, role, created_at', [name.trim(), emailLower, passwordHash]);
            
            return result.rows[0];
        },

        login: async ({ email, password }) => {

            if (!email || !password) {
                const error = new Error('Email e senha são obrigatórios');
                error.code = "MISSING_FIELDS";
                throw error;
            }

            const emailLower = email.toLowerCase().trim();

            const user = await pool.query('SELECT id, name, email, role, password_hash FROM users WHERE email = $1', [emailLower]);
            const sessionId = crypto.randomUUID();

            if (user.rows.length === 0) {
                const error = new Error('Usuário não encontrado');
                error.code = "INVALID_USER";
                throw error;
            }

            const passwordMatch = await bcrypt.compare(password, user.rows[0].password_hash);

            if (!passwordMatch) {
                const error = new Error('Senha incorreta');
                error.code = "INVALID_USER";
                throw error;
            }

            const accessToken = jwt.sign(
                { sub: user.rows[0].id, role: user.rows[0].role, sid: sessionId },
                process.env.JWT_ACCESS_SECRET,
                { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m" }
            );

            const refreshToken = jwt.sign(
                { sub: user.rows[0].id, type: "refresh", sid: sessionId },
                process.env.JWT_REFRESH_SECRET,
                { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d" }
            );

            const refreshTokenHash = crypto
                .createHash("sha256")
                .update(refreshToken)
                .digest("hex");

            const decodedRefresh = jwt.decode(refreshToken);

            
            await pool.query(
                `INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at)
                VALUES ($1, $2, $3, to_timestamp($4))`,
                [sessionId, user.rows[0].id, refreshTokenHash, decodedRefresh.exp]
            );

            return {
                accessToken,
                refreshToken,
                user: {
                id: user.rows[0].id,
                name: user.rows[0].name,
                email: user.rows[0].email,
                role: user.rows[0].role,
                sid: sessionId,
                },
            };
        },

        logout: async ({ refreshToken }) => {
            if (!refreshToken) {
                const error = new Error('Token de refresh é obrigatório');
                error.code = "MISSING_FIELDS";
                throw error;
            }

            const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

            const result = await pool.query(
                `UPDATE sessions
                SET revoked_at = NOW()
                WHERE refresh_token_hash = $1
                AND revoked_at IS NULL
                AND expires_at > NOW()
                RETURNING refresh_token_hash`, 
                [refreshTokenHash]);
            
            if (result.rows.length === 0) {
                const error = new Error("Sessão inválida ou já revogada");
                error.code = "INVALID_SESSION";
                throw error;
            }

            return { success: true, message: 'Logout realizado com sucesso' };
        },
    
    logoutAll: async (userId) => {

        const result = await pool.query(`UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at is NULL`, [userId]);
        return { success: true, message: 'Logout de todas as sessões realizado com sucesso', result: result.rows };
    },

    refresh: async ({ refreshToken }) => {

            try {

                if (!refreshToken) {
                    const error = new Error('Token de refresh é obrigatório');
                    error.code = "MISSING_FIELDS";
                    throw error;
                }

                let decoded;
                try {
                    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
                } catch {
                    const error = new Error('Token de refresh inválido');
                    error.code = "INVALID_REFRESH_TOKEN";
                    throw error;
                }

                if (decoded.type !== "refresh") {
                    const error = new Error("Tipo de token inválido para refresh");
                    error.code = "INVALID_REFRESH_TOKEN";
                    throw error;
                }

                const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

                const currentSession = await pool.query(
                    `SELECT id, user_id
                    FROM sessions
                    WHERE refresh_token_hash = $1
                    AND revoked_at IS NULL
                    AND expires_at > NOW()`,
                    [refreshTokenHash]
                );
                
                if (currentSession.rows.length === 0) {
                    const error = new Error("Sessão inválida ou já revogada");
                    error.code = "INVALID_SESSION";
                    throw error;
                }

                const sessionId = currentSession.rows[0].id;
                const userId = currentSession.rows[0].user_id;
                const newSessionId = crypto.randomUUID();

                // revoga sessão antiga
                await pool.query(
                    `UPDATE sessions SET revoked_at = NOW() WHERE id = $1`,
                    [sessionId]
                );

                const role = await pool.query('SELECT role FROM users WHERE id = $1', [userId]);

                if (role.rows.length === 0) {
                    const error = new Error("Usuário não encontrado");
                    error.code = "INVALID_USER";
                    throw error;
                }
                
                const accessToken = jwt.sign(
                    { sub: userId, role: role.rows[0].role || 'user', sid: newSessionId },
                    process.env.JWT_ACCESS_SECRET,
                    { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m" }
                );

                const newRefreshToken = jwt.sign(
                    { sub: userId, type: 'refresh', sid: newSessionId },
                    process.env.JWT_REFRESH_SECRET,
                    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
                );

                const newRefreshTokenDecoded = jwt.decode(newRefreshToken);

                const newRefreshTokenHash = crypto
                .createHash('sha256')
                .update(newRefreshToken)
                .digest('hex');

                await pool.query(
                    `INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at)
                    VALUES ($1, $2, $3, to_timestamp($4))`,
                    [newSessionId, userId, newRefreshTokenHash, newRefreshTokenDecoded.exp]
                );

                return {
                    accessToken,
                    refreshToken: newRefreshToken,
                    type: "refresh",
                    sid: newSessionId,
                };

            } catch (error) {
                
                if (
                    error.code === "MISSING_FIELDS" ||
                    error.code === "INVALID_REFRESH_TOKEN" ||
                    error.code === "INVALID_SESSION" ||
                    error.code === "INVALID_USER"
                    ) {
                    throw error;
                    }
                  // Erros vindos direto do jwt.verify
                if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
                    const jwtError = new Error("Token de refresh inválido ou expirado");
                    jwtError.code = "INVALID_REFRESH_TOKEN";
                    throw jwtError;
                }
                  // Fallback
                const fallbackError = new Error("Erro interno ao renovar token");
                fallbackError.code = "INTERNAL_ERROR";
                throw fallbackError;
                }
            },

    isValidToken: async ({ sub, sid }) => {

        if (!sub || !sid) {
            const error = new Error('Token inválido ou expirado / Sessão inválida');
            error.code = "INVALID_SESSION";
            throw error;
        }

        const user = await pool.query('SELECT id FROM sessions WHERE id = $1 and user_id = $2 and revoked_at is null', [sid, Number(sub)]);

        if (user.rows.length === 0) {
            const error = new Error('Token inválido ou expirado / Sessão inválida');
            error.code = "INVALID_SESSION";
            throw error;
        }
        return true;
    },

    getAllSessions: async () => {
        const sessions = await pool.query('SELECT id, user_id, refresh_token_hash, expires_at FROM sessions WHERE revoked_at is NULL');
        return sessions.rows;
    },
}