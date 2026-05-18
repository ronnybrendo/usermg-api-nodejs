const router = require('express').Router();
const pool = require('../config/db');

router.get('/', async (req, res) => {
    
    try {
        const result = await pool.query('SELECT * FROM users');
        res.status(200).json({ ok: true, message: 'API Healthcheck OK', users: result.rows });
    } catch (error) {
        res.status(500).json({ ok: false, message: 'Erro ao verificar a saúde da API e conexao com o banco de dados', error: error.message });
    }


});

module.exports = router;