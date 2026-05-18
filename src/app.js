const express = require('express');
const healthRouter = require('./routes/health.routes');
const authRouter = require('./routes/auth.routes');
const usersRouter = require('./routes/users.route');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

app.use(helmet());
app.use(cors({
    origin: [process.env.FRONTEND_URL],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Content-Type", "Authorization"],
    maxAge: 600,
    preflightContinue: false,
    optionsSuccessStatus: 204,
}));
app.use(express.json());
app.use('/health', healthRouter);
app.use('/auth', authRouter);
app.use('/users', usersRouter);

module.exports = app;