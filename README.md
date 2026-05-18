# usermg

User management API with authentication and authorization using Node.js, JWT, and PostgreSQL.

## Stack

- Node.js + Express
- PostgreSQL (`pg`)
- JWT (`jsonwebtoken`)
- `bcrypt`
- `helmet`, `cors`, `express-rate-limit`

## Installation

```bash
npm install
```

## Environment Setup

Create `.env` from `.env.example`:

```bash
cp .env.example .env
```

## Run

```bash
npm run dev
```

Default API URL: `http://localhost:3000`

## Endpoints

### Health
- `GET /health`  
  Checks if the API is running and if the database connection is working.

### Auth
- `POST /auth/register`  
  Creates a new user with a hashed password.
- `POST /auth/login`  
  Validates credentials and returns `accessToken` + `refreshToken`.
- `POST /auth/refresh`  
  Renews tokens with session rotation.
- `POST /auth/logout`  
  Revokes the session linked to the provided refresh token.
- `POST /auth/logout-all`  
  Revokes all active sessions for the authenticated user.

### Users
- `GET /users/me`  
  Returns authenticated user data.
- `PATCH /users/me/password`  
  Changes password (requires current password) and revokes active sessions.
- `GET /users` *(admin)*  
  Lists users.
- `GET /users/:id` *(admin)*  
  Gets user by id.
- `PATCH /users/:id` *(admin)*  
  Updates user data.
- `DELETE /users/:id` *(admin)*  
  Deletes a user.

## Security Implemented

- Passwords are stored using `bcrypt` hashing (never plaintext).
- Authentication uses short-lived `accessToken` and longer-lived `refreshToken`.
- Session control with `sid` claim inside tokens.
- Sessions are persisted in database (`sessions`) and can be revoked.
- Session revocation on logout.
- Global session revocation with logout-all.
- Refresh token rotation in `/auth/refresh`.
- Session validation in auth middleware (checks active/non-revoked session).
- Role-based authorization with `requireRole('admin')`.
- Rate limiting on login and refresh endpoints (brute-force mitigation).
- `helmet` and `cors` enabled.
- Sensitive values isolated in `.env` (`.env.example` is versioned).

## License

MIT
