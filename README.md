# SecureID IAM Authentication & Registration System

A full Identity and Access Management (IAM) system built with a Node.js/Express
backend, MySQL, and a vanilla HTML/JS frontend. Features registration with
email OTP verification, optional SMS-based MFA, server-side sessions, active
session management, an audit trail, forgot-password/reset flows, a
session-to-JWT exchange (`/api/token`) for API access, and a JWT-guarded
resource endpoint (`/api/protected`). A minimal OAuth 2.0 / OpenID Connect
provider is also included.

## Project structure

```
secureid/
├── vercel.json                # Vercel deployment configuration
├── backend/
│   ├── app.js                 # Express app definition (used locally AND on Vercel)
│   ├── server.js              # Local/traditional-host entry point (app.listen + DB check)
│   ├── api/
│   │   └── index.js           # Vercel serverless function entry point
│   ├── config/db.js           # MySQL connection pool
│   ├── controllers/authController.js
│   ├── middleware/            # session auth, JWT auth, RBAC, rate limiting
│   ├── routes/authRoutes.js
│   ├── services/               # email, SMS, audit logging
│   ├── utils/                  # OTP + JWT helpers
│   ├── tests/                  # automated test suite (node tests/run_all_tests.js)
│   └── .env.example
├── database/schema.sql        # MySQL schema
└── frontend/                   # static HTML/CSS/JS, served by Express
```

## Local setup

1. Provision a local MySQL database and load the schema:
   ```bash
   mysql -u root -p < database/schema.sql
   ```
2. Copy the example environment file and fill in real values:
   ```bash
   cd backend
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the server:
   ```bash
   npm start
   ```
5. Open `http://localhost:3000` (redirects to the registration page).

## Environment variables

See `backend/.env.example` for the full, documented list. Required:

| Variable | Purpose |
|---|---|
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | MySQL connection |
| `JWT_SECRET` | HS256 signing key for access tokens/ID tokens. **Never commit a real value.** Must be ≥32 random characters in production. |
| `JWT_EXPIRES_IN` | Access token lifetime (e.g. `15m`) |
| `NODE_ENV` | `development` locally; `production` in deployment (enables `Secure` cookies and strict env validation) |
| `PORT` | Local dev server port (unused on Vercel) |

Optional: `EMAIL_USER`/`EMAIL_APP_PASSWORD` (outbound verification email), `DB_CONNECTION_LIMIT` (MySQL pool size per instance, default 3), `OIDC_ISSUER` (OIDC `iss` claim, defaults to `http://localhost:3000`).

`.env` is git-ignored and must never be committed. Neither should any real secret value.

## Running tests

```bash
cd backend
npm test
```

Runs `backend/tests/run_all_tests.js` against a running instance of the app
and a live MySQL database (the tests connect directly to MySQL to seed/verify
data alongside calling the HTTP API, so both the app and the database need to
be up first).

## Deploying to Vercel

The app is a standard Express application. `backend/app.js` exports the
configured Express app (no `app.listen()`, no blocking startup DB check),
and `backend/api/index.js` re-exports it as a Vercel serverless function.
`vercel.json` routes every request to that one function, which serves both
the API (`/api/*`) and the static frontend exactly as it does locally.

1. Provision an externally-reachable MySQL database (e.g. PlanetScale,
   Railway, AWS RDS) reachable over the internet, and load `database/schema.sql`
   into it.
2. Push this repository to GitHub and import it into Vercel.
3. In the Vercel project's Environment Variables settings, set (production
   values, not placeholders):
   - `NODE_ENV=production`
   - `JWT_SECRET` (long, random, ≥32 characters)
   - `JWT_EXPIRES_IN` (e.g. `15m`)
   - `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` (your external MySQL)
   - `EMAIL_USER`, `EMAIL_APP_PASSWORD` (if outbound email is required)
   - `DB_CONNECTION_LIMIT` (optional; defaults to 3, appropriate for serverless)
   - `OIDC_ISSUER` (optional; your deployed URL, e.g. `https://your-app.vercel.app`)
4. Deploy. Vercel builds `backend/api/index.js` with `@vercel/node` and
   bundles the `frontend/` directory alongside it so `express.static`
   continues to serve the frontend unchanged.

This has been prepared and locally verified for syntax/config correctness,
but has not been deployed to an actual Vercel project or tested against a
live external MySQL instance from this environment — verify the first real
deployment before relying on it.

## API endpoints

```
POST /api/register
POST /api/send-email-otp        POST /api/verify-email-otp
POST /api/send-sms-otp          POST /api/verify-sms-otp
POST /api/login                 POST /api/verify-login-otp   POST /api/send-login-sms-otp
GET  /api/me                    POST /api/logout
PUT  /api/profile                POST /api/change-password
GET  /api/sessions               POST /api/sessions/revoke    POST /api/sessions/revoke-others
GET  /api/audit-logs
GET  /api/admin/users            POST /api/admin/users/:userId/lock   (admin role required)
POST /api/forgot-password        POST /api/verify-reset-otp   POST /api/reset-password
POST /api/token                  GET  /api/protected
GET  /api/oauth/authorize        POST /api/oauth/token        GET /api/oauth/userinfo
POST /api/verify-token
```

## Security features

- Passwords hashed with bcrypt; all SQL is parameterized (no string-built queries).
- Server-side sessions (random 64-character hex IDs) stored in MySQL, checked
  for existence/expiry/revocation on every authenticated request.
- Session cookie: `HttpOnly`, `SameSite=Lax`, `Secure` in production.
- OTPs (email/SMS): backend-generated, bcrypt-hashed at rest, expire in 5
  minutes, capped at a fixed number of attempts, single-use.
- Account lockout after 5 consecutive failed login attempts.
- JWT access tokens: HS256 with an explicit algorithm allowlist, environment-sourced
  secret (never hard-coded, length-checked in production), short expiry,
  allowlisted claims only (never a password hash, OTP, or secret).
- `/api/protected` is guarded purely by JWT Bearer auth — a valid session
  cookie alone cannot access it.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, CSP, `Cache-Control: no-store` on `/api`) applied globally.
- No JWT or session token is ever stored in `localStorage`/`sessionStorage` on
  the frontend — the HttpOnly cookie is the sole browser-side credential.
