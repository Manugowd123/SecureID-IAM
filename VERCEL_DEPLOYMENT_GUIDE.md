# Deploying SecureID IAM to Vercel with an External MySQL Database

This guide describes the deployment steps for this existing project. It has
**not** been executed end-to-end in this session — this environment has no
network access to `vercel.com` or to any external MySQL host, so no step
below has been verified against a live deployment. Treat this as instructions
to follow and verify yourself, not a report of a completed deployment.

## Prerequisites

- A GitHub (or GitLab/Bitbucket) account, with this project pushed as a repo.
- A Vercel account, connected to that Git provider.
- An externally-reachable MySQL database (e.g. PlanetScale, Railway, AWS RDS,
  Azure Database for MySQL). "Externally reachable" means it accepts
  connections from the internet / from Vercel's infrastructure, not just
  localhost.

## Step 1 — Provision the database

1. Create the MySQL instance with your provider of choice.
2. Load the schema:
   ```bash
   mysql -h <DB_HOST> -P <DB_PORT> -u <DB_USER> -p <DB_NAME> < database/schema.sql
   ```
3. **Check whether your provider requires TLS.** PlanetScale, for example,
   requires SSL connections. `backend/config/db.js` currently creates the
   `mysql2` pool with no `ssl` option:
   ```js
   const pool = mysql.createPool({
     host: process.env.DB_HOST || 'localhost',
     port: parseInt(process.env.DB_PORT || '3306', 10),
     user: process.env.DB_USER || 'root',
     password: process.env.DB_PASSWORD || '',
     database: process.env.DB_NAME || 'secureid_db',
     waitForConnections: true,
     connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT || '3', 10),
     queueLimit: 0
   });
   ```
   If your provider requires TLS, you will need to add an `ssl` option (e.g.
   `ssl: { rejectUnauthorized: true }` or the provider's CA certificate)
   before it will connect. This was intentionally **not** added
   speculatively, since the exact requirement depends on which provider you
   choose — add it once you know your target.

## Step 2 — Push to Git and import into Vercel

1. Push the repository to GitHub.
2. In Vercel: **New Project → Import Git Repository** → select the repo.
3. If the repo root is not the `secureid/` folder itself, set the Vercel
   project's **Root Directory** to `secureid/` in the import settings.

## Step 3 — Set environment variables

In the Vercel project's **Settings → Environment Variables**, add (Production
values, not placeholders — `backend/app.js` will refuse to boot in production
if any of these are missing or still contain `placeholder`/`your_`):

| Variable | Notes |
|---|---|
| `NODE_ENV` | `production` |
| `JWT_SECRET` | ≥32 random characters; app exits at startup if shorter |
| `JWT_EXPIRES_IN` | e.g. `15m` |
| `DB_HOST` | your external MySQL host |
| `DB_PORT` | usually `3306` |
| `DB_USER` | |
| `DB_PASSWORD` | |
| `DB_NAME` | |
| `DB_CONNECTION_LIMIT` | optional, default `3` (kept low intentionally — see note below) |
| `EMAIL_USER` / `EMAIL_APP_PASSWORD` | optional, only if outbound email (OTP/reset) is needed |
| `OIDC_ISSUER` | optional, set to `https://<your-app>.vercel.app` once you know your domain |

**Why `DB_CONNECTION_LIMIT` defaults low:** on Vercel, each warm serverless
instance holds its own connection pool, and many concurrent cold starts can
each open a pool against the same external database at once. A small
per-instance limit (default 3) keeps total connection usage reasonable. Raise
it only if you understand your MySQL provider's max-connections ceiling.

## Step 4 — Deploy

Trigger the deploy (push to the connected branch, or use the Vercel
dashboard/CLI). Vercel will build `backend/api/index.js` with `@vercel/node`
per `vercel.json`, bundling `frontend/**` alongside it.

## Step 5 — Verify the live deployment (do this yourself; not done here)

1. Visit `https://<your-app>.vercel.app/` — should redirect to
   `register.html`.
2. Register a test user; confirm a row appears in the `users` table in your
   MySQL database.
3. Complete the email OTP flow (if `EMAIL_USER`/`EMAIL_APP_PASSWORD` are set)
   and log in.
4. `POST /api/token` with a valid session cookie → confirm you get back a
   JWT `accessToken`.
5. `GET /api/protected` with `Authorization: Bearer <accessToken>` → confirm
   `200`.
6. `GET /api/protected` with the JWT placed in a JSON body (`{"token":
   "..."}`) instead of the header → confirm this now returns `401`. This
   specifically confirms the `req.body.token` fallback removal took effect
   in the deployed environment, not just locally.
7. Check Vercel's function logs for the deploy to confirm no MySQL
   connection errors on cold start.

Only once these checks pass against the real deployment should it be
considered verified — do not treat a successful `vercel deploy` command
alone as confirmation that authentication and the database connection work
correctly.
