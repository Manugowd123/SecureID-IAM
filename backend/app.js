const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
require('dotenv').config();

// Validate production environment variables (Phase 2)
if (process.env.NODE_ENV === 'production') {
  const requiredEnv = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
  const missing = requiredEnv.filter(key => !process.env[key] || process.env[key] === '' || process.env[key].includes('placeholder') || process.env[key].includes('your_'));
  if (missing.length > 0) {
    console.error('CRITICAL ERROR: Missing or invalid required environment variables in production:');
    missing.forEach(m => console.error(` - ${m}`));
    process.exit(1);
  }

  // JWT_SECRET must also be strong enough to resist brute-force guessing of the
  // HS256 signing key, not merely present and non-placeholder.
  if (process.env.JWT_SECRET.length < 32) {
    console.error('CRITICAL ERROR: JWT_SECRET is too short for production use.');
    console.error(' - JWT_SECRET must be at least 32 characters (256 bits) of high-entropy random data.');
    process.exit(1);
  }
}

const authRoutes = require('./routes/authRoutes');

/**
 * Builds and configures the Express application.
 *
 * This module intentionally does NOT call app.listen() or perform any
 * blocking database connectivity check at load time: it is required both
 * by backend/server.js (traditional long-running local/dev process, which
 * layers app.listen() + a startup DB check on top of this) and by
 * backend/api/index.js (the Vercel serverless entry point, where the
 * platform itself owns the request/response lifecycle and a blocking
 * connectivity check on every cold start would only add latency without
 * improving reliability -- individual routes already handle DB errors
 * and return 500 SERVER_ERROR on failure).
 */
function createExpressApp() {
  const app = express();

  // Middleware
  app.use(express.json({ limit: '10kb' })); // JSON payload limit (Phase 16)
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  app.use(cookieParser());

  // Security Headers Middleware (Phase 14)
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
    if (req.path.startsWith('/api')) {
      res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
    }
    next();
  });

  // Serve frontend static files
  app.use(express.static(path.join(__dirname, '../frontend')));

  // API Routes
  app.use('/api', authRoutes);

  // Root route redirect to register.html
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/register.html'));
  });

  // Global 404 handler
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      code: 'NOT_FOUND',
      message: 'Requested endpoint or resource not found.'
    });
  });

  return app;
}

module.exports = createExpressApp();
