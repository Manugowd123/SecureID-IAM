const { pool } = require('../config/db');

const COOKIE_NAME = 'secureid_session';

/**
 * Authentication Middleware
 * Reads session_id from secureid_session HttpOnly cookie (or Authorization Bearer / request body fallback).
 * Verifies that session exists in sessions table, has not expired, and has not been revoked.
 */
async function authMiddleware(req, res, next) {
  try {
    let sessionId = req.cookies?.[COOKIE_NAME];

    if (!sessionId && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
        sessionId = parts[1];
      }
    }

    if (!sessionId && req.body && req.body.sessionId) {
      sessionId = req.body.sessionId;
    }

    if (!sessionId) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required. No session cookie or token provided.'
      });
    }

    // Query session join with users table
    const [rows] = await pool.execute(
      `SELECT s.id AS session_db_id, s.session_id, s.user_id, s.expires_at, s.revoked_at,
              u.id AS u_id, u.first_name, u.last_name, u.email, u.phone, u.role, u.account_locked_until
       FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.session_id = ? LIMIT 1`,
      [sessionId]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Invalid session.'
      });
    }

    const sessionRecord = rows[0];

    // Check if user account is locked (Phase 12)
    if (sessionRecord.account_locked_until) {
      const lockTime = new Date(sessionRecord.account_locked_until);
      if (new Date() < lockTime) {
        return res.status(403).json({
          success: false,
          code: 'ACCOUNT_LOCKED',
          message: 'Account is locked. Session suspended.'
        });
      }
    }

    // Check if session has been revoked
    if (sessionRecord.revoked_at !== null) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Session has been revoked.'
      });
    }

    // Check if session has expired
    if (new Date() > new Date(sessionRecord.expires_at)) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Session has expired.'
      });
    }

    // Attach authenticated user and session data to req object
    req.user = {
      id: sessionRecord.u_id,
      firstName: sessionRecord.first_name,
      lastName: sessionRecord.last_name,
      email: sessionRecord.email,
      phone: sessionRecord.phone,
      role: sessionRecord.role || 'user'
    };

    req.session = {
      id: sessionRecord.session_db_id,
      sessionId: sessionRecord.session_id,
      expiresAt: sessionRecord.expires_at
    };

    next();

  } catch (error) {
    console.error('Auth Middleware Error:', error);
    return res.status(500).json({
      success: false,
      code: 'SERVER_ERROR',
      message: 'An error occurred while verifying session authentication.'
    });
  }
}

module.exports = authMiddleware;
