const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('CRITICAL: JWT_SECRET environment variable is required.');
}

const ACTUAL_SECRET = JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';

/**
 * Generates a signed JWT Access Token for the authenticated user.
 * Used for accessing protected backend APIs.
 * @param {object} user - User record
 * @returns {string} Signed JWT Access Token
 */
function generateAccessToken(user) {
  const payload = {
    userId: user.id || user.user_id,
    email: user.email,
    firstName: user.first_name || user.firstName,
    lastName: user.last_name || user.lastName,
    role: user.role || 'user'
  };

  return jwt.sign(payload, ACTUAL_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256'
  });
}

/**
 * Generates an OpenID Connect (OIDC) ID Token signed with JWT_SECRET.
 * Used by OAuth 2.0 / OIDC client applications to identify the authenticated user.
 * Contains standard OIDC claims: iss, sub, aud, iat, exp, auth_time, name, given_name, family_name, email, email_verified, phone_number, role.
 * @param {object} user - User record
 * @param {string} clientId - OAuth Client ID (aud claim)
 * @returns {string} Signed OIDC ID Token
 */
function generateIdToken(user, clientId) {
  const issuer = process.env.OIDC_ISSUER || 'http://localhost:3000';
  const nowInSeconds = Math.floor(Date.now() / 1000);

  const payload = {
    iss: issuer,
    sub: String(user.id || user.user_id),
    aud: clientId,
    auth_time: nowInSeconds,
    name: `${user.first_name || user.firstName || ''} ${user.last_name || user.lastName || ''}`.trim(),
    given_name: user.first_name || user.firstName,
    family_name: user.last_name || user.lastName,
    email: user.email,
    email_verified: Boolean(user.email_verified || user.emailVerified),
    phone_number: user.phone,
    role: user.role || 'user'
  };

  return jwt.sign(payload, ACTUAL_SECRET, {
    expiresIn: '15m',
    algorithm: 'HS256'
  });
}

/**
 * Verifies a JWT Access Token or OIDC ID Token.
 * @param {string} token - JWT string
 * @returns {object} Decoded token payload
 */
function verifyAccessToken(token) {
  return jwt.verify(token, ACTUAL_SECRET, { algorithms: ['HS256'] });
}

module.exports = {
  generateAccessToken,
  generateIdToken,
  verifyAccessToken
};
