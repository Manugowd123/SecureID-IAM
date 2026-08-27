const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const BASE_URL = 'http://localhost:3000/api';
const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'root',
  database: 'secureid_db'
};

/**
 * Test Suite: GET /api/protected
 * Covers access to a JWT Bearer-token-guarded resource endpoint, including
 * rejection of missing/invalid/expired tokens and successful access with a
 * token obtained via POST /api/token.
 */
async function testProtectedEndpoint() {
  console.log('--- Testing GET /api/protected (JWT-Guarded Resource) ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `protected_ep_${ts}@example.com`;
    const phone = `85${ts.toString().slice(-8)}`;
    const pwd = 'Password@123';
    const hash = await bcrypt.hash(pwd, 10);

    await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('Protected', 'Resource', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [email, phone, hash]
    );

    // 1. GET /api/protected with no Authorization header is rejected
    const rNoAuth = await fetch(`${BASE_URL}/protected`);
    assert(rNoAuth.status === 401, 'GET /api/protected without a Bearer token is rejected (HTTP 401)');

    // 2. GET /api/protected with a malformed/garbage token is rejected
    const rBadToken = await fetch(`${BASE_URL}/protected`, {
      headers: { Authorization: 'Bearer not.a.validtoken' }
    });
    assert(rBadToken.status === 401, 'GET /api/protected with an invalid JWT is rejected (HTTP 401)');
    const dBadToken = await rBadToken.json();
    assert(dBadToken.code === 'INVALID_TOKEN', 'Invalid token response carries INVALID_TOKEN error code');

    // 3. Log in to obtain a session, then exchange it for a JWT via POST /api/token
    const rLogin = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd })
    });
    const dLogin = await rLogin.json();
    assert(rLogin.status === 200 && dLogin.success, 'Login succeeds for protected-endpoint test user');

    // accessToken is also returned directly on login; use it to access the protected resource
    const loginAccessToken = dLogin.accessToken;
    assert(typeof loginAccessToken === 'string' && loginAccessToken.length > 0, 'Login response includes a JWT access token');

    // 4. GET /api/protected with a valid Bearer token succeeds
    const rProtected = await fetch(`${BASE_URL}/protected`, {
      headers: { Authorization: `Bearer ${loginAccessToken}` }
    });
    const dProtected = await rProtected.json();
    assert(rProtected.status === 200 && dProtected.success, 'GET /api/protected with a valid Bearer token succeeds (HTTP 200)');
    assert(dProtected.data && dProtected.data.resource === 'protected-data', 'Protected resource payload is returned');
    assert(dProtected.user && dProtected.user.email === email, 'Decoded JWT user info matches the authenticated user');

    // 5. Token obtained via POST /api/token (session -> JWT exchange) also works on /api/protected
    const sessionCookieHeader = `secureid_session=${dLogin.sessionId}`;
    const rTokenExchange = await fetch(`${BASE_URL}/token`, {
      method: 'POST',
      headers: { Cookie: sessionCookieHeader }
    });
    const dTokenExchange = await rTokenExchange.json();
    assert(rTokenExchange.status === 200 && dTokenExchange.success, 'POST /api/token exchange succeeds using the login session');

    const rProtectedViaExchange = await fetch(`${BASE_URL}/protected`, {
      headers: { Authorization: `Bearer ${dTokenExchange.accessToken}` }
    });
    const dProtectedViaExchange = await rProtectedViaExchange.json();
    assert(rProtectedViaExchange.status === 200 && dProtectedViaExchange.success,
      'GET /api/protected succeeds using a token issued by POST /api/token (HTTP 200)');

    // 6. A genuinely expired JWT (valid signature, past exp) is rejected
    require('dotenv').config();
    const secret = process.env.JWT_SECRET;
    const expiredJwt = jwt.sign(
      { userId: 1, email, role: 'user' },
      secret,
      { algorithm: 'HS256', expiresIn: -10 } // already expired 10s ago
    );
    const rExpiredJwt = await fetch(`${BASE_URL}/protected`, {
      headers: { Authorization: `Bearer ${expiredJwt}` }
    });
    assert(rExpiredJwt.status === 401, 'GET /api/protected with an expired JWT is rejected (HTTP 401)');
    const dExpiredJwt = await rExpiredJwt.json();
    assert(dExpiredJwt.code === 'TOKEN_EXPIRED', 'Expired token response carries TOKEN_EXPIRED error code');

    // 7. A JWT signed with the wrong secret (bad signature) is rejected
    const wrongSignatureJwt = jwt.sign(
      { userId: 1, email, role: 'user' },
      'this-is-not-the-real-jwt-secret',
      { algorithm: 'HS256', expiresIn: '15m' }
    );
    const rWrongSig = await fetch(`${BASE_URL}/protected`, {
      headers: { Authorization: `Bearer ${wrongSignatureJwt}` }
    });
    assert(rWrongSig.status === 401, 'GET /api/protected with a wrong-signature JWT is rejected (HTTP 401)');
    const dWrongSig = await rWrongSig.json();
    assert(dWrongSig.code === 'INVALID_TOKEN', 'Wrong-signature token response carries INVALID_TOKEN error code');

    // 8. A malformed Authorization header (missing "Bearer" scheme) is rejected
    const rMalformedHeader = await fetch(`${BASE_URL}/protected`, {
      headers: { Authorization: loginAccessToken } // raw token, no "Bearer " prefix
    });
    assert(rMalformedHeader.status === 401, 'GET /api/protected with a malformed Authorization header (no Bearer scheme) is rejected (HTTP 401)');

    // 9. A valid server-side session cookie alone must NOT bypass JWT authentication here
    const sessionCookieOnly = `secureid_session=${dLogin.sessionId}`;
    const rCookieOnly = await fetch(`${BASE_URL}/protected`, {
      headers: { Cookie: sessionCookieOnly } // no Authorization header at all
    });
    assert(rCookieOnly.status === 401, 'GET /api/protected is rejected when only a valid session cookie is presented (no JWT bypass)');

  } catch (err) {
    console.error('Protected Endpoint Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testProtectedEndpoint;
if (require.main === module) {
  testProtectedEndpoint().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
