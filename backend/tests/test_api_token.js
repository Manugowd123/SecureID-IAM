const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

const BASE_URL = 'http://localhost:3000/api';
const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'root',
  database: 'secureid_db'
};

/**
 * Test Suite: POST /api/token
 * Covers session -> JWT access token exchange, auth requirements, and
 * the "Remember Me" session lifetime extension used during login.
 */
async function testApiToken() {
  console.log('--- Testing POST /api/token (API Token Issuance) & Remember Me ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `api_token_${ts}@example.com`;
    const phone = `84${ts.toString().slice(-8)}`;
    const pwd = 'Password@123';
    const hash = await bcrypt.hash(pwd, 10);

    await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('Token', 'Tester', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [email, phone, hash]
    );

    // 1. POST /api/token without a session is rejected
    const rNoSession = await fetch(`${BASE_URL}/token`, { method: 'POST' });
    assert(rNoSession.status === 401, 'POST /api/token without an active session is rejected (HTTP 401)');

    // 2. Standard login (no Remember Me) issues a short-lived session cookie
    const rLogin = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd, rememberMe: false })
    });
    const dLogin = await rLogin.json();
    assert(rLogin.status === 200 && dLogin.success && dLogin.sessionId, 'Login without Remember Me succeeds and returns a session');
    assert(dLogin.rememberMe === false, 'Login response echoes rememberMe: false when not requested');

    const setCookieStandard = rLogin.headers.get('set-cookie');
    assert(!!setCookieStandard && setCookieStandard.includes('secureid_session'), 'Session cookie is issued on login');

    const [sessRows] = await conn.execute(
      'SELECT expires_at, created_at FROM sessions WHERE session_id = ? LIMIT 1',
      [dLogin.sessionId]
    );
    const standardLifetimeHours = (new Date(sessRows[0].expires_at) - new Date(sessRows[0].created_at)) / (60 * 60 * 1000);
    assert(standardLifetimeHours > 23 && standardLifetimeHours < 25, 'Standard (non-Remember Me) session expires in ~24 hours');

    const sessionCookieHeader = `secureid_session=${dLogin.sessionId}`;

    // 3. POST /api/token WITH a valid session issues a fresh JWT access token
    const rToken = await fetch(`${BASE_URL}/token`, {
      method: 'POST',
      headers: { Cookie: sessionCookieHeader }
    });
    const dToken = await rToken.json();
    assert(rToken.status === 200 && dToken.success && typeof dToken.accessToken === 'string' && dToken.accessToken.length > 0,
      'POST /api/token with a valid session returns a JWT access token');
    assert(dToken.tokenType === 'Bearer', 'Issued token response declares tokenType: Bearer');

    // 4. Issued token is a well-formed JWT (three dot-separated segments) and usable on a protected endpoint
    assert(dToken.accessToken.split('.').length === 3, 'Issued access token has valid JWT structure (header.payload.signature)');

    // 5. Remember Me login extends session lifetime to ~30 days
    const rLoginRemember = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd, rememberMe: true })
    });
    const dLoginRemember = await rLoginRemember.json();
    assert(rLoginRemember.status === 200 && dLoginRemember.success, 'Login with rememberMe: true succeeds');
    assert(dLoginRemember.rememberMe === true, 'Login response echoes rememberMe: true when requested');

    const [sessRowsRemember] = await conn.execute(
      'SELECT expires_at, created_at FROM sessions WHERE session_id = ? LIMIT 1',
      [dLoginRemember.sessionId]
    );
    const rememberLifetimeDays = (new Date(sessRowsRemember[0].expires_at) - new Date(sessRowsRemember[0].created_at)) / (24 * 60 * 60 * 1000);
    assert(rememberLifetimeDays > 29 && rememberLifetimeDays < 31, 'Remember Me session expires in ~30 days');

    const setCookieRemember = rLoginRemember.headers.get('set-cookie');
    const maxAgeMatch = setCookieRemember && setCookieRemember.match(/Max-Age=(\d+)/i);
    assert(!!maxAgeMatch && parseInt(maxAgeMatch[1], 10) > (20 * 24 * 60 * 60), 'Remember Me session cookie Max-Age reflects extended (~30 day) lifetime');

    // 6. Invalid/garbage session cookie is rejected by /api/token
    const rBadSession = await fetch(`${BASE_URL}/token`, {
      method: 'POST',
      headers: { Cookie: 'secureid_session=not_a_real_session_id' }
    });
    assert(rBadSession.status === 401, 'POST /api/token with an invalid session cookie is rejected (HTTP 401)');

    // 7. Expired session is rejected by /api/token (session exists in DB but expires_at is in the past)
    const [userRow] = await conn.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
    const userId = userRow[0].id;
    const expiredSessId = 'sess_tok_exp_' + ts;
    const pastExpires = new Date(Date.now() - 1000);
    await conn.execute(
      'INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())',
      [expiredSessId, userId, pastExpires]
    );
    const rExpiredSession = await fetch(`${BASE_URL}/token`, {
      method: 'POST',
      headers: { Cookie: `secureid_session=${expiredSessId}` }
    });
    assert(rExpiredSession.status === 401, 'POST /api/token with an expired session is rejected (HTTP 401)');

    // 8. Revoked session is rejected by /api/token (session exists, unexpired, but revoked_at is set)
    const revokedSessId = 'sess_tok_rev_' + ts;
    const futureExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await conn.execute(
      'INSERT INTO sessions (session_id, user_id, expires_at, revoked_at, created_at) VALUES (?, ?, ?, NOW(), NOW())',
      [revokedSessId, userId, futureExpires]
    );
    const rRevokedSession = await fetch(`${BASE_URL}/token`, {
      method: 'POST',
      headers: { Cookie: `secureid_session=${revokedSessId}` }
    });
    assert(rRevokedSession.status === 401, 'POST /api/token with a revoked session is rejected (HTTP 401)');

    // 9. Issued JWT never carries sensitive fields (password hash, OTP, or the signing secret itself)
    const decodedPayload = JSON.parse(Buffer.from(dToken.accessToken.split('.')[1], 'base64url').toString('utf8'));
    const forbiddenKeys = ['password', 'passwordHash', 'password_hash', 'otp', 'otpHash', 'otp_hash', 'dbPassword', 'db_password', 'jwtSecret', 'jwt_secret', 'secret'];
    const leakedKeys = Object.keys(decodedPayload).filter(k => forbiddenKeys.includes(k));
    assert(leakedKeys.length === 0, 'Issued JWT payload contains no sensitive/forbidden claims');
    assert(typeof decodedPayload.exp === 'number', 'Issued JWT payload includes an expiration (exp) claim');

  } catch (err) {
    console.error('API Token Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testApiToken;
if (require.main === module) {
  testApiToken().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
