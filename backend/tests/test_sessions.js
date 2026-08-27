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

async function testSessions() {
  console.log('--- Testing Server-Side Session Management ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `sess_test_${ts}@example.com`;
    const phone = `88${ts.toString().slice(-8)}`;
    const pwd = 'Password@123';
    const hash = await bcrypt.hash(pwd, 10);

    const [u] = await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('Session', 'Test', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [email, phone, hash]
    );
    const userId = u.insertId;

    // 1. Create multiple sessions for the same user
    const sessId1 = 'sess1_' + ts;
    const sessId2 = 'sess2_' + ts;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [sessId1, userId, expiresAt]);
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [sessId2, userId, expiresAt]);

    // 2. GET /api/me requires a valid session
    const rNoSess = await fetch(`${BASE_URL}/me`);
    assert(rNoSess.status === 401, 'GET /api/me without cookie is unauthorized (HTTP 401)');

    // 3. GET /api/me with session 1 returns correct user
    const rSess1 = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${sessId1}` }
    });
    const dSess1 = await rSess1.json();
    assert(rSess1.status === 200 && dSess1.success && dSess1.user.id === userId, 'GET /api/me with session 1 retrieves correct user profile');

    // 4. Test Expired Session Rejection
    const expiredSessId = 'sess_exp_' + ts;
    const pastExpires = new Date(Date.now() - 1000);
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [expiredSessId, userId, pastExpires]);

    const rExpired = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${expiredSessId}` }
    });
    assert(rExpired.status === 401, 'Expired session rejected with HTTP 401');

    // 5. Test Revoked Session Rejection
    const revokedSessId = 'sess_rev_' + ts;
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, revoked_at, created_at) VALUES (?, ?, ?, NOW(), NOW())', [revokedSessId, userId, expiresAt]);

    const rRevoked = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${revokedSessId}` }
    });
    assert(rRevoked.status === 401, 'Revoked session rejected with HTTP 401');

    // 6. Logout revokes the current session and clears the cookie
    const rLogout = await fetch(`${BASE_URL}/logout`, {
      method: 'POST',
      headers: { 'Cookie': `secureid_session=${sessId1}` }
    });
    const logoutCookies = rLogout.headers.get('set-cookie');
    assert(rLogout.status === 200 && logoutCookies && logoutCookies.includes('secureid_session='), 'POST /api/logout clears secureid_session cookie');

    // Check in DB that session 1 is indeed revoked
    const [sess1Db] = await conn.execute('SELECT revoked_at FROM sessions WHERE session_id = ?', [sessId1]);
    assert(sess1Db[0].revoked_at !== null, 'Session 1 is marked revoked in database');

    // Verify session 2 is still active (unrelated session NOT revoked)
    const [sess2Db] = await conn.execute('SELECT revoked_at FROM sessions WHERE session_id = ?', [sessId2]);
    assert(sess2Db[0].revoked_at === null, 'Logging out session 1 does not affect active session 2');

    // 7. The old session cannot be reused after logout — retrying it against a protected
    //    endpoint (not just checking the DB flag) must be rejected.
    const rReuseAfterLogout = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${sessId1}` }
    });
    assert(rReuseAfterLogout.status === 401, 'Reusing the session cookie after logout is rejected (HTTP 401)');

    // 8. Session cookie security attributes: log in for real and inspect the Set-Cookie header.
    const emailAttr = `sess_cookie_${ts}@example.com`;
    const phoneAttr = `89${ts.toString().slice(-8)}`;
    await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('Cookie', 'Attrs', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [emailAttr, phoneAttr, hash]
    );
    const rLoginAttr = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: emailAttr, password: pwd })
    });
    const loginSetCookie = rLoginAttr.headers.get('set-cookie') || '';
    assert(rLoginAttr.status === 200, 'Login for cookie-attribute check succeeds');
    assert(/HttpOnly/i.test(loginSetCookie), 'Session cookie is HttpOnly');
    assert(/SameSite=Lax/i.test(loginSetCookie), 'Session cookie sets SameSite=Lax');
    // Secure should track NODE_ENV: only guaranteed set in production. Tests run outside
    // production, so we assert the flag correctly matches the current environment rather
    // than hard-requiring it, so local/dev HTTP testing isn't broken.
    const hasSecureFlag = /;\s*Secure/i.test(loginSetCookie);
    assert(hasSecureFlag === (process.env.NODE_ENV === 'production'),
      'Session cookie Secure flag matches NODE_ENV (set only in production)');

    // 9. Session IDs are unpredictable (high-entropy random hex) and are not JWTs.
    const dLoginAttr = await rLoginAttr.json();
    const issuedSessionId = dLoginAttr.sessionId;
    assert(typeof issuedSessionId === 'string' && /^[0-9a-f]{64}$/.test(issuedSessionId),
      'Session ID is a 64-character random hex string (crypto.randomBytes-based)');
    assert(issuedSessionId.split('.').length !== 3, 'Session ID is not structured like a JWT (header.payload.signature)');

  } catch (err) {
    console.error('Sessions Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testSessions;
if (require.main === module) {
  testSessions().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
