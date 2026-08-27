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

async function testSecurityHardening() {
  console.log('--- Testing Security Hardening & Vulnerabilities ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const emailA = `user_a_${ts}@example.com`;
    const emailB = `user_b_${ts}@example.com`;
    const phoneA = `89${ts.toString().slice(-8)}`;
    const phoneB = `88${ts.toString().slice(-8)}`;
    const pwd = 'Password@123';
    const hash = await bcrypt.hash(pwd, 10);

    // 1. Create two test users (User A and User B) and active sessions
    const [uA] = await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('User', 'A', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [emailA, phoneA, hash]
    );
    const [uB] = await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('User', 'B', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
      [emailB, phoneB, hash]
    );

    const userIdA = uA.insertId;
    const userIdB = uB.insertId;

    const sessA = `sess_a_${ts}`;
    const sessB = `sess_b_${ts}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [sessA, userIdA, expiresAt]);
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [sessB, userIdB, expiresAt]);

    // --- IDOR PROTECTION CHECKS ---
    // A tries to update B's profile (since PUT /api/profile resolves user ID from authenticated session req.user.id, this is intrinsically safe. Let's verify.)
    const rProfileUpdate = await fetch(`${BASE_URL}/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `secureid_session=${sessA}`
      },
      body: JSON.stringify({ firstName: 'Hacked', lastName: 'Name', phone: phoneA })
    });
    const dProfile = await rProfileUpdate.json();
    assert(rProfileUpdate.status === 200 && dProfile.user.id === userIdA, 'IDOR: User A cannot change User B profile (updates own profile)');

    // A tries to revoke B's session IDOR check
    const rRevokeIdor = await fetch(`${BASE_URL}/sessions/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `secureid_session=${sessA}`
      },
      body: JSON.stringify({ targetSessionId: sessB })
    });
    assert(rRevokeIdor.status === 404, 'IDOR: User A cannot revoke User B session (returns 404)');

    // Verify User B's session remains active
    const [sessBRow] = await conn.execute('SELECT revoked_at FROM sessions WHERE session_id = ?', [sessB]);
    assert(sessBRow[0].revoked_at === null, 'IDOR Check: User B session was not revoked by User A');


    // --- USER ENUMERATION PROTECTION CHECKS ---
    // Test forgot password does not leak account existence
    const rForgotExist = await fetch(`${BASE_URL}/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: emailA })
    });
    const dForgotExist = await rForgotExist.json();

    const rForgotNonExist = await fetch(`${BASE_URL}/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `nonexistent_${ts}@example.com` })
    });
    const dForgotNonExist = await rForgotNonExist.json();

    assert(
      rForgotExist.status === 200 && 
      rForgotNonExist.status === 200 && 
      dForgotExist.message === dForgotNonExist.message &&
      dForgotExist.challengeId !== undefined &&
      dForgotNonExist.challengeId !== undefined,
      'User Enumeration: forgot-password returns generic success and challengeId regardless of user existence'
    );


    // --- OTP PLAY & REUSE PROTECTION CHECKS ---
    // Create password reset OTP challenge for User A
    const resetChalId = `reset_chal_${ts}`;
    const otpVal = '999111';
    const otpHash = await bcrypt.hash(otpVal, 10);
    const exp = new Date(Date.now() + 5 * 60 * 1000);
    await conn.execute(
      `INSERT INTO otp_challenges (challenge_id, user_id, channel, purpose, otp_hash, expires_at, created_at)
       VALUES (?, ?, 'email', 'password_reset', ?, ?, NOW())`,
      [resetChalId, userIdA, otpHash, exp]
    );

    // Verify OTP first time -> should succeed
    const rVerify1 = await fetch(`${BASE_URL}/verify-reset-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: resetChalId, otp: otpVal })
    });
    const dVerify1 = await rVerify1.json();
    const resetToken = dVerify1.resetToken;
    assert(rVerify1.status === 200 && typeof resetToken === 'string', 'OTP verify first attempt succeeded');

    // Verify OTP second time -> should fail (replay protection)
    const rVerify2 = await fetch(`${BASE_URL}/verify-reset-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: resetChalId, otp: otpVal })
    });
    assert(rVerify2.status === 400 && (await rVerify2.json()).code === 'CHALLENGE_INACTIVE', 'OTP Replay: Challenge cannot be reused once verified');


    // --- PASSWORD RESET TOKEN REUSE PROTECTION ---
    // Reset password first time with resetToken -> should succeed
    const newPwd = 'NewPassword@2026';
    const rReset1 = await fetch(`${BASE_URL}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, newPassword: newPwd, confirmPassword: newPwd })
    });
    assert(rReset1.status === 200, 'Password reset first attempt with resetToken succeeded');

    // Reset password second time with same resetToken -> should fail (single-use token check)
    const rReset2 = await fetch(`${BASE_URL}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, newPassword: newPwd, confirmPassword: newPwd })
    });
    assert(rReset2.status === 400 && (await rReset2.json()).code === 'RESET_TOKEN_ALREADY_USED', 'Token Replay: resetToken cannot be used twice');


    // --- JWT VALIDATION CHECKS ---
    // Test verify-token endpoint with expired/malformed token
    const rBadJwt = await fetch(`${BASE_URL}/verify-token`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': 'Bearer malformed_token_val'
      }
    });
    assert(rBadJwt.status === 401 && (await rBadJwt.json()).code === 'INVALID_TOKEN', 'JWT Validation: Malformed JWT is rejected with 401 INVALID_TOKEN');


    // --- ADMIN AUTHORIZATION CHECKS ---
    // NOTE: The earlier PASSWORD RESET TOKEN REUSE checks reset User A's password via
    // /reset-password, which (correctly, as a security measure) revokes all of User A's
    // active sessions -- including sessA. A revoked session is unauthenticated, so reusing
    // sessA here would legitimately yield 401 rather than 403 and would not be testing RBAC
    // at all. Issue User A a fresh, valid session so these checks exercise the intended
    // "authenticated normal user -> 403" case rather than the "revoked session -> 401" case.
    const sessA2 = `sess_a2_${ts}`;
    await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, NOW())', [sessA2, userIdA, expiresAt]);

    // Regular User A attempts to view admin directory -> should return HTTP 403 Forbidden
    const rAdminUsers = await fetch(`${BASE_URL}/admin/users`, {
      headers: { 'Cookie': `secureid_session=${sessA2}` }
    });
    assert(rAdminUsers.status === 403, 'Admin Auth: Regular user is forbidden from admin user list (HTTP 403)');

    // Regular User A attempts to toggle lock -> should return HTTP 403 Forbidden
    const rAdminLock = await fetch(`${BASE_URL}/admin/users/${userIdB}/lock`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Cookie': `secureid_session=${sessA2}` 
      },
      body: JSON.stringify({ lock: true })
    });
    assert(rAdminLock.status === 403, 'Admin Auth: Regular user is forbidden from locking accounts (HTTP 403)');


    // --- SECURITY HEADERS CHECKS ---
    // Check `/api/me` response headers
    const rMeHeaders = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${sessA}` }
    });
    const headers = rMeHeaders.headers;
    assert(
      headers.get('x-content-type-options') === 'nosniff' &&
      headers.get('x-frame-options') === 'DENY' &&
      headers.get('referrer-policy') === 'strict-origin-when-cross-origin' &&
      headers.get('cache-control') === 'no-store, max-age=0, must-revalidate',
      'Security Headers: Server includes secure HTTP headers and no-store caching'
    );

  } catch (err) {
    console.error('Security Hardening Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testSecurityHardening;
if (require.main === module) {
  testSecurityHardening().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
