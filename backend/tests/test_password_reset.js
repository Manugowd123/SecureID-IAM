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

async function testPasswordReset() {
  console.log('--- Testing Password Reset Flow ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  const ts = Date.now();
  const email = `pwd_reset_${ts}@example.com`;
  const phone = `81${ts.toString().slice(-8)}`;
  const oldPwd = 'OldPassword@123';
  const newPwd = 'NewPassword@2026';
  const oldHash = await bcrypt.hash(oldPwd, 10);

  // Create verified user & active session
  const [u] = await conn.execute(
    `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
     VALUES ('Reset', 'Tester', ?, ?, ?, 1, 0, 0, NULL, NOW(), NOW())`,
    [email, phone, oldHash]
  );
  const userId = u.insertId;
  const activeSess = 'pwd_reset_sess_' + ts;
  await conn.execute('INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR), NOW())', [activeSess, userId]);

  // 1. Request Forgot Password
  const rForgot = await fetch(`${BASE_URL}/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  const dForgot = await rForgot.json();
  const challengeId = dForgot.challengeId;
  assert(rForgot.status === 200 && challengeId, 'POST /api/forgot-password generated OTP challenge');

  // 2. Test Invalid OTP Rejection
  const rWrongOtp = await fetch(`${BASE_URL}/verify-reset-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, otp: '000000' })
  });
  const dWrongOtp = await rWrongOtp.json();
  assert(rWrongOtp.status === 400 && dWrongOtp.code === 'INVALID_OTP', 'Invalid OTP rejected with INVALID_OTP');

  // 3. Set known OTP and test successful verification
  const knownOtp = '888999';
  const knownHash = await bcrypt.hash(knownOtp, 10);
  await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE challenge_id = ?', [knownHash, challengeId]);

  const rVerifyOtp = await fetch(`${BASE_URL}/verify-reset-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, otp: knownOtp })
  });
  const dVerifyOtp = await rVerifyOtp.json();
  const resetToken = dVerifyOtp.resetToken;
  assert(rVerifyOtp.status === 200 && dVerifyOtp.success && typeof resetToken === 'string', 'OTP verified successfully; issued single-use resetToken');

  // 4. Test Weak Password Rejection
  const rWeak = await fetch(`${BASE_URL}/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resetToken, newPassword: '123', confirmPassword: '123' })
  });
  const dWeak = await rWeak.json();
  assert(rWeak.status === 400 && dWeak.code === 'WEAK_PASSWORD', 'Weak password rejected with WEAK_PASSWORD');

  // 5. Test Mismatching Password Rejection
  const rMismatch = await fetch(`${BASE_URL}/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resetToken, newPassword: newPwd, confirmPassword: 'DifferentPassword@123' })
  });
  const dMismatch = await rMismatch.json();
  assert(rMismatch.status === 400 && dMismatch.code === 'PASSWORD_MISMATCH', 'Mismatching passwords rejected with PASSWORD_MISMATCH');

  // 6. Test Successful Password Reset with resetToken
  const rReset = await fetch(`${BASE_URL}/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resetToken, newPassword: newPwd, confirmPassword: newPwd })
  });
  const dReset = await rReset.json();
  assert(rReset.status === 200 && dReset.success, 'POST /api/reset-password succeeded with resetToken');

  // 7. Test Single-Use resetToken Enforcement (Re-use rejected)
  const rReuse = await fetch(`${BASE_URL}/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resetToken, newPassword: newPwd, confirmPassword: newPwd })
  });
  const dReuse = await rReuse.json();
  assert(rReuse.status === 400 && dReuse.code === 'RESET_TOKEN_ALREADY_USED', 'Re-using resetToken rejected with RESET_TOKEN_ALREADY_USED (Single-use enforcement)');

  // 8. Security Check: Verify Active Session Revocation
  const [sessRow] = await conn.execute('SELECT revoked_at FROM sessions WHERE session_id = ?', [activeSess]);
  assert(sessRow.length > 0 && sessRow[0].revoked_at !== null, 'Security Check: All active sessions revoked upon password reset');

  // 9. Login with OLD Password (rejected)
  const rOldLogin = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: oldPwd })
  });
  assert(rOldLogin.status === 401, 'Login with OLD password rejected');

  // 10. Login with NEW Password (succeeded)
  const rNewLogin = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: newPwd })
  });
  const dNewLogin = await rNewLogin.json();
  assert(rNewLogin.status === 200 && dNewLogin.success, 'Login with NEW password succeeded');

  await conn.end();
  return { passed, failed };
}

module.exports = testPasswordReset;
if (require.main === module) {
  testPasswordReset().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
