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

async function testIntegration() {
  console.log('--- Testing E2E Integration Flow ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `e2e_user_${ts}@example.com`;
    const phone = `89${ts.toString().slice(-8)}`;
    const password = 'Password@123';

    // 1. REGISTER
    const rReg = await fetch(`${BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firstName: 'Integration',
        lastName: 'User',
        email,
        phone,
        password,
        confirmPassword: password
      })
    });
    const dReg = await rReg.json();
    const userId = dReg.userId;
    const emailChallengeId = dReg.challengeId;
    assert(rReg.status === 201 && userId && emailChallengeId, 'E2E: REGISTER succeeded');

    // Fetch email OTP from database to verify
    const [emailChals] = await conn.execute('SELECT otp_hash FROM otp_challenges WHERE challenge_id = ?', [emailChallengeId]);
    // Set custom known OTP for validation
    const emailOtp = '111111';
    const emailOtpHash = await bcrypt.hash(emailOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE challenge_id = ?', [emailOtpHash, emailChallengeId]);

    // 2. EMAIL VERIFICATION
    const rEmailVerify = await fetch(`${BASE_URL}/verify-email-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: emailChallengeId, otp: emailOtp })
    });
    assert(rEmailVerify.status === 200, 'E2E: EMAIL VERIFICATION succeeded');

    // 3. PHONE VERIFICATION & MFA SETUP
    const rSmsSend = await fetch(`${BASE_URL}/send-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId })
    });
    const dSmsSend = await rSmsSend.json();
    const smsChallengeId = dSmsSend.challengeId;
    assert(rSmsSend.status === 200 && smsChallengeId, 'E2E: Send SMS OTP succeeded');

    const smsOtp = '222222';
    const smsOtpHash = await bcrypt.hash(smsOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE challenge_id = ?', [smsOtpHash, smsChallengeId]);

    const rSmsVerify = await fetch(`${BASE_URL}/verify-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: smsChallengeId, otp: smsOtp })
    });
    const dSmsVerify = await rSmsVerify.json();
    assert(rSmsVerify.status === 200 && dSmsVerify.mfaEnabled, 'E2E: PHONE VERIFICATION succeeded & MFA ENABLED');

    // 4. LOGIN WITH PASSWORD (triggers SMS MFA Challenge)
    const rLogin = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const dLogin = await rLogin.json();
    const loginChallengeId = dLogin.challengeId;
    assert(rLogin.status === 200 && dLogin.mfaRequired && loginChallengeId, 'E2E: LOGIN WITH PASSWORD triggers SMS MFA CHALLENGE');

    // 5. VERIFY SMS OTP -> CREATE SERVER SESSION
    const loginOtp = '333333';
    const loginOtpHash = await bcrypt.hash(loginOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE challenge_id = ?', [loginOtpHash, loginChallengeId]);

    const rMfaVerify = await fetch(`${BASE_URL}/verify-login-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: loginChallengeId, otp: loginOtp })
    });
    const dMfaVerify = await rMfaVerify.json();
    const sessionId = dMfaVerify.sessionId;
    assert(rMfaVerify.status === 200 && sessionId, 'E2E: VERIFY SMS OTP succeeded and SERVER SESSION created');

    // 6. GET /api/me
    const rMe = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${sessionId}` }
    });
    const dMe = await rMe.json();
    assert(rMe.status === 200 && dMe.user.email === email, 'E2E: GET /api/me succeeded');

    // 7. LOGOUT
    const rLogout = await fetch(`${BASE_URL}/logout`, {
      method: 'POST',
      headers: { 'Cookie': `secureid_session=${sessionId}` }
    });
    assert(rLogout.status === 200, 'E2E: LOGOUT succeeded');

    // 8. GET /api/me MUST FAIL
    const rMeAfter = await fetch(`${BASE_URL}/me`, {
      headers: { 'Cookie': `secureid_session=${sessionId}` }
    });
    assert(rMeAfter.status === 401, 'E2E: GET /api/me fails after logout');

    // 9. LOGIN AGAIN -> PASSWORD FAILURE -> 5 FAILED ATTEMPTS -> ACCOUNT LOCKED
    for (let i = 0; i < 4; i++) {
      await fetch(`${BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'wrong' })
      });
    }
    const rLockAttempt = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'wrong' })
    });
    assert(rLockAttempt.status === 423, 'E2E: 5th failed password attempt locks account');

    // 10. LOGIN MUST FAIL WHILE LOCKED (even with correct password)
    const rLoginWhileLocked = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    assert(rLoginWhileLocked.status === 423, 'E2E: Login fails while account is locked');

  } catch (err) {
    console.error('Integration Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testIntegration;
if (require.main === module) {
  testIntegration().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
