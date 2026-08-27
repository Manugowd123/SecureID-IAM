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

async function testLoginMfa() {
  console.log('--- Testing SMS Login MFA Challenge ---');
  let passed = 0;
  let failed = 0;

  function assert(cond, msg) {
    if (cond) { console.log(`  [PASS] ${msg}`); passed++; }
    else { console.error(`  [FAIL] ${msg}`); failed++; }
  }

  const conn = await mysql.createConnection(dbConfig);
  try {
    const ts = Date.now();
    const email = `login_mfa_${ts}@example.com`;
    const phone = `87${ts.toString().slice(-8)}`;
    const pwd = 'Password@123';
    const hash = await bcrypt.hash(pwd, 10);

    const [u] = await conn.execute(
      `INSERT INTO users (first_name, last_name, email, phone, password_hash, email_verified, mfa_enabled, failed_login_attempts, account_locked_until, created_at, updated_at)
       VALUES ('Login', 'MFA', ?, ?, ?, 1, 1, 0, NULL, NOW(), NOW())`,
      [email, phone, hash]
    );
    const userId = u.insertId;

    // 1. Password login step 1 (MFA required)
    const rStep1 = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd })
    });
    const dStep1 = await rStep1.json();
    const challengeId = dStep1.challengeId;
    assert(rStep1.status === 200 && dStep1.mfaRequired && challengeId, 'Step A: Correct password succeeds and generates challengeId for MFA-enabled user');

    // Verify no session cookie set in headers
    const setCookieHeader = rStep1.headers.get('set-cookie');
    assert(!setCookieHeader || !setCookieHeader.includes('secureid_session'), 'Step A: No session cookie is issued before SMS MFA verification');

    // 2. verify-login-otp with incorrect OTP is rejected
    const rWrong = await fetch(`${BASE_URL}/verify-login-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: challengeId, otp: '000000' })
    });
    assert(rWrong.status === 400, 'Step B: Incorrect OTP rejected (HTTP 400)');

    // 3. send-login-sms-otp resends OTP
    const rResend = await fetch(`${BASE_URL}/send-login-sms-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: userId })
    });
    const dResend = await rResend.json();
    const newChallengeId = dResend.challengeId;
    assert(rResend.status === 200 && newChallengeId && newChallengeId !== challengeId, 'Requesting new login SMS OTP succeeds and returns new challengeId');

    // Set known OTP for the new challenge
    const testOtp = '135791';
    const otpHash = await bcrypt.hash(testOtp, 10);
    await conn.execute('UPDATE otp_challenges SET otp_hash = ? WHERE challenge_id = ?', [otpHash, newChallengeId]);

    // 4. Verify login with correct OTP
    const rSuccess = await fetch(`${BASE_URL}/verify-login-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: newChallengeId, otp: testOtp })
    });
    const dSuccess = await rSuccess.json();
    assert(rSuccess.status === 200 && dSuccess.success && dSuccess.sessionId, 'Step B: Correct OTP completes authentication (HTTP 200)');

    // Verify session cookie set in headers
    const successCookies = rSuccess.headers.get('set-cookie');
    assert(successCookies && successCookies.includes('secureid_session'), 'Step B: Session cookie is issued on successful MFA verification');

    // 5. Verify single-use (cannot replay MFA challenge)
    const rReplay = await fetch(`${BASE_URL}/verify-login-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: newChallengeId, otp: testOtp })
    });
    assert(rReplay.status === 400, 'Verified MFA challenge cannot be replayed');

  } catch (err) {
    console.error('Login MFA Test Error:', err);
    failed++;
  } finally {
    await conn.end();
  }

  return { passed, failed };
}

module.exports = testLoginMfa;
if (require.main === module) {
  testLoginMfa().then(res => console.log(`Result: ${res.passed} Passed, ${res.failed} Failed.`)).catch(console.error);
}
